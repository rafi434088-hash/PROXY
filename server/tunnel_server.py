#!/usr/bin/env python3
"""SMTP-framed tunnel server.

Opens each connection as an ordinary ESMTP session (220 banner / EHLO /
AUTH PLAIN) so an on-path DPI filter recognises and allows it, then
carries an encrypted tunnel inside. Runs on a GitHub Actions runner
behind a raw-TCP tunnel (bore).

Access control: instead of one shared secret, the server loads a list of
named users, each with its own secret and its own allow-list of domains
(see parse_access). A client proves which user it is by the AUTH token,
and every CONNECT is checked against that user's allowed domains - so each
person can be handed a build that only reaches the sites you granted them.
Enforcement is server-side; the client is never trusted for it.

The user list comes from the PROXY_SECRETS env (a repo secret, one block
per user) and is never committed to the (public) source. For backward
compatibility a single PROXY_SECRET still works as one allow-all user.

Security note (honest): a user's secret gates use of the proxy and
obfuscates the hop, but it is symmetric and compiled into that user's
client, so it is NOT a defence against someone who holds their client -
they could still reach any site their allow-list permits. Real browsing
is HTTPS, which the browser secures end to end; this tunnel is for getting
through the filter and scoping who can reach what, not for secrecy from a
client holder.
"""

import hashlib
import hmac
import ipaddress
import os
import socket
import struct
import sys
import threading
import time

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 2525
BANNER = b"220 mx.tsoolgee.uk ESMTP Postfix (Ubuntu)\r\n"

AUTH_WINDOW = 300
HANDSHAKE_TIMEOUT = 20      # slowloris guard: the SMTP+key phase must be quick
RELAY_IDLE = 1800           # generous: don't kill idle keepalive/websocket conns
MAX_CONNS = 256


def _keepalive(sock):
    """Enable TCP keepalive so a truly dead peer is eventually reaped even
    with a long idle timeout (covers legitimately-idle long-lived conns)."""
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except OSError:
        pass
_sem = threading.Semaphore(MAX_CONNS)


def log(m):
    print("[srv %.3f] %s" % (time.time(), m), flush=True)


# ---- access list: named users, each with a secret and allowed domains ----
def parse_access(text):
    """Parse the access file into a list of users.

    Format (one block per user):

        SECRET-<NAME>=<value>
        <domain>
        <domain>
        ...

    A 'SECRET-<NAME>=<value>' line opens a user block; the non-empty lines
    after it (until the next SECRET line) are that user's allowed domains.
    Blank lines and lines starting with '#' are ignored. A block with no
    domains, or a domain line of '*', means that user may reach any host.

    A domain 'example.com' matches example.com and every subdomain of it;
    '*.example.com' behaves the same (apex + subdomains).
    """
    users = []
    cur = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.upper().startswith("SECRET-") and "=" in line:
            name, _, val = line[len("SECRET-"):].partition("=")
            cur = {"name": name.strip() or "?", "secret": val.strip().encode(),
                   "domains": [], "all": False}
            users.append(cur)
        elif cur is not None:
            if line == "*":
                cur["all"] = True
            else:
                cur["domains"].append(line.lower().strip().lstrip("*").lstrip("."))
    out = []
    for u in users:
        if not u["secret"]:
            continue
        if not u["domains"]:
            u["all"] = True            # no domains listed -> full access
        out.append(u)
    return out


def load_users():
    """Users from PROXY_SECRETS (preferred), else a single allow-all user
    from PROXY_SECRET, else an insecure dev fallback."""
    multi = os.environ.get("PROXY_SECRETS", "")
    if multi.strip():
        users = parse_access(multi)
        if users:
            return users
    single = os.environ.get("PROXY_SECRET", "").strip()
    if single:
        return [{"name": "default", "secret": single.encode(),
                 "domains": [], "all": True}]
    return [{"name": "dev", "secret": b"dev-insecure-secret",
             "domains": [], "all": True}]


USERS = load_users()


def host_allowed(host, user):
    """True if `user` may reach `host` (apex or any subdomain of an entry)."""
    if user.get("all"):
        return True
    h = host.lower().strip().rstrip(".")
    for d in user["domains"]:
        if h == d or h.endswith("." + d):
            return True
    return False


# ---- keystream: CTR of SHA-256(key || counter) -------------------------
# XOR is done over the whole chunk as one big integer (~10x faster than a
# per-byte Python loop); the keystream bytes are identical either way, so
# this stays wire-compatible.
class Stream:
    def __init__(self, key):
        self.key = key; self.ctr = 0; self.buf = b""

    def xor(self, data):
        n = len(data)
        if not n:
            return b""
        while len(self.buf) < n:
            self.buf += hashlib.sha256(self.key + struct.pack(">Q", self.ctr)).digest()
            self.ctr += 1
        ks = self.buf[:n]; self.buf = self.buf[n:]
        return (int.from_bytes(data, "big") ^ int.from_bytes(ks, "big")).to_bytes(n, "big")


# ---- one buffered reader per socket (never mix with raw recv) ----------
class BufReader:
    def __init__(self, sock):
        self.s = sock; self.buf = b""

    def _fill(self):
        d = self.s.recv(65536)
        if not d:
            raise ConnectionError("peer closed")   # OSError subclass
        self.buf += d

    def readline(self, limit=2048):
        while b"\n" not in self.buf:
            if len(self.buf) > limit:
                break
            self._fill()
        i = self.buf.find(b"\n")
        if i < 0:
            line, self.buf = self.buf, b""
            return line
        line, self.buf = self.buf[:i + 1], self.buf[i + 1:]
        return line

    def read_exact(self, n):
        while len(self.buf) < n:
            self._fill()
        d, self.buf = self.buf[:n], self.buf[n:]
        return d

    def take(self):
        d, self.buf = self.buf, b""
        return d


def derive(secret, ns, nc, tag):
    return hashlib.sha256(secret + tag + ns + nc).digest()


def match_user(token):
    """Return the user whose time-windowed AUTH token equals `token`, or None.

    Each user has its own secret, so the token identifies who is connecting;
    the +/-1 window tolerates clock skew across the 5-minute boundary."""
    b = int(time.time() // AUTH_WINDOW)
    for u in USERS:
        for x in (b, b - 1, b + 1):
            t = hmac.new(u["secret"], b"auth" + str(x).encode(),
                         hashlib.sha256).hexdigest()
            if hmac.compare_digest(t, token):
                return u
    return None


def vet_target(host, port):
    """Resolve and reject loopback / link-local / private / metadata etc.

    Returns a vetted (ip, port) to connect to, or None if it must be
    refused. Prevents proxy users from reaching the runner's localhost or
    the cloud metadata endpoint (169.254.169.254).
    """
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return None
    for fam, _, _, _, sa in infos:
        try:
            ip = ipaddress.ip_address(sa[0])
        except ValueError:
            continue
        if (ip.is_loopback or ip.is_link_local or ip.is_private
                or ip.is_multicast or ip.is_reserved or ip.is_unspecified):
            return None
        return sa            # first public address wins
    return None


def pump(src, dst, cipher, initial=b""):
    """Read raw from src, xor with `cipher`, write to dst. `initial` is
    already-plaintext bytes to write first (not ciphered)."""
    try:
        if initial:
            dst.sendall(initial)
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(cipher.xor(data))
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)     # half-close: let the other dir drain
        except OSError:
            pass


def handle(conn, addr):
    tag = "conn[%s:%d]" % addr
    up = None
    try:
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        conn.settimeout(HANDSHAKE_TIMEOUT)
        r = BufReader(conn)

        # ---- SMTP opening (cleartext, looks like real ESMTP) ----
        conn.sendall(BANNER)
        saw_ehlo = False
        user = None
        for _ in range(8):
            line = r.readline()
            if not line:
                return
            up_line = line.strip().upper()
            if up_line.startswith(b"EHLO") or up_line.startswith(b"HELO"):
                conn.sendall(b"250-mx.tsoolgee.uk\r\n250 AUTH PLAIN\r\n")
                saw_ehlo = True
            elif up_line.startswith(b"AUTH PLAIN"):
                parts = line.split()
                token = parts[-1].decode("ascii", "ignore") if len(parts) >= 3 else ""
                user = match_user(token)
                if user is not None:
                    conn.sendall(b"235 2.7.0 Authentication successful\r\n")
                    break
                conn.sendall(b"535 5.7.8 Authentication failed\r\n")
                return
            elif up_line.startswith(b"QUIT"):
                conn.sendall(b"221 Bye\r\n")
                return
            else:
                conn.sendall(b"250 OK\r\n")
        if not (saw_ehlo and user is not None):
            return

        # ---- key exchange (through the SAME reader; no raw recv) ----
        nonce_s = os.urandom(16)
        conn.sendall(nonce_s)
        nonce_c = r.read_exact(16)
        secret = user["secret"]
        dec = Stream(derive(secret, nonce_s, nonce_c, b"C2S"))   # client -> server
        enc = Stream(derive(secret, nonce_s, nonce_c, b"S2C"))   # server -> client

        # ---- encrypted CONNECT line ----
        acc = dec.xor(r.take())                # decrypt whatever was buffered
        while b"\n" not in acc and len(acc) < 512:
            chunk = conn.recv(256)
            if not chunk:
                return
            acc += dec.xor(chunk)
        head, _, leftover = acc.partition(b"\n")
        req = head.decode("ascii", "ignore").strip()
        if not req.upper().startswith("CONNECT "):
            conn.sendall(enc.xor(b"ERR bad request\n")); return
        target = req[8:].strip()
        host, _, port = target.rpartition(":")
        try:
            port = int(port)
        except ValueError:
            conn.sendall(enc.xor(b"ERR bad target\n")); return

        if not host_allowed(host, user):
            conn.sendall(enc.xor(b"ERR not allowed\n"))
            log("%s DENY user=%s %s:%d" % (tag, user["name"], host, port))
            return

        sa = vet_target(host, port)
        if sa is None:
            conn.sendall(enc.xor(b"ERR blocked\n")); return
        try:
            up = socket.create_connection(sa, timeout=10)
            up.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError as e:
            conn.sendall(enc.xor(b"ERR %s\n" % str(e).encode()[:60])); return
        conn.sendall(enc.xor(b"OK\n"))
        log("%s user=%s CONNECT %s:%d" % (tag, user["name"], host, port))

        # ---- relay: blocking sockets, one thread per direction ----
        conn.settimeout(RELAY_IDLE)
        up.settimeout(RELAY_IDLE)
        _keepalive(conn); _keepalive(up)
        t = threading.Thread(target=pump, args=(conn, up, dec, leftover), daemon=True)
        t.start()
        pump(up, conn, enc)              # target -> client, in this thread
        t.join(timeout=RELAY_IDLE + 5)
    except (OSError, EOFError):
        pass
    finally:
        for s in (conn, up):
            if s:
                try:
                    s.close()
                except OSError:
                    pass
        _sem.release()


def main():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", PORT))
    srv.listen(128)
    insecure = len(USERS) == 1 and USERS[0]["secret"] == b"dev-insecure-secret"
    if insecure:
        log("tunnel server on 127.0.0.1:%d - NO SECRET SET (dev fallback)!" % PORT)
    else:
        summary = ", ".join(
            "%s[%s]" % (u["name"], "all" if u.get("all") else len(u["domains"]))
            for u in USERS)
        log("tunnel server on 127.0.0.1:%d - %d user(s): %s"
            % (PORT, len(USERS), summary))
    while True:
        conn, addr = srv.accept()
        _sem.acquire()
        try:
            threading.Thread(target=handle, args=(conn, addr), daemon=True).start()
        except RuntimeError:                 # thread/resource exhaustion
            _sem.release()
            try:
                conn.close()
            except OSError:
                pass


if __name__ == "__main__":
    main()
