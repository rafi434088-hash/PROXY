#!/usr/bin/env python3
"""SMTP-framed tunnel server.

Opens each connection as an ordinary ESMTP session (220 banner / EHLO /
AUTH PLAIN) so an on-path DPI filter recognises and allows it, then
carries an encrypted tunnel inside. Runs on a GitHub Actions runner
behind a raw-TCP tunnel (bore).

Security note (honest): the shared secret gates use of the proxy and
obfuscates the hop, but it is symmetric and compiled into every client,
so it is NOT a defence against an adversary who holds the client. Real
browsing is HTTPS, which the browser secures end to end; this tunnel is
for getting through the filter, not for secrecy from a client holder.
The secret is injected from the PROXY_SECRET env (a repo secret) and is
never committed to the (public) source.
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

SECRET = (os.environ.get("PROXY_SECRET", "").strip() or "dev-insecure-secret").encode()
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 2525
BANNER = b"220 mx.tsoolgee.uk ESMTP Postfix (Ubuntu)\r\n"

AUTH_WINDOW = 300
HANDSHAKE_TIMEOUT = 20      # slowloris guard: the SMTP+key phase must be quick
RELAY_IDLE = 300            # drop a relay idle this long (frees dead fds)
MAX_CONNS = 256
_sem = threading.Semaphore(MAX_CONNS)


def log(m):
    print("[srv %.3f] %s" % (time.time(), m), flush=True)


# ---- keystream: CTR of SHA-256(key || counter) -------------------------
class Stream:
    def __init__(self, key):
        self.key = key; self.ctr = 0; self.buf = b""

    def _block(self):
        b = hashlib.sha256(self.key + struct.pack(">Q", self.ctr)).digest()
        self.ctr += 1
        return b

    def xor(self, data):
        out = bytearray(data); buf = self.buf; i = 0
        while i < len(out):
            if not buf:
                buf = self._block()
            n = min(len(buf), len(out) - i)
            for j in range(n):
                out[i + j] ^= buf[j]
            buf = buf[n:]; i += n
        self.buf = buf
        return bytes(out)


# ---- one buffered reader per socket (never mix with raw recv) ----------
class BufReader:
    def __init__(self, sock):
        self.s = sock; self.buf = b""

    def _fill(self):
        d = self.s.recv(65536)
        if not d:
            raise EOFError
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


def derive(ns, nc, tag):
    return hashlib.sha256(SECRET + tag + ns + nc).digest()


def expected_auth():
    b = int(time.time() // AUTH_WINDOW)
    return {hmac.new(SECRET, b"auth" + str(x).encode(), hashlib.sha256).hexdigest()
            for x in (b, b - 1, b + 1)}


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
        saw_ehlo = authed = False
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
                if token in expected_auth():
                    conn.sendall(b"235 2.7.0 Authentication successful\r\n")
                    authed = True
                    break
                conn.sendall(b"535 5.7.8 Authentication failed\r\n")
                return
            elif up_line.startswith(b"QUIT"):
                conn.sendall(b"221 Bye\r\n")
                return
            else:
                conn.sendall(b"250 OK\r\n")
        if not (saw_ehlo and authed):
            return

        # ---- key exchange (through the SAME reader; no raw recv) ----
        nonce_s = os.urandom(16)
        conn.sendall(nonce_s)
        nonce_c = r.read_exact(16)
        dec = Stream(derive(nonce_s, nonce_c, b"C2S"))     # client -> server
        enc = Stream(derive(nonce_s, nonce_c, b"S2C"))     # server -> client

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

        sa = vet_target(host, port)
        if sa is None:
            conn.sendall(enc.xor(b"ERR blocked\n")); return
        try:
            up = socket.create_connection(sa, timeout=15)
            up.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError as e:
            conn.sendall(enc.xor(b"ERR %s\n" % str(e).encode()[:60])); return
        conn.sendall(enc.xor(b"OK\n"))
        log("%s CONNECT %s:%d" % (tag, host, port))

        # ---- relay: blocking sockets, one thread per direction ----
        conn.settimeout(RELAY_IDLE)
        up.settimeout(RELAY_IDLE)
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
    ok = SECRET != b"dev-insecure-secret"
    log("tunnel server on 127.0.0.1:%d (secret=%s)" % (PORT, "set" if ok else "MISSING!"))
    while True:
        conn, addr = srv.accept()
        _sem.acquire()
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
