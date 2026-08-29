#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SMTP-framed proxy client.

Listens locally as an HTTP and SOCKS5 proxy for the browser, and carries
every connection to the GitHub-Actions server over a connection that
opens as an ordinary ESMTP session (so a DPI filter lets it through) and
then becomes an encrypted tunnel.

  HTTP   127.0.0.1:10809   <- point the browser / ZeroOmega here
  SOCKS5 127.0.0.1:10808

Startup finds the live server endpoint from the public 'live' branch (no
token needed); if no run is active and a dispatch token is present it
starts one. Many machines can run this at once against the same run.

Honest security note: the tunnel secret is symmetric and baked into this
client, so it protects against the filter and casual abuse, not against
someone who has the client. Real browsing is HTTPS end to end.
"""

import base64
import hashlib
import hmac
import json
import os
import socket
import ssl
import struct
import sys
import threading
import time
import urllib.request

# ------------------------------------------------------------- configuration
OWNER = "rafi434088-hash"
REPO = "PROXY"
WORKFLOW = "proxy.yml"

# Shared tunnel secret - MUST match the repo secret PROXY_SECRET. Injected
# at build time; the placeholder is replaced by build_exe. Never commit a
# real value to the public repo.
SECRET = b"__PROXY_SECRET_PLACEHOLDER__"

DISPATCH_TOKEN = ""          # optional; or token.txt / TSOOLGEE_TOKEN env

HTTP_PORT = 10809
SOCKS_PORT = 10808
AUTH_WINDOW = 300
CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0

FROZEN = getattr(sys, "frozen", False)
SIDECAR = os.path.dirname(sys.executable if FROZEN else os.path.abspath(__file__))


def say(m=""):
    try:
        print(m, flush=True)
    except UnicodeEncodeError:
        print(m.encode("ascii", "replace").decode("ascii"), flush=True)


# ------------------------------------------------------------- crypto / io
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


class BufReader:
    def __init__(self, sock):
        self.s = sock; self.buf = b""

    def _fill(self):
        d = self.s.recv(65536)
        if not d:
            raise EOFError
        self.buf += d

    def readline(self, limit=8192):
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


def auth_token():
    b = int(time.time() // AUTH_WINDOW)
    return hmac.new(SECRET, b"auth" + str(b).encode(), hashlib.sha256).hexdigest()


def pump(src, dst, cipher, initial=b""):
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
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


# ------------------------------------------------------------- github discovery
def tls_context():
    """Verifying TLS context that also trusts the OS certificate store.

    This network intercepts TLS and re-signs it with a filter CA that
    lives in the Windows root store. Python's default context does not
    load that store, so api.github.com fails to verify - load it by hand.
    """
    ctx = ssl.create_default_context()
    try:
        ctx.load_default_certs(ssl.Purpose.SERVER_AUTH)
    except Exception:
        pass
    if os.name == "nt":
        try:
            for cert, enc, trust in ssl.enum_certificates("ROOT"):
                if enc == "x509_asn" and (trust is True or (
                        isinstance(trust, set) and ssl.Purpose.SERVER_AUTH.oid in trust)):
                    try:
                        ctx.load_verify_locations(cadata=ssl.DER_cert_to_PEM_cert(cert))
                    except ssl.SSLError:
                        pass
        except Exception:
            pass
    return ctx


def _get(url, token=None, timeout=15):
    h = {"User-Agent": "tsoolgee-proxy", "Accept": "application/vnd.github+json"}
    if token:
        h["Authorization"] = "Bearer " + token
    req = urllib.request.Request(url, headers=h)
    with urllib.request.urlopen(req, timeout=timeout, context=tls_context()) as r:
        return r.status, r.read()


def find_token():
    if DISPATCH_TOKEN.strip():
        return DISPATCH_TOKEN.strip()
    for env in ("TSOOLGEE_TOKEN", "GITHUB_TOKEN", "GH_TOKEN"):
        v = os.environ.get(env, "").strip()
        if v:
            return v
    tf = os.path.join(SIDECAR, "token.txt")
    if os.path.exists(tf):
        try:
            return open(tf, encoding="utf-8").read().strip()
        except OSError:
            pass
    return ""


def live_endpoint():
    """Read the endpoint from raw.githubusercontent - a CDN with no API
    rate limit, so every machine (all sharing one IP behind the filter)
    can poll it freely. The endpoint is pinned, so ~5 min CDN caching is
    fine. Falls back to the API only if the CDN read fails."""
    raw_url = "https://raw.githubusercontent.com/%s/%s/live/endpoint.json" % (OWNER, REPO)
    try:
        _, raw = _get(raw_url)
        return json.loads(raw).get("endpoint")
    except Exception:
        pass
    try:
        api = "https://api.github.com/repos/%s/%s/contents/endpoint.json?ref=live" % (OWNER, REPO)
        _, raw = _get(api)
        data = base64.b64decode(json.loads(raw)["content"])
        return json.loads(data).get("endpoint")
    except Exception:
        return None


def run_active():
    url = ("https://api.github.com/repos/%s/%s/actions/workflows/%s/runs?per_page=10"
           % (OWNER, REPO, WORKFLOW))
    try:
        _, raw = _get(url)
        for run in json.loads(raw).get("workflow_runs", []):
            if run.get("status") in ("in_progress", "queued", "waiting", "requested", "pending"):
                return True
    except Exception:
        pass
    return False


def dispatch():
    tok = find_token()
    if not tok:
        say("[!] No run live and no dispatch token - waiting for the schedule.")
        say("    (drop a fine-grained PAT into token.txt to start on demand)")
        return False
    url = ("https://api.github.com/repos/%s/%s/actions/workflows/%s/dispatches"
           % (OWNER, REPO, WORKFLOW))
    body = json.dumps({"ref": "main"}).encode()
    h = {"User-Agent": "tsoolgee-proxy", "Accept": "application/vnd.github+json",
         "Authorization": "Bearer " + tok}
    try:
        req = urllib.request.Request(url, headers=h, data=body)
        with urllib.request.urlopen(req, timeout=20, context=tls_context()) as r:
            if r.status in (201, 204):
                say("[+] Requested a new server run."); return True
    except Exception as e:
        say("[!] dispatch failed: %s" % e)
    return False


# ------------------------------------------------------------- tunnel
STATE = {"endpoint": None, "fails": 0, "lock": threading.Lock()}


def open_tunnel(endpoint, host, port):
    """Open one SMTP-framed encrypted tunnel to host:port. Returns
    (sock, enc, dec, leftover) where leftover is plaintext already read
    past the server's OK line (usually empty)."""
    bhost, bport = endpoint.rsplit(":", 1)
    s = socket.create_connection((bhost, int(bport)), timeout=15)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.settimeout(20)
    r = BufReader(s)
    try:
        if not r.readline().startswith(b"220"):
            raise OSError("no SMTP banner")
        s.sendall(b"EHLO tsoolgee\r\n")
        while True:
            line = r.readline()
            if not line:
                raise OSError("EHLO failed")
            if line[3:4] == b" " or line[3:4] == b"":
                break
        s.sendall(b"AUTH PLAIN %s\r\n" % auth_token().encode())
        if not r.readline().startswith(b"235"):
            raise OSError("auth rejected")
        # key exchange - all through the same reader
        nonce_s = r.read_exact(16)
        nonce_c = os.urandom(16)
        s.sendall(nonce_c)
        enc = Stream(derive(nonce_s, nonce_c, b"C2S"))
        dec = Stream(derive(nonce_s, nonce_c, b"S2C"))
        s.sendall(enc.xor(b"CONNECT %s:%d\n" % (host.encode(), port)))
        acc = dec.xor(r.take())
        while b"\n" not in acc and len(acc) < 256:
            chunk = s.recv(128)
            if not chunk:
                raise OSError("no CONNECT reply")
            acc += dec.xor(chunk)
        head, _, leftover = acc.partition(b"\n")
        if not head.startswith(b"OK"):
            raise OSError("server: %s" % head.decode("ascii", "ignore"))
        s.settimeout(None)
        return s, enc, dec, leftover
    except Exception:
        try:
            s.close()
        except OSError:
            pass
        raise


# ------------------------------------------------------------- local fronts
def serve_http(browser):
    r = BufReader(browser)
    first = r.readline()
    if not first:
        browser.close(); return
    try:
        method, target, _ = first.decode("latin-1").split(" ", 2)
    except ValueError:
        browser.close(); return
    headers = []
    while True:
        h = r.readline()
        if h in (b"\r\n", b"\n", b""):
            break
        headers.append(h)

    if method.upper() == "CONNECT":
        host, port = _split_hostport(target, 443)
        ok = _bridge(browser, host, port, preface=r.take(), connect=True)
    else:
        try:
            rest = target.split("://", 1)[1]
            hostport, _, path = rest.partition("/")
            host, port = _split_hostport(hostport, 80)
        except Exception:
            browser.close(); return
        req = ("%s /%s HTTP/1.1\r\n" % (method, path)).encode() + b"".join(headers) + b"\r\n"
        # r.take() = any request body already buffered (POST/PUT)
        ok = _bridge(browser, host, port, preface=req + r.take(), connect=False)
    if not ok:
        try:
            browser.sendall(b"HTTP/1.1 502 Bad Gateway\r\n"
                            b"Content-Length: 0\r\nConnection: close\r\n\r\n")
        except OSError:
            pass
        browser.close()


def _split_hostport(hostport, default_port):
    if hostport.startswith("["):
        h, _, rest = hostport[1:].partition("]")
        p = rest.lstrip(":")
        return h, int(p) if p else default_port
    if ":" in hostport:
        h, _, p = hostport.rpartition(":")
        return h, int(p) if p else default_port
    return hostport, default_port


def serve_socks(browser):
    r = BufReader(browser)
    head = r.read_exact(2)
    if head[0] != 5:
        browser.close(); return
    r.read_exact(head[1])                       # methods
    browser.sendall(b"\x05\x00")
    req = r.read_exact(4)
    if req[1] != 1:                             # CONNECT only
        browser.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00"); browser.close(); return
    atyp = req[3]
    if atyp == 1:
        host = socket.inet_ntoa(r.read_exact(4))
    elif atyp == 3:
        host = r.read_exact(r.read_exact(1)[0]).decode("latin-1")
    elif atyp == 4:
        host = socket.inet_ntop(socket.AF_INET6, r.read_exact(16))
    else:
        browser.close(); return
    port = struct.unpack("!H", r.read_exact(2))[0]
    if not _bridge(browser, host, port, preface=r.take(), connect=False, socks_reply=True):
        try:
            browser.sendall(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
        except OSError:
            pass
        browser.close()


def _open_retry(host, port, tries=3):
    """Tunnel-open with a couple of quick retries. The bore free relay
    occasionally drops a handshake; a retry almost always succeeds and
    keeps a page's many parallel connections from failing under load."""
    last = None
    for i in range(tries):
        ep = STATE["endpoint"]
        if not ep:
            break
        try:
            t = open_tunnel(ep, host, port)
            with STATE["lock"]:
                STATE["fails"] = 0             # healthy again
            return t
        except OSError as e:
            last = e
            _note_fail()
            time.sleep(0.25 * (i + 1))
    if last:
        raise last
    raise OSError("no endpoint")


def _bridge(browser, host, port, preface, connect, socks_reply=False):
    # On an open failure return False WITHOUT closing the browser, so the
    # caller can send a proper error reply (502 / SOCKS error) first.
    if not STATE["endpoint"]:
        return False
    try:
        tunnel, enc, dec, leftover = _open_retry(host, port)
    except OSError:
        return False
    try:
        if connect:
            browser.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        if socks_reply:
            browser.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        if leftover:
            browser.sendall(leftover)
        # relay: browser<->tunnel, blocking, one thread per direction.
        # `preface` is plaintext from the browser side, so it must be
        # encrypted before it goes into the tunnel (pump sends initial raw).
        t = threading.Thread(target=pump, args=(browser, tunnel, enc, enc.xor(preface)), daemon=True)
        t.start()
        pump(tunnel, browser, dec)
        t.join(timeout=5)
    finally:
        for s in (browser, tunnel):
            try:
                s.close()
            except OSError:
                pass
    return True


def _note_fail():
    with STATE["lock"]:
        STATE["fails"] += 1
        refresh = STATE["fails"] >= 3        # endpoint may have moved
        if refresh:
            STATE["fails"] = 0
    if not refresh:
        return
    new = live_endpoint()                    # network I/O OUTSIDE the lock
    if new and new != STATE["endpoint"]:
        with STATE["lock"]:
            if new != STATE["endpoint"]:
                say("[*] Endpoint changed -> %s" % new)
                STATE["endpoint"] = new


def listener(port, handler):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(128)
    while True:
        conn, _ = srv.accept()
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        threading.Thread(target=_guard, args=(handler, conn), daemon=True).start()


def _guard(handler, conn):
    try:
        handler(conn)
    except Exception:
        try:
            conn.close()
        except OSError:
            pass


# ------------------------------------------------------------- main
def main():
    say("=" * 58)
    say(" Tsoolgee proxy  -  ESMTP-framed tunnel")
    say("=" * 58)
    if SECRET.startswith(b"__PROXY_SECRET"):
        say("[!] This build has no secret baked in. Rebuild with build_exe.py.")

    ep = live_endpoint()
    if not ep:
        if run_active():
            say("[*] A run is starting - waiting for its endpoint ...")
        else:
            say("[*] No live run - trying to start one ...")
            dispatch()
        for i in range(90):
            ep = live_endpoint()
            if ep:
                break
            if i % 3 == 0:
                say("    ... waiting for server (%ds)" % (i * 10))
            time.sleep(10)
    if not ep:
        say("[!] No server endpoint available. Check the Actions tab.")
        _pause(); return 1
    STATE["endpoint"] = ep
    say("[+] Server endpoint: %s" % ep)

    ip = _selftest()
    if ip:
        say("[+] Verified: traffic exits from %s" % ip)
    else:
        say("[!] Tunnel up but self-check did not confirm traffic yet.")

    say("-" * 58)
    say(" HTTP   127.0.0.1:%d   <- point the browser here" % HTTP_PORT)
    say(" SOCKS5 127.0.0.1:%d" % SOCKS_PORT)
    say(" Ctrl+C to stop.")
    say("-" * 58)

    threading.Thread(target=listener, args=(HTTP_PORT, serve_http), daemon=True).start()
    threading.Thread(target=listener, args=(SOCKS_PORT, serve_socks), daemon=True).start()
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        say("\n[*] Stopped.")
    return 0


def _selftest():
    """Fetch our public IP over plain HTTP through the tunnel (no TLS in
    the client on purpose - the browser terminates real HTTPS end to end)."""
    for host, path in (("api.ipify.org", "/"), ("ifconfig.me", "/ip")):
        try:
            t, enc, dec, leftover = open_tunnel(STATE["endpoint"], host, 80)
        except OSError:
            continue
        try:
            req = ("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: curl/8\r\n"
                   "Connection: close\r\n\r\n" % (path, host)).encode()
            t.sendall(enc.xor(req))
            t.settimeout(20)
            data = leftover
            while len(data) < 8192:
                chunk = t.recv(4096)
                if not chunk:
                    break
                data += dec.xor(chunk)
            body = data.split(b"\r\n\r\n", 1)[-1].strip()
            ip = body.decode("ascii", "ignore").splitlines()[-1] if body else ""
            if ip and ip.count(".") == 3 and len(ip) <= 15:
                return ip
        except Exception:
            pass
        finally:
            try:
                t.close()
            except OSError:
                pass
    return None


def _pause():
    try:
        input("Press Enter to exit ...")
    except (EOFError, OSError):
        pass


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(0)
