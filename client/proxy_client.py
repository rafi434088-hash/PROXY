#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SMTP-framed proxy client.

Listens locally as an HTTP and SOCKS5 proxy for the browser, and carries
every connection to the GitHub-Actions server over a connection that
opens as an ordinary ESMTP session (so the NetFree filter lets it
through) and then becomes our encrypted tunnel.

  HTTP   127.0.0.1:10809   <- point the browser / ZeroOmega here
  SOCKS5 127.0.0.1:10808

Startup:
  * find the live server endpoint from the public 'live' branch
    (no token needed - the repo is public);
  * if no run is active and a dispatch token is available, start one;
  * many machines can run this at once against the same run.
"""

import base64
import hashlib
import hmac
import json
import os
import select
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

# Shared tunnel secret. MUST match the repo secret PROXY_SECRET. It only
# gates use of the proxy and encrypts the hop to the server - it is not a
# GitHub credential.
SECRET = b"25000c8a3bf79aea8faf3a7fba5110c17b669a6a0b546ff1"

# Optional GitHub token, ONLY used to start a run on demand when none is
# live (workflow_dispatch). Leave empty to rely on the cron schedule.
# Put a fine-grained PAT (this repo, Actions: read+write) here or in
# token.txt next to the exe, or the TSOOLGEE_TOKEN env var.
DISPATCH_TOKEN = ""

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


# ------------------------------------------------------------- crypto
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


def derive(ns, nc, tag):
    return hashlib.sha256(SECRET + tag + ns + nc).digest()


def auth_token():
    bucket = int(time.time() // AUTH_WINDOW)
    return hmac.new(SECRET, b"auth" + str(bucket).encode(), hashlib.sha256).hexdigest()


# ------------------------------------------------------------- endpoint discovery
def _get(url, token=None, timeout=15):
    h = {"User-Agent": "tsoolgee-proxy", "Accept": "application/vnd.github+json"}
    if token:
        h["Authorization"] = "Bearer " + token
    req = urllib.request.Request(url, headers=h)
    with urllib.request.urlopen(req, timeout=timeout, context=ssl.create_default_context()) as r:
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
    """Read bore.pub:PORT from the public 'live' branch. No auth needed."""
    url = "https://api.github.com/repos/%s/%s/contents/endpoint.json?ref=live" % (OWNER, REPO)
    try:
        _, raw = _get(url)
        obj = json.loads(raw)
        data = base64.b64decode(obj["content"])
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
        say("    (add a fine-grained PAT to token.txt to start on demand)")
        return False
    url = ("https://api.github.com/repos/%s/%s/actions/workflows/%s/dispatches"
           % (OWNER, REPO, WORKFLOW))
    body = json.dumps({"ref": "main"}).encode()
    h = {"User-Agent": "tsoolgee-proxy", "Accept": "application/vnd.github+json",
         "Authorization": "Bearer " + tok}
    try:
        req = urllib.request.Request(url, headers=h, data=body)
        with urllib.request.urlopen(req, timeout=20, context=ssl.create_default_context()) as r:
            if r.status in (201, 204):
                say("[+] Requested a new server run."); return True
    except Exception as e:
        say("[!] dispatch failed: %s" % e)
    return False


# ------------------------------------------------------------- tunnel
def open_tunnel(endpoint, host, port):
    """Open one SMTP-framed encrypted tunnel to `host:port` via the server."""
    bhost, bport = endpoint.rsplit(":", 1)
    s = socket.create_connection((bhost, int(bport)), timeout=15)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.settimeout(20)                       # bound the whole SMTP+key handshake
    f = s.makefile("rb")
    if not f.readline().startswith(b"220"):
        s.close(); raise OSError("no SMTP banner")
    s.sendall(b"EHLO tsoolgee\r\n")
    while True:
        line = f.readline()
        if not line:
            s.close(); raise OSError("EHLO failed")
        if line[3:4] == b" ":
            break
    s.sendall(b"AUTH PLAIN %s\r\n" % auth_token().encode())
    if not f.readline().startswith(b"235"):
        s.close(); raise OSError("auth rejected")
    # key exchange
    ns = _recv_exact(s, 16)
    if not ns:
        s.close(); raise OSError("no server nonce")
    nc = os.urandom(16)
    s.sendall(nc)
    enc = Stream(derive(ns, nc, b"C2S"))   # client -> server
    dec = Stream(derive(ns, nc, b"S2C"))   # server -> client
    s.sendall(enc.xor(b"CONNECT %s:%d\n" % (host.encode(), port)))
    reply = b""
    while b"\n" not in reply and len(reply) < 200:
        chunk = s.recv(64)
        if not chunk:
            s.close(); raise OSError("no CONNECT reply")
        reply += dec.xor(chunk)
    if not reply.startswith(b"OK"):
        s.close(); raise OSError("server: %s" % reply.split(b"\n")[0].decode("ascii", "ignore"))
    s.settimeout(None)                     # blocking for the relay phase
    return s, enc, dec


def _recv_exact(s, n):
    buf = b""
    while len(buf) < n:
        c = s.recv(n - len(buf))
        if not c:
            return None
        buf += c
    return buf


def splice(browser, tunnel, enc, dec):
    browser.setblocking(False); tunnel.setblocking(False)
    try:
        while True:
            r, _, x = select.select([browser, tunnel], [], [browser, tunnel], 120)
            if x or not r:
                if x:
                    break
                continue
            for s in r:
                try:
                    data = s.recv(65536)
                except (BlockingIOError, InterruptedError):
                    continue
                except OSError:
                    return
                if not data:
                    return
                if s is browser:
                    tunnel.sendall(enc.xor(data))
                else:
                    browser.sendall(dec.xor(data))
    finally:
        for s in (browser, tunnel):
            try:
                s.close()
            except OSError:
                pass


# ------------------------------------------------------------- local proxy fronts
STATE = {"endpoint": None}


def serve_http(browser):
    """Absolute-form and CONNECT HTTP proxy."""
    f = browser.makefile("rb")
    first = f.readline()
    if not first:
        browser.close(); return
    try:
        method, target, _ = first.decode("latin-1").split(" ", 2)
    except ValueError:
        browser.close(); return
    headers = []
    while True:
        h = f.readline()
        if h in (b"\r\n", b"\n", b""):
            break
        headers.append(h)

    if method.upper() == "CONNECT":
        host, port = _split_hostport(target, 443)
        _bridge(browser, host, port, preface=b"", connect=True)
    else:
        # absolute URI: http://host[:port]/path
        try:
            rest = target.split("://", 1)[1]
            hostport, _, path = rest.partition("/")
            host, port = _split_hostport(hostport, 80)
        except Exception:
            browser.close(); return
        req = ("%s /%s HTTP/1.1\r\n" % (method, path)).encode() + b"".join(headers) + b"\r\n"
        _bridge(browser, host, port, preface=req, connect=False)


def _split_hostport(hostport, default_port):
    """Split 'host' or 'host:port' safely (no colon -> default port)."""
    if hostport.startswith("["):                      # [ipv6]:port
        h, _, rest = hostport[1:].partition("]")
        p = rest.lstrip(":")
        return h, int(p) if p else default_port
    if ":" in hostport:
        h, _, p = hostport.rpartition(":")
        return h, int(p) if p else default_port
    return hostport, default_port


def serve_socks(browser):
    """Minimal SOCKS5 (CONNECT, no auth)."""
    d = _recv_exact(browser, 2)
    if not d or d[0] != 5:
        browser.close(); return
    nm = d[1]
    _recv_exact(browser, nm)
    browser.sendall(b"\x05\x00")               # no auth
    hdr = _recv_exact(browser, 4)
    if not hdr or hdr[1] != 1:                  # only CONNECT
        browser.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00"); browser.close(); return
    atyp = hdr[3]
    if atyp == 1:
        host = socket.inet_ntoa(_recv_exact(browser, 4))
    elif atyp == 3:
        ln = _recv_exact(browser, 1)[0]
        host = _recv_exact(browser, ln).decode("latin-1")
    elif atyp == 4:
        host = socket.inet_ntop(socket.AF_INET6, _recv_exact(browser, 16))
    else:
        browser.close(); return
    port = struct.unpack("!H", _recv_exact(browser, 2))[0]
    ok = _bridge(browser, host, port, preface=b"", connect=False, socks_reply=True)
    if not ok:
        try:
            browser.sendall(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
        except OSError:
            pass
        browser.close()


def _bridge(browser, host, port, preface, connect, socks_reply=False):
    ep = STATE["endpoint"]
    if not ep:
        browser.close(); return False
    try:
        tunnel, enc, dec = open_tunnel(ep, host, port)
    except OSError:
        return False
    if connect:
        browser.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
    if socks_reply:
        browser.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
    if preface:
        tunnel.sendall(enc.xor(preface))
    splice(browser, tunnel, enc, dec)
    return True


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
        try:
            input("Press Enter to exit ...")
        except (EOFError, OSError):
            pass
        return 1
    STATE["endpoint"] = ep
    say("[+] Server endpoint: %s" % ep)

    # quick self-check: real traffic through the tunnel
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
    """Fetch our public IP over plain HTTP through the tunnel.

    No TLS here on purpose - the client never does TLS. Real browser
    traffic is HTTPS that the browser terminates end-to-end; we only
    relay its bytes. This check just proves the tunnel carries traffic
    and reports the exit IP.
    """
    for host in ("api.ipify.org", "ifconfig.me"):
        path = "/" if host == "api.ipify.org" else "/ip"
        try:
            t, enc, dec = open_tunnel(STATE["endpoint"], host, 80)
        except OSError:
            continue
        try:
            req = ("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: curl/8\r\n"
                   "Connection: close\r\n\r\n" % (path, host)).encode()
            t.sendall(enc.xor(req))
            data = b""
            t.settimeout(20)
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


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(0)
