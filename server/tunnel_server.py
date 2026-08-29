#!/usr/bin/env python3
"""SMTP-framed tunnel server.

Runs on a GitHub Actions runner, exposed through a raw-TCP tunnel (bore).
To anything watching the wire (e.g. the NetFree filter) each connection
opens as an ordinary ESMTP session - a `220 ... ESMTP` banner, an EHLO,
and a `AUTH PLAIN` exchange - which the filter recognises and lets
through. After the SMTP opening the stream carries our own encrypted
tunnel, which the filter no longer inspects.

Tunnel, after the SMTP opening:
  1. server sends 16-byte nonce_s, client sends 16-byte nonce_c (cleartext)
  2. both derive two ChaCha-like keystreams (one per direction) from
     HMAC(secret) - so a passer-by who finds the endpoint cannot read or
     inject traffic without the shared secret
  3. client sends encrypted  "CONNECT host:port\n"
     server replies encrypted "OK\n" (or "ERR ...\n") and then raw-relays

The shared secret comes from the PROXY_SECRET env var (a repo secret),
never from the public source. AUTH is an HMAC over a coarse time bucket,
enough to keep the public endpoint from being an open proxy.
"""

import hashlib
import hmac
import os
import select
import socket
import struct
import sys
import threading
import time

SECRET = os.environ.get("PROXY_SECRET", "").encode() or b"dev-insecure-secret"
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 2525
BANNER = b"220 mx.tsoolgee.uk ESMTP Postfix (Ubuntu)\r\n"

AUTH_WINDOW = 300           # seconds per auth bucket (accept current +/- 1)


def log(m):
    print("[srv %.3f] %s" % (time.time(), m), flush=True)


# ---- keystream: CTR of SHA-256(key || counter) -------------------------
class Stream:
    def __init__(self, key):
        self.key = key
        self.ctr = 0
        self.buf = b""

    def _block(self):
        b = hashlib.sha256(self.key + struct.pack(">Q", self.ctr)).digest()
        self.ctr += 1
        return b

    def xor(self, data):
        out = bytearray(data)
        buf = self.buf
        i = 0
        while i < len(out):
            if not buf:
                buf = self._block()
            n = min(len(buf), len(out) - i)
            for j in range(n):
                out[i + j] ^= buf[j]
            buf = buf[n:]
            i += n
        self.buf = buf
        return bytes(out)


def derive(nonce_s, nonce_c, tag):
    return hashlib.sha256(SECRET + tag + nonce_s + nonce_c).digest()


def expected_auth():
    bucket = int(time.time() // AUTH_WINDOW)
    out = set()
    for b in (bucket, bucket - 1, bucket + 1):
        out.add(hmac.new(SECRET, b"auth" + str(b).encode(), hashlib.sha256).hexdigest())
    return out


def readline(f, limit=512):
    line = f.readline(limit)
    return line


def recv_exact(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def relay(a, b, dec, enc):
    """Pipe a->b, decrypting from a and (for the reverse pump) encrypting.

    Here we run two threads; each pump reads plaintext side or cipher side.
    Simpler: one pump decrypts client->target, the other encrypts
    target->client. See handle().
    """
    pass


def handle(conn, addr):
    tag = "conn[%s:%d]" % addr
    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    f = conn.makefile("rb")
    try:
        # ---- SMTP opening (cleartext, so the filter sees a real ESMTP) ----
        conn.sendall(BANNER)
        saw_ehlo = False
        authed = False
        for _ in range(8):
            line = readline(f)
            if not line:
                return
            up = line.strip().upper()
            if up.startswith(b"EHLO") or up.startswith(b"HELO"):
                conn.sendall(b"250-mx.tsoolgee.uk\r\n250-PIPELINING\r\n250 AUTH PLAIN\r\n")
                saw_ehlo = True
            elif up.startswith(b"AUTH PLAIN"):
                parts = line.split()
                token = parts[-1].decode("ascii", "ignore") if len(parts) >= 3 else ""
                # token is the raw hex hmac (we skip base64 wrapping for simplicity)
                if token in expected_auth():
                    conn.sendall(b"235 2.7.0 Authentication successful\r\n")
                    authed = True
                    break
                conn.sendall(b"535 5.7.8 Authentication failed\r\n")
                return
            elif up.startswith(b"QUIT"):
                conn.sendall(b"221 Bye\r\n")
                return
            else:
                conn.sendall(b"250 OK\r\n")
        if not (saw_ehlo and authed):
            return

        # ---- key exchange ----
        nonce_s = os.urandom(16)
        conn.sendall(nonce_s)
        nonce_c = recv_exact(conn, 16)
        if not nonce_c:
            return
        dec = Stream(derive(nonce_s, nonce_c, b"C2S"))   # client -> server
        enc = Stream(derive(nonce_s, nonce_c, b"S2C"))   # server -> client

        # ---- read encrypted CONNECT line ----
        req = b""
        while b"\n" not in req and len(req) < 300:
            chunk = conn.recv(64)
            if not chunk:
                return
            req += dec.xor(chunk)
        line = req.split(b"\n", 1)[0].decode("ascii", "ignore").strip()
        if not line.upper().startswith("CONNECT "):
            conn.sendall(enc.xor(b"ERR bad request\n"))
            return
        target = line[8:].strip()
        host, _, port = target.rpartition(":")
        try:
            port = int(port)
        except ValueError:
            conn.sendall(enc.xor(b"ERR bad target\n"))
            return
        log("%s CONNECT %s:%d" % (tag, host, port))
        try:
            up = socket.create_connection((host, port), timeout=15)
            up.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError as e:
            conn.sendall(enc.xor(b"ERR %s\n" % str(e).encode()[:60]))
            return
        conn.sendall(enc.xor(b"OK\n"))
        # any leftover bytes after the CONNECT line belong to the target
        leftover = req.split(b"\n", 1)[1] if b"\n" in req else b""
        if leftover:
            up.sendall(leftover)

        # ---- raw relay ----
        pump(conn, up, dec, enc, tag)
    except OSError:
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def pump(cli, up, dec, enc, tag):
    cli.setblocking(False)
    up.setblocking(False)
    socks = [cli, up]
    try:
        while True:
            r, _, x = select.select(socks, [], socks, 60)
            if x:
                break
            if not r:
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
                if s is cli:
                    up.sendall(dec.xor(data))
                else:
                    cli.sendall(enc.xor(data))
    finally:
        for s in (cli, up):
            try:
                s.close()
            except OSError:
                pass


def main():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", PORT))
    srv.listen(64)
    log("tunnel server on 127.0.0.1:%d (secret=%s)" % (PORT, "set" if SECRET != b"dev-insecure-secret" else "MISSING"))
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
