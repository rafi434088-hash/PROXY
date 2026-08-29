# Tsoolgee proxy (SMTP-framed)

A personal proxy that tunnels through the NetFree filter by opening each
connection as an ordinary ESMTP session, then carrying an encrypted
tunnel inside it. Server runs on GitHub Actions behind a bore raw-TCP
tunnel; the client exposes a local HTTP/SOCKS proxy for the browser.

- `server/tunnel_server.py` — the tunnel server (runs on the Actions runner)
- `client/proxy_client.py` — the local client
- `.github/workflows/proxy.yml` — cron-kept server (also on-demand dispatch)

The shared secret lives in the repo secret `PROXY_SECRET` (server) and is
compiled into the client. It gates use and encrypts the hop to the server.
