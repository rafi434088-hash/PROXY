# Tsoolgee proxy (SMTP-framed)

A personal proxy that tunnels through the NetFree filter by opening each
connection as an ordinary ESMTP session, then carrying an encrypted
tunnel inside it. Server runs on GitHub Actions behind a bore raw-TCP
tunnel; the client exposes a local HTTP/SOCKS proxy for the browser.

- `server/tunnel_server.py` — the tunnel server (runs on the Actions runner)
- `client/proxy_client.py` — the local client
- `.github/workflows/proxy.yml` — cron-kept server (also on-demand dispatch)
- `access.example.txt` — sample access list (copy to `access.txt`, gitignored)

## Per-user access list

Each user has their own secret and their own allow-list of domains, so you
can hand different people a build that only reaches the sites you granted
them. Enforcement is server-side — the client is never trusted for it.

Edit a local `access.txt` (gitignored, never commit — the repo is public):

```
SECRET-RAFI=754563214586          # no domains below -> full access

SECRET-YEHUDA=long-random-value   # YouTube only
youtube.com
googlevideo.com
```

- `SECRET-<NAME>=<value>` opens a user block; the lines under it are that
  user's allowed domains (one per line).
- A domain covers that host **and all its subdomains**
  (`youtube.com` → `www.youtube.com`, `m.youtube.com`, …).
- A block with no domains, or a single line `*`, means full access.
- Blank lines and `#` comments are ignored.

### Deploy the list to the server

The list is delivered as the repo secret `PROXY_SECRETS` (multi-line). The
workflow injects it into the server; the server prefers it over the legacy
single `PROXY_SECRET`.

```
gh secret set PROXY_SECRETS < access.txt
```

Then re-run the workflow (or wait for the next cron / self-restart) so the
server picks up the new list.

### Build a client for one user

```
python build_exe.py RAFI      # -> dist/TsoolgeeProxy-RAFI.exe
```

Each build bakes only that user's secret. Legacy single-secret builds
(`python build_exe.py`, reading `secret.txt`) still work.

## Desktop admin tool (one click per person)

`admin/make_user.py` is a small GUI that does the whole per-user flow. Run
it only on your own machine (the one with git/gh access) — a desktop
launcher `פרוקסי - יצירת משתמש.cmd` starts it.

Type a name and the allowed domains, press **צור / עדכן משתמש**, and it:

1. verifies the correct GitHub account is active (the owner of this repo,
   switching to it if another account is logged in);
2. creates a secret for a new person, or reuses the existing one if the
   name is already in `access.txt` (update, never duplicate);
3. writes `access.txt` and pushes it to the `PROXY_SECRETS` repo secret;
4. generates a **per-user extension** whose PAC sends only the approved
   domains through the proxy — the browser goes DIRECT for everything else,
   so it never even tries the rest through the tunnel (the server blocks
   them too, as a second layer);
5. builds that user's client EXE;
6. zips extension + EXE + a Hebrew README into `dist_users/<NAME>.zip`.

With **החל מיד** ticked it also restarts the server so a new user works
within about a minute (a brief interruption for everyone); untick it to let
the change apply on the next server cycle instead.
