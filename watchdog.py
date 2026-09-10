#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Server-run watchdog.

Runs continuously on your machine. Every 2 minutes it asks the GitHub API
whether a proxy server run is currently alive. If one is, it does nothing
(and writes nothing to the log). If NONE is alive, it dispatches a fresh
run and appends one dated line to watchdog.log.

So watchdog.log ends up being a record of exactly the moments the server
was found down - after a week, if the file is empty, there was never a
gap; every line is one gap it caught (and tried to fix).

Uses the SAME repo-scoped token the EXE build used: it reads token_build.txt
next to this script (the file build_exe.py baked into the old EXE), falling
back to token.txt or the TSOOLGEE_TOKEN / GITHUB_TOKEN / GH_TOKEN env var.
The token only needs to dispatch the workflow on rafi434088-hash/PROXY
(fine-grained PAT with Actions: read+write on that repo only, or a classic
token with the 'workflow' scope). Both files are gitignored.
"""

import json
import os
import ssl
import sys
import time
import urllib.request
from datetime import datetime

# ------------------------------------------------------------- configuration
OWNER = "rafi434088-hash"
REPO = "PROXY"
WORKFLOW = "proxy.yml"
INTERVAL = 120                      # seconds between checks (2 minutes)

# a run in any of these states means a server exists - don't start another
ALIVE = ("in_progress", "queued", "waiting", "requested", "pending")

HERE = os.path.dirname(os.path.abspath(__file__))
LOG_PATH = os.path.join(HERE, "watchdog.log")


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def log_gap(line):
    """Append one line to the gap log AND echo it to the console."""
    msg = "%s  %s" % (now(), line)
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(msg + "\n")
    except OSError as e:
        print("[!] could not write log: %s" % e, flush=True)
    print(msg, flush=True)


def beat(line):
    """Console-only heartbeat - never touches the log file."""
    try:
        print("%s  %s" % (now(), line), flush=True)
    except UnicodeEncodeError:
        print("%s  %s" % (now(), line.encode("ascii", "replace").decode()), flush=True)


# ------------------------------------------------------------- github io
def tls_context():
    """Verifying TLS that also trusts the Windows root store, so it works
    behind a filter that MITMs TLS with a CA installed there (NetFree)."""
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


def find_token():
    # Same repo-scoped token the EXE build used: token_build.txt is the
    # file build_exe.py read to bake the dispatch token into the old EXE.
    # token.txt works too. Env vars override both.
    for env in ("TSOOLGEE_TOKEN", "GITHUB_TOKEN", "GH_TOKEN"):
        v = os.environ.get(env, "").strip()
        if v:
            return v
    for name in ("token_build.txt", "token.txt"):
        tf = os.path.join(HERE, name)
        if os.path.exists(tf):
            try:
                v = open(tf, encoding="utf-8").read().strip()
                if v:
                    return v
            except OSError:
                pass
    return ""


def _req(url, token, data=None):
    h = {"User-Agent": "tsoolgee-watchdog", "Accept": "application/vnd.github+json"}
    if token:
        h["Authorization"] = "Bearer " + token
    return urllib.request.Request(url, headers=h, data=data)


def run_alive(token):
    """Return True/False if we could determine it, or None on error (so the
    caller can stay conservative and NOT dispatch on a transient failure)."""
    url = ("https://api.github.com/repos/%s/%s/actions/workflows/%s/runs?per_page=15"
           % (OWNER, REPO, WORKFLOW))
    try:
        with urllib.request.urlopen(_req(url, token), timeout=20,
                                    context=tls_context()) as r:
            runs = json.loads(r.read()).get("workflow_runs", [])
    except Exception as e:
        beat("[?] could not check run status: %s" % e)
        return None
    for run in runs:
        if run.get("status") in ALIVE:
            return True
    return False


def dispatch(token):
    url = ("https://api.github.com/repos/%s/%s/actions/workflows/%s/dispatches"
           % (OWNER, REPO, WORKFLOW))
    body = json.dumps({"ref": "main"}).encode()
    try:
        with urllib.request.urlopen(_req(url, token, body), timeout=20,
                                    context=tls_context()) as r:
            return r.status in (201, 204), str(r.status)
    except Exception as e:
        return False, str(e)


# ------------------------------------------------------------- main
def main():
    token = find_token()
    if not token:
        print("[!] No dispatch token. Put a PAT (Actions: read+write on "
              "%s/%s) in token.txt, or set TSOOLGEE_TOKEN." % (OWNER, REPO),
              flush=True)
        return 1

    beat("watchdog started - checking every %ds. Gaps go to %s"
         % (INTERVAL, LOG_PATH))
    while True:
        try:
            alive = run_alive(token)
            if alive is True:
                beat("[ok] server run alive")          # console only
            elif alive is False:
                ok, info = dispatch(token)
                if ok:
                    log_gap("NO ACTIVE RUN - dispatched a new server run.")
                else:
                    log_gap("NO ACTIVE RUN - dispatch FAILED (%s)." % info)
            # alive is None -> error already noted on console; don't dispatch
        except Exception as e:
            beat("[!] loop error: %s" % e)
        time.sleep(INTERVAL)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[*] Stopped.", flush=True)
        sys.exit(0)
