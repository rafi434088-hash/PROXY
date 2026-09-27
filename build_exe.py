#!/usr/bin/env python3
"""Build the client EXE with a user's tunnel secret injected.

  python build_exe.py NAME     build the client for user NAME (from access.txt),
                               producing dist/TsoolgeeProxy-NAME.exe
  python build_exe.py          fall back to the single secret in secret.txt,
                               producing dist/TsoolgeeProxy.exe

Each user in access.txt has their own secret; the server only lets that
build reach the domains you granted that user. The secret is injected into
a throwaway copy and PyInstaller runs on that, so it ends up only in the
local EXE - never in the public source. access.txt / secret.txt are
gitignored and must never be committed to the public repo.
"""
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def parse_access(text):
    """Map user NAME -> secret from an access.txt (SECRET-NAME=value lines)."""
    users = {}
    for raw in text.splitlines():
        line = raw.strip()
        if line.upper().startswith("SECRET-") and "=" in line:
            name, _, val = line[len("SECRET-"):].partition("=")
            if name.strip() and val.strip():
                users[name.strip()] = val.strip()
    return users


def resolve_secret(argv):
    """Return (secret, exe_name). Prefer access.txt + a NAME argument."""
    name = argv[1] if len(argv) > 1 else None
    access_path = os.path.join(HERE, "access.txt")
    if name:
        if not os.path.exists(access_path):
            sys.exit("access.txt not found - create it (gitignored) with "
                     "SECRET-%s=... lines. See README." % name)
        users = parse_access(open(access_path, encoding="utf-8").read())
        # case-insensitive match on the name
        hit = next((k for k in users if k.lower() == name.lower()), None)
        if not hit:
            sys.exit("user '%s' not in access.txt. Found: %s"
                     % (name, ", ".join(users) or "(none)"))
        return users[hit], "TsoolgeeProxy-%s" % hit
    # no name: single-secret fallback
    secret_path = os.path.join(HERE, "secret.txt")
    if not os.path.exists(secret_path):
        sys.exit("Give a user NAME (from access.txt), or put a single secret "
                 "in secret.txt. See README.")
    secret = open(secret_path, encoding="utf-8").read().strip()
    if not secret:
        sys.exit("secret.txt is empty.")
    return secret, "TsoolgeeProxy"


def main():
    secret, exe_name = resolve_secret(sys.argv)

    src = open(os.path.join(HERE, "client", "proxy_client.py"), encoding="utf-8").read()
    if 'b"__PROXY_SECRET_PLACEHOLDER__"' not in src:
        sys.exit("placeholder not found in client - already injected?")
    # inject as a safe bytes literal (repr) so any characters in the secret
    # can't break the source or silently alter the value
    src = src.replace('b"__PROXY_SECRET_PLACEHOLDER__"', repr(secret.encode("utf-8")))

    # The client connects straight to the always-on server, so there is no
    # dispatch token to bake in any more.

    built_dir = os.path.join(HERE, "_build_src")
    os.makedirs(built_dir, exist_ok=True)
    built = os.path.join(built_dir, exe_name + ".py")
    with open(built, "w", encoding="utf-8") as f:
        f.write(src)

    cmd = [sys.executable, "-m", "PyInstaller", "--noconfirm", "--onefile",
           "--console", "--name", exe_name,
           "--exclude-module", "tkinter", "--exclude-module", "numpy",
           "--exclude-module", "PIL", built]
    print("building %s ..." % exe_name)
    r = subprocess.run(cmd, cwd=HERE)
    if r.returncode == 0:
        print("OK -> %s" % os.path.join(HERE, "dist", exe_name + ".exe"))
    else:
        sys.exit("PyInstaller failed")
    # do not leave the injected source lying around
    shutil.rmtree(built_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
