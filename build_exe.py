#!/usr/bin/env python3
"""Build the client EXE with the real tunnel secret injected.

The committed client carries a placeholder secret. The real secret lives
only in secret.txt (gitignored) and the repo secret PROXY_SECRET - never
in the public source. This script injects it into a throwaway copy and
runs PyInstaller on that, so the secret ends up only in the local EXE.
"""
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def main():
    secret_path = os.path.join(HERE, "secret.txt")
    if not os.path.exists(secret_path):
        sys.exit("secret.txt not found - put the tunnel secret there (gitignored).")
    secret = open(secret_path, encoding="utf-8").read().strip()
    if not secret:
        sys.exit("secret.txt is empty.")

    src = open(os.path.join(HERE, "client", "proxy_client.py"), encoding="utf-8").read()
    if 'b"__PROXY_SECRET_PLACEHOLDER__"' not in src:
        sys.exit("placeholder not found in client - already injected?")
    # inject as a safe bytes literal (repr) so any characters in the secret
    # can't break the source or silently alter the value
    src = src.replace('b"__PROXY_SECRET_PLACEHOLDER__"', repr(secret.encode("utf-8")))

    built_dir = os.path.join(HERE, "_build_src")
    os.makedirs(built_dir, exist_ok=True)
    built = os.path.join(built_dir, "TsoolgeeProxy.py")
    with open(built, "w", encoding="utf-8") as f:
        f.write(src)

    cmd = [sys.executable, "-m", "PyInstaller", "--noconfirm", "--onefile",
           "--console", "--name", "TsoolgeeProxy",
           "--exclude-module", "tkinter", "--exclude-module", "numpy",
           "--exclude-module", "PIL", built]
    print("building ...")
    r = subprocess.run(cmd, cwd=HERE)
    if r.returncode == 0:
        print("OK -> %s" % os.path.join(HERE, "dist", "TsoolgeeProxy.exe"))
    else:
        sys.exit("PyInstaller failed")
    # do not leave the injected source lying around
    shutil.rmtree(built_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
