#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tsoolgee proxy - per-user builder (desktop admin tool).

Run this ONLY on your own machine (the one with git/gh access). Type a
person's name and the domains they may reach; it will:

  1. verify the correct GitHub account is active (the owner of the server
     repo - switching to it automatically if another account is logged in);
  2. create a fresh secret for a new person, or reuse the existing secret if
     that name is already in access.txt (update, not duplicate);
  3. write the local access.txt (gitignored master list);
  4. push the whole list to the repo secret PROXY_SECRETS (server side);
  5. generate a per-user browser extension whose PAC routes ONLY the
     approved domains through the proxy (everything else goes DIRECT), so
     the browser never even tries to reach other sites through it;
  6. build that user's client EXE (their secret baked in);
  7. zip the extension + EXE + a short readme into dist_users/<NAME>.zip.

The server still blocks any domain you did not approve - this just means an
approved user's browser won't even attempt the others through the tunnel.
"""

import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import threading
import zipfile

import tkinter as tk
from tkinter import messagebox, scrolledtext

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)                       # proxy-smtp/
ACCESS = os.path.join(ROOT, "access.txt")
EXT_SRC = os.path.join(ROOT, "extension")          # base extension (icons/popup)
OUT_DIR = os.path.join(ROOT, "dist_users")
SECRET_SET_NAME = "PROXY_SECRETS"
WORKFLOW = "proxy.yml"
NO_WINDOW = 0x08000000 if os.name == "nt" else 0
WRITE_PERMS = {"ADMIN"}                             # repo-secret write needs admin


# --------------------------------------------------------------- shell helper
def run(args, cwd=ROOT, input_bytes=None):
    """Run a command, return (rc, stdout+stderr text). Never pops a console."""
    try:
        p = subprocess.run(args, cwd=cwd, input=input_bytes,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           creationflags=NO_WINDOW)
    except FileNotFoundError as e:
        return 127, "not found: %s" % e
    return p.returncode, p.stdout.decode("utf-8", "replace")


# --------------------------------------------------------------- git / gh
def repo_slug():
    """owner/repo from the git 'origin' remote."""
    rc, out = run(["git", "remote", "get-url", "origin"])
    if rc != 0:
        return None
    m = re.search(r"github\.com[/:]([^/]+/[^/.]+)", out.strip())
    return m.group(1) if m else None


def gh_accounts():
    """[(name, is_active), ...] from `gh auth status`."""
    rc, out = run(["gh", "auth", "status"])
    accounts = []
    for line in out.splitlines():
        m = re.search(r"account (\S+)", line)
        if "Logged in to" in line and m:
            accounts.append([m.group(1), False])
        if "Active account: true" in line and accounts:
            accounts[-1][1] = True
    return accounts


def viewer_perm(repo):
    rc, out = run(["gh", "repo", "view", repo, "--json", "viewerPermission"])
    if rc != 0:
        return ""
    try:
        return json.loads(out).get("viewerPermission", "")
    except ValueError:
        return ""


def ensure_account(repo, log):
    """Make sure the active gh account can write secrets on `repo`.

    Tries the active account first, then the repo owner, then any other
    logged-in account, switching with `gh auth switch`. Returns the account
    name on success or None on failure."""
    owner = repo.split("/")[0]
    accounts = gh_accounts()
    if not accounts:
        log("[!] no GitHub account is logged in - run: gh auth login")
        return None
    active = next((n for n, a in accounts if a), None)
    log("Logged-in accounts: %s (active: %s)"
        % (", ".join(n for n, _ in accounts), active or "?"))

    perm = viewer_perm(repo)
    if perm in WRITE_PERMS:
        log("[+] active account '%s' has %s on %s" % (active, perm, repo))
        return active

    log("[*] active account '%s' has '%s' on %s - looking for the right one"
        % (active, perm or "no access", repo))
    names = [n for n, _ in accounts]
    order = ([owner] if owner in names else []) + [n for n in names if n != owner]
    for cand in order:
        if cand == active:
            continue
        rc, out = run(["gh", "auth", "switch", "--user", cand])
        if rc != 0:
            log("    could not switch to %s: %s" % (cand, out.strip()))
            continue
        perm = viewer_perm(repo)
        if perm in WRITE_PERMS:
            log("[+] switched to '%s' (%s on %s)" % (cand, perm, repo))
            return cand
        log("    %s has '%s' - not enough" % (cand, perm or "no access"))
    log("[!] no logged-in account has admin on %s. Log in as its owner (%s)."
        % (repo, owner))
    return None


# --------------------------------------------------------------- access list
def parse_access(text):
    """Ordered list of {name, secret, domains} from access.txt text."""
    users, cur = [], None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.upper().startswith("SECRET-") and "=" in line:
            name, _, val = line[len("SECRET-"):].partition("=")
            cur = {"name": name.strip(), "secret": val.strip(), "domains": []}
            if cur["name"] and cur["secret"]:
                users.append(cur)
        elif cur is not None:
            cur["domains"].append(clean_domain(line))
    for u in users:
        u["domains"] = [d for d in u["domains"] if d]
    return users


def serialize_access(users):
    out = ["# Tsoolgee proxy access list - managed by make_user.py",
           "# One block per user: SECRET-<NAME>=<value> then allowed domains.",
           "# No domains under a user = full access.", ""]
    for u in users:
        out.append("SECRET-%s=%s" % (u["name"], u["secret"]))
        out.extend(u["domains"])
        out.append("")
    return "\n".join(out).rstrip() + "\n"


def load_users():
    if not os.path.exists(ACCESS):
        return []
    with open(ACCESS, encoding="utf-8") as f:
        return parse_access(f.read())


def clean_domain(d):
    """Normalise a domain entry: lowercase, drop scheme/path/leading *. and dot."""
    d = d.strip().lower()
    if not d or d == "*":
        return d
    d = re.sub(r"^[a-z]+://", "", d)           # strip scheme
    d = d.split("/")[0].split("?")[0]          # strip path/query
    d = d.lstrip("*").lstrip(".")              # *.foo.com / .foo.com -> foo.com
    return d


# --------------------------------------------------------------- extension gen
def bg_js(name, domains):
    """Per-user background.js: PAC routes only `domains` through the proxy."""
    dom_json = json.dumps(domains, ensure_ascii=False)
    return (
        '// Tsoolgee Proxy - built for: %s\n'
        '// Only these domains go through the local proxy (127.0.0.1:10809);\n'
        '// everything else connects DIRECT.\n'
        'const USER = %s;\n'
        'const DOMAINS = %s;   // [] = all sites through the proxy\n'
        '\n'
        'function pacData() {\n'
        '  return "function FindProxyForURL(url, host){" +\n'
        '    "host = host.toLowerCase();" +\n'
        '    "if (host===\\"localhost\\"||shExpMatch(host,\\"127.*\\")||host===\\"[::1]\\") return \\"DIRECT\\";" +\n'
        '    "var d = " + JSON.stringify(DOMAINS) + ";" +\n'
        '    "if (d.length===0) return \\"PROXY 127.0.0.1:10809\\";" +\n'
        '    "for (var i=0;i<d.length;i++){ if (host===d[i]||shExpMatch(host,\\"*.\\"+d[i])) return \\"PROXY 127.0.0.1:10809\\"; }" +\n'
        '    "return \\"DIRECT\\";" +\n'
        '  "}";\n'
        '}\n'
        '\n'
        'function apply(enabled) {\n'
        '  if (enabled) {\n'
        '    chrome.proxy.settings.set({ scope: "regular",\n'
        '      value: { mode: "pac_script", pacScript: { data: pacData() } } });\n'
        '    chrome.action.setBadgeText({ text: "ON" });\n'
        '    chrome.action.setBadgeBackgroundColor({ color: "#16a34a" });\n'
        '  } else {\n'
        '    chrome.proxy.settings.clear({ scope: "regular" });\n'
        '    chrome.action.setBadgeText({ text: "OFF" });\n'
        '    chrome.action.setBadgeBackgroundColor({ color: "#9ca3af" });\n'
        '  }\n'
        '}\n'
        '\n'
        'function syncFromStorage() {\n'
        '  chrome.storage.local.get({ enabled: true }, (s) => apply(s.enabled));\n'
        '}\n'
        'chrome.runtime.onInstalled.addListener(() => {\n'
        '  chrome.storage.local.get({ enabled: true }, (s) => {\n'
        '    chrome.storage.local.set({ enabled: s.enabled }, () => apply(s.enabled));\n'
        '  });\n'
        '});\n'
        'chrome.runtime.onStartup.addListener(syncFromStorage);\n'
        'chrome.storage.onChanged.addListener((changes, area) => {\n'
        '  if (area === "local" && changes.enabled) apply(changes.enabled.newValue);\n'
        '});\n'
        'syncFromStorage();\n'
        % (name, json.dumps(name, ensure_ascii=False), dom_json)
    )


def manifest_json(name):
    return json.dumps({
        "manifest_version": 3,
        "name": "Tsoolgee Proxy - %s" % name,
        "version": "1.0.0",
        "description": "פרוקסי מותאם ל-%s - רק הדומיינים המאושרים עוברים דרכו." % name,
        "permissions": ["proxy", "storage"],
        "background": {"service_worker": "background.js"},
        "action": {"default_popup": "popup.html",
                   "default_title": "Tsoolgee Proxy - %s" % name},
        "icons": {"16": "icons/icon16.png", "48": "icons/icon48.png",
                  "128": "icons/icon128.png"},
    }, ensure_ascii=False, indent=2)


def popup_html(name, domains):
    listed = "כל האתרים" if not domains else "%d דומיינים מאושרים" % len(domains)
    rows = "".join("<li>%s</li>" % d for d in domains) if domains else ""
    extra = ('<details><summary>הדומיינים המאושרים</summary><ul class="doms">%s</ul></details>'
             % rows) if domains else ""
    return (
        '<!doctype html><html lang="he" dir="rtl"><head><meta charset="utf-8"><style>'
        ':root{color-scheme:light dark}'
        'body{width:250px;margin:0;padding:16px;font:14px system-ui,"Segoe UI",Arial;background:#fff;color:#111827}'
        '@media(prefers-color-scheme:dark){body{background:#1f2937;color:#f3f4f6}}'
        'h1{font-size:15px;margin:0 0 2px}.who{font-size:12px;color:#6b7280;margin-bottom:10px}'
        '.status{font-size:13px;margin-bottom:12px}'
        '.dot{display:inline-block;width:9px;height:9px;border-radius:50%%;margin-inline-start:6px;vertical-align:middle}'
        'button{width:100%%;padding:10px;font-size:14px;font-weight:600;border:0;border-radius:8px;cursor:pointer;color:#fff}'
        '.on{background:#16a34a}.off{background:#6b7280}'
        'details{margin-top:12px;font-size:12px}.doms{margin:6px 0;padding-inline-start:18px;max-height:140px;overflow:auto}'
        '.doms li{direction:ltr;text-align:left}'
        '</style></head><body>'
        '<h1>Tsoolgee Proxy</h1><div class="who">%s &middot; %s</div>'
        '<div class="status">מצב: <span id="label">…</span><span id="dot" class="dot"></span></div>'
        '<button id="toggle">…</button>%s'
        '<script src="popup.js"></script></body></html>'
        % (name, listed, extra)
    )


POPUP_JS = (
    'const label=document.getElementById("label");'
    'const dot=document.getElementById("dot");'
    'const btn=document.getElementById("toggle");'
    'function render(e){'
    'label.textContent=e?"פעיל (דרך הפרוקסי)":"כבוי (חיבור ישיר)";'
    'dot.style.background=e?"#16a34a":"#9ca3af";'
    'btn.textContent=e?"כבה פרוקסי":"הפעל פרוקסי";'
    'btn.className=e?"on":"off";}'
    'chrome.storage.local.get({enabled:true},(s)=>render(s.enabled));'
    'btn.addEventListener("click",()=>{'
    'chrome.storage.local.get({enabled:true},(s)=>{'
    'const n=!s.enabled;chrome.storage.local.set({enabled:n},()=>render(n));});});'
)


def build_extension(name, domains, dest):
    ext = os.path.join(dest, "extension")
    os.makedirs(ext, exist_ok=True)
    # icons from the base extension
    src_icons = os.path.join(EXT_SRC, "icons")
    if os.path.isdir(src_icons):
        shutil.copytree(src_icons, os.path.join(ext, "icons"), dirs_exist_ok=True)
    _write(os.path.join(ext, "manifest.json"), manifest_json(name))
    _write(os.path.join(ext, "background.js"), bg_js(name, domains))
    _write(os.path.join(ext, "popup.html"), popup_html(name, domains))
    _write(os.path.join(ext, "popup.js"), POPUP_JS)
    return ext


def _write(path, text):
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


# --------------------------------------------------------------- client EXE
def build_client(name, log):
    """Run build_exe.py NAME; return the built exe path or None."""
    rc, out = run([sys.executable, os.path.join(ROOT, "build_exe.py"), name])
    for line in out.splitlines():
        log("    " + line)
    exe = os.path.join(ROOT, "dist", "TsoolgeeProxy-%s.exe" % name)
    return exe if rc == 0 and os.path.exists(exe) else None


# --------------------------------------------------------------- server restart
def restart_server(repo, log):
    """Arm a fresh run (picks up the new secret) and cancel the running one
    so it takes over within ~a minute (brief interruption for everyone)."""
    rc, out = run(["gh", "workflow", "run", WORKFLOW, "--repo", repo, "--ref", "main"])
    log("    dispatch: %s" % (out.strip() or "ok" if rc == 0 else out.strip()))
    rc, out = run(["gh", "run", "list", "--workflow", WORKFLOW, "--repo", repo,
                   "--status", "in_progress", "--json", "databaseId", "-q",
                   ".[].databaseId"])
    ids = [x for x in out.split() if x.isdigit()]
    for rid in ids:
        run(["gh", "run", "cancel", rid, "--repo", repo])
        log("    cancelled running server %s (fresh run will take over)" % rid)
    if not ids:
        log("    no run in progress; the dispatched run will start shortly")


# --------------------------------------------------------------- readme in zip
def user_readme(name, domains):
    doms = "\n".join("  - " + d for d in domains) if domains else "  (כל האתרים)"
    return (
        "פרוקסי Tsoolgee - הוראות התקנה עבור %s\n"
        "=========================================\n\n"
        "1) הרצת התוכנה:\n"
        "   הפעל את הקובץ TsoolgeeProxy-%s.exe (השאר אותו פתוח כל עוד אתה גולש).\n\n"
        "2) התקנת התוסף בכרום:\n"
        "   - פתח chrome://extensions\n"
        "   - הפעל 'מצב מפתח' (Developer mode) בפינה\n"
        "   - לחץ 'טען פריט לא ארוז' (Load unpacked) ובחר את התיקייה 'extension'\n\n"
        "התוסף מעביר דרך הפרוקסי רק את הדומיינים המאושרים; כל השאר - חיבור רגיל.\n\n"
        "הדומיינים המאושרים:\n%s\n"
        % (name, name, doms)
    )


def make_zip(name, dest, exe_path, domains):
    _write(os.path.join(dest, "README.txt"), user_readme(name, domains))
    if exe_path and os.path.exists(exe_path):
        shutil.copy2(exe_path, os.path.join(dest, os.path.basename(exe_path)))
    zip_path = os.path.join(OUT_DIR, "%s.zip" % name)
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        for root, _, files in os.walk(dest):
            for fn in files:
                full = os.path.join(root, fn)
                z.write(full, os.path.relpath(full, dest))
    return zip_path


# =============================================================== GUI
class App:
    def __init__(self, root):
        self.root = root
        root.title("Tsoolgee Proxy - יצירת משתמש")
        root.geometry("560x620")
        pad = {"padx": 12, "pady": 4}

        tk.Label(root, text="שם המשתמש (באנגלית, בלי רווחים):",
                 anchor="e").pack(fill="x", **pad)
        self.name = tk.Entry(root, font=("Segoe UI", 12))
        self.name.pack(fill="x", padx=12)

        tk.Label(root, text="דומיינים מאושרים (אחד בכל שורה, ריק = הכל):",
                 anchor="e").pack(fill="x", **pad)
        self.doms = scrolledtext.ScrolledText(root, height=8, font=("Consolas", 11))
        self.doms.pack(fill="x", padx=12)

        self.restart = tk.BooleanVar(value=True)
        tk.Checkbutton(root, text="החל מיד (הפעלה מחדש של השרת, ~דקה הפסקה לכולם)",
                       variable=self.restart, anchor="e").pack(fill="x", padx=12, pady=6)

        row = tk.Frame(root); row.pack(fill="x", padx=12, pady=4)
        self.btn = tk.Button(row, text="צור / עדכן משתמש", height=2,
                             bg="#16a34a", fg="white", font=("Segoe UI", 12, "bold"),
                             command=self.on_go)
        self.btn.pack(side="right", fill="x", expand=True)
        tk.Button(row, text="טען משתמש קיים", command=self.on_load).pack(side="right", padx=6)

        self.log_box = scrolledtext.ScrolledText(root, height=14, font=("Consolas", 9),
                                                 bg="#0b1020", fg="#d1d5db")
        self.log_box.pack(fill="both", expand=True, padx=12, pady=8)
        self.log("מוכן. הזן שם ודומיינים, ולחץ 'צור / עדכן משתמש'.")
        existing = [u["name"] for u in load_users()]
        if existing:
            self.log("משתמשים קיימים: " + ", ".join(existing))

    def log(self, m):
        # marshal to the main thread - the pipeline runs on a worker thread
        self.root.after(0, self._log_main, m)

    def _log_main(self, m):
        self.log_box.insert("end", m + "\n")
        self.log_box.see("end")

    def _set_busy(self, busy):
        self.root.after(0, lambda: self.btn.config(state="disabled" if busy else "normal"))

    def on_load(self):
        name = self.name.get().strip()
        u = next((u for u in load_users() if u["name"].lower() == name.lower()), None)
        if not u:
            messagebox.showinfo("לא נמצא", "אין משתמש בשם הזה ב-access.txt.")
            return
        self.doms.delete("1.0", "end")
        self.doms.insert("1.0", "\n".join(u["domains"]))
        self.log("[*] נטען '%s' (%s)"
                 % (u["name"], "הכל" if not u["domains"] else "%d דומיינים" % len(u["domains"])))

    def on_go(self):
        name = self.name.get().strip()
        if not re.fullmatch(r"[A-Za-z0-9_-]+", name or ""):
            messagebox.showerror("שם לא תקין",
                                 "השם חייב להיות אנגלית/מספרים/מקף בלבד, בלי רווחים.")
            return
        domains = []
        for line in self.doms.get("1.0", "end").splitlines():
            d = clean_domain(line)
            if d and d not in domains:
                domains.append(d)
        self._set_busy(True)
        threading.Thread(target=self._work, args=(name, domains), daemon=True).start()

    def _work(self, name, domains):
        try:
            self._pipeline(name, domains)
        except Exception as e:
            self.log("[!] שגיאה: %s: %s" % (type(e).__name__, e))
        finally:
            self._set_busy(False)

    def _pipeline(self, name, domains):
        ok = build_user(name, domains, self.restart.get(), self.log)
        if ok:
            try:
                if os.name == "nt":
                    os.startfile(OUT_DIR)      # open the output folder
            except OSError:
                pass


# =============================================================== the pipeline
def build_user(name, domains, restart, log):
    """The whole per-user flow, shared by the GUI and the CLI. `log` is a
    callable taking one string. Returns True on success."""
    log("\n" + "=" * 52)
    log("משתמש: %s | דומיינים: %s"
        % (name, "הכל (גישה מלאה)" if not domains else ", ".join(domains)))

    repo = repo_slug()
    if not repo:
        log("[!] לא נמצא remote 'origin' של git. הרץ מתוך תיקיית הפרויקט.")
        return False
    log("repo של השרת: %s" % repo)

    # remember the account that was active, to restore it at the end
    original = next((n for n, a in gh_accounts() if a), None)
    try:
        return _run_gh_and_build(repo, name, domains, restart, log)
    finally:
        if original:
            now = next((n for n, a in gh_accounts() if a), None)
            if now != original:
                run(["gh", "auth", "switch", "--user", original])
                log("[*] הוחזר החשבון הפעיל ל-%s." % original)


def _run_gh_and_build(repo, name, domains, restart, log):
    # 1) correct account
    acct = ensure_account(repo, log)
    if not acct:
        return False

    # 2/3) upsert the user in access.txt (keep secret if it exists)
    users = load_users()
    existing = next((u for u in users if u["name"].lower() == name.lower()), None)
    if existing:
        existing["name"] = name          # normalise casing to what was typed
        existing["secret"] = existing["secret"] or secrets.token_hex(32)
        existing["domains"] = domains
        log("[*] מעדכן משתמש קיים (הסוד נשמר).")
    else:
        users.append({"name": name, "secret": secrets.token_hex(32),
                      "domains": domains})
        log("[+] משתמש חדש, נוצר סוד חדש.")
    _write(ACCESS, serialize_access(users))
    log("[+] access.txt עודכן (%d משתמשים)." % len(users))

    # 4) push to the server (repo secret)
    rc, out = run(["gh", "secret", "set", SECRET_SET_NAME, "--repo", repo],
                  input_bytes=open(ACCESS, "rb").read())
    if rc != 0:
        log("[!] כשל בהעלאת הסוד לשרת: %s" % out.strip())
        return False
    log("[+] הרשימה הועלתה ל-%s (repo secret %s)." % (repo, SECRET_SET_NAME))

    # 5) per-user extension
    dest = os.path.join(OUT_DIR, name)
    if os.path.isdir(dest):
        shutil.rmtree(dest, ignore_errors=True)
    os.makedirs(dest, exist_ok=True)
    build_extension(name, domains, dest)
    log("[+] נוצר תוסף מותאם (PAC לפי הדומיינים המאושרים).")

    # 6) client EXE
    log("[*] בונה EXE ללקוח (עשוי לקחת דקה)...")
    exe = build_client(name, log)
    if exe:
        log("[+] EXE נבנה: %s" % os.path.basename(exe))
    else:
        log("[!] בניית ה-EXE נכשלה (PyInstaller?). התוסף והסוד מוכנים בכל זאת.")

    # 7) zip package
    zip_path = make_zip(name, dest, exe, domains)
    log("[+] חבילה מוכנה: %s" % zip_path)

    # optional immediate restart
    if restart:
        log("[*] מפעיל מחדש את השרת כדי להחיל מיד...")
        restart_server(repo, log)

    log("== סיום ==  שלח למשתמש את הקובץ: %s" % os.path.basename(zip_path))
    return True


def run_cli(argv):
    """Headless run: make_user.py --cli --name NAME [--domains a.com,b.com]
    [--no-restart]. Runs the exact same pipeline as the GUI button."""
    name = domains = None
    restart = True
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--name":
            i += 1; name = argv[i]
        elif a == "--domains":
            i += 1; domains = argv[i]
        elif a == "--no-restart":
            restart = False
        i += 1
    if not name or not re.fullmatch(r"[A-Za-z0-9_-]+", name):
        sys.exit("--name is required (letters/digits/-, no spaces)")
    doms = []
    for part in re.split(r"[,\n]", domains or ""):
        d = clean_domain(part)
        if d and d not in doms:
            doms.append(d)
    os.makedirs(OUT_DIR, exist_ok=True)
    ok = build_user(name, doms, restart, lambda m: print(m, flush=True))
    sys.exit(0 if ok else 1)


def main():
    if "--cli" in sys.argv:
        run_cli([a for a in sys.argv[1:] if a != "--cli"])
        return
    os.makedirs(OUT_DIR, exist_ok=True)
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
