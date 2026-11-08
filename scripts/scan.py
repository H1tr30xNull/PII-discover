#!/usr/bin/env python3
"""First-pass PII & secret candidate scanner (stdlib only).

Usage:
  python3 scan.py <path> [--history] [--json out.json] [--max-mb 5]

Prints MASKED candidates as file:line. Candidates are not findings —
the agent must judge context (real vs placeholder, reachability, impact).
"""
import argparse, io, json, math, os, re, subprocess, sys, zipfile
from collections import Counter

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "env", "__pycache__", ".tox",
             "dist", "build", ".next", ".cache", "target", ".gradle", ".terraform"}
BIN_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".mp4", ".mov", ".mp3",
           ".wav", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".so", ".dll", ".exe", ".bin",
           ".class", ".jar", ".pyc", ".o", ".a", ".dylib", ".pdf", ".7z", ".gz", ".tgz",
           ".bz2", ".xz", ".rar", ".iso", ".dmg", ".sqlite", ".db"}
SENSITIVE_NAMES = re.compile(
    r"(^|/)(\.env(\..*)?|.*\.env|secrets?\..*|credentials?.*|.*\.pem|.*\.key|id_(rsa|dsa|ecdsa|ed25519)"
    r"|.*\.p12|.*\.pfx|.*\.jks|.*\.kdbx|.*\.tfvars|\.npmrc|\.pypirc|\.netrc|kubeconfig|.*\.har"
    r"|.*\.sql|.*\.sqlite|.*\.db|.*dump.*|.*backup.*|.*\.bak|\.bash_history|\.zsh_history)$", re.I)

RULES = [
    ("private-key", "Critical", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY-----"),
    ("aws-access-key", "Critical", r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"),
    ("gcp-service-account", "Critical", r"\"type\"\s*:\s*\"service_account\""),
    ("github-token", "Critical", r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b"),
    ("gitlab-token", "Critical", r"\bglpat-[A-Za-z0-9_\-]{20,}\b"),
    ("slack-token", "Critical", r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    ("slack-webhook", "High", r"https://hooks\.slack\.com/services/[A-Za-z0-9/_\-]+"),
    ("discord-webhook", "High", r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[\w\-]+"),
    ("stripe-live", "Critical", r"\b(?:sk|rk)_live_[0-9a-zA-Z]{20,}\b"),
    ("stripe-test", "Low", r"\b(?:sk|rk)_test_[0-9a-zA-Z]{20,}\b"),
    ("anthropic-key", "Critical", r"\bsk-ant-[A-Za-z0-9_\-]{20,}"),
    ("openai-key", "Critical", r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{32,}"),
    ("google-api-key", "High", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    ("sendgrid-key", "Critical", r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"),
    ("azure-conn-string", "Critical", r"(?:AccountKey|SharedAccessKey)=[A-Za-z0-9+/=]{20,}"),
    ("jwt", "High", r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    ("db-url-with-password", "Critical",
     r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqps?|mssql)://[^\s:/@]+:[^\s@/]+@[^\s/]+"),
    ("npm-token", "Critical", r"_authToken\s*=\s*\S+"),
    ("generic-secret", "Medium",
     r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret)"
     r"\b[\"']?\s*[:=]\s*[\"']?([^\s\"',;]{8,})"),
    ("email", "Medium", r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
    ("phone-vn", "Medium", r"(?<![\d\w])(?:\+84|0)(?:3|5|7|8|9)\d{8}(?!\d)"),
    ("phone-intl", "Low", r"(?<![\d\w])\+\d{1,3}[\s\-.]?\(?\d{2,4}\)?[\s\-.]?\d{3,4}[\s\-.]?\d{3,4}(?!\d)"),
    ("us-ssn", "High", r"\b\d{3}-\d{2}-\d{4}\b"),
    ("card-number", "Critical", r"\b(?:\d[ \-]?){13,19}\b"),
    ("private-ip", "Low", r"\b(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b"),
    ("internal-host", "Medium", r"\b[a-z0-9\-]+(?:\.[a-z0-9\-]+)*\.(?:internal|corp|intranet|lan)\b"),
]
RULES = [(n, s, re.compile(p)) for n, s, p in RULES]

PLACEHOLDER = re.compile(
    r"(?i)(example|sample|dummy|fake|mock|test|changeme|change_me|your[_\-]?|xxx+|\*{3,}|placeholder|"
    r"<[^>]+>|\$\{[^}]+\}|\{\{[^}]+\}\}|redacted|lorem|foo|bar\b|todo|AKIAIOSFODNN7EXAMPLE|4242424242424242|4111 ?1111 ?1111 ?1111)")
SAFE_EMAIL = re.compile(r"(?i)@(example\.(com|org|net)|test\.com|localhost|users\.noreply\.github\.com)$|^(noreply|no-reply)@")


def mask(v):
    v = v.strip()
    if "@" in v and "." in v.split("@")[-1]:
        u, d = v.split("@", 1)
        return (u[:1] + "***@" + d) if u else "***@" + d
    if len(v) <= 8:
        return v[:1] + "*" * (len(v) - 1)
    return v[:4] + "…" + v[-4:]


def entropy(s):
    if not s:
        return 0.0
    c = Counter(s)
    return -sum(n / len(s) * math.log2(n / len(s)) for n in c.values())


def luhn(num):
    d = [int(x) for x in num if x.isdigit()]
    if not 13 <= len(d) <= 19 or len(set(d)) == 1:
        return False
    s = 0
    for i, x in enumerate(reversed(d)):
        if i % 2:
            x *= 2
            x -= 9 if x > 9 else 0
        s += x
    return s % 10 == 0


def scan_text(text, where, out):
    for ln, line in enumerate(text.splitlines(), 1):
        if len(line) > 5000:
            line = line[:5000]
        for name, sev, rx in RULES:
            for m in rx.finditer(line):
                val = m.group(1) if m.groups() and m.group(1) else m.group(0)
                if name == "card-number" and not luhn(val):
                    continue
                if name == "email" and (SAFE_EMAIL.search(val) or line[max(0, m.start() - 1):m.start()] == ":"):
                    continue  # placeholder domain, or user:pass@host inside a URL
                if name == "generic-secret" and entropy(val) < 3.0:
                    continue
                ph = bool(PLACEHOLDER.search(line))
                out.append({"type": name, "severity": sev, "location": f"{where}:{ln}",
                            "value": mask(val), "placeholder_hint": ph})


def read_text(data):
    if b"\x00" in data[:4096]:
        return None
    return data.decode("utf-8", errors="replace")


def scan_tree(root, max_bytes, out, notes):
    files = 0
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in SKIP_DIRS]
        for fn in fns:
            p = os.path.join(dp, fn)
            rel = os.path.relpath(p, root)
            if SENSITIVE_NAMES.search(rel.replace(os.sep, "/")):
                out.append({"type": "sensitive-filename", "severity": "High", "location": rel,
                            "value": "-", "placeholder_hint": "example" in fn.lower() or "sample" in fn.lower()})
            ext = os.path.splitext(fn)[1].lower()
            try:
                size = os.path.getsize(p)
            except OSError:
                continue
            if ext == ".zip":
                scan_zip(p, rel, max_bytes, out, notes)
                continue
            if ext in BIN_EXT:
                notes.append(f"not scanned (binary): {rel}")
                continue
            if size > max_bytes:
                notes.append(f"not scanned (> limit): {rel}")
                continue
            try:
                with open(p, "rb") as f:
                    t = read_text(f.read())
            except OSError:
                continue
            if t is None:
                notes.append(f"not scanned (binary): {rel}")
                continue
            files += 1
            scan_text(t, rel, out)
    return files


def scan_zip(path, rel, max_bytes, out, notes):
    try:
        with zipfile.ZipFile(path) as z:
            for i in z.infolist():
                if i.is_dir():
                    continue
                inner = f"{rel}!{i.filename}"
                if SENSITIVE_NAMES.search(i.filename):
                    out.append({"type": "sensitive-filename", "severity": "High", "location": inner,
                                "value": "-", "placeholder_hint": False})
                if i.flag_bits & 0x1:
                    notes.append(f"not scanned (encrypted): {inner}")
                    continue
                if i.file_size > max_bytes or os.path.splitext(i.filename)[1].lower() in BIN_EXT:
                    notes.append(f"not scanned (binary/large): {inner}")
                    continue
                t = read_text(z.read(i))
                if t is not None:
                    scan_text(t, inner, out)
    except (zipfile.BadZipFile, OSError) as e:
        notes.append(f"not scanned (zip error {e}): {rel}")


def git(root, *args):
    try:
        r = subprocess.run(["git", "-C", root, *args], capture_output=True, text=True,
                           errors="replace", timeout=300)
        return r.stdout if r.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def scan_git(root, history, out, notes):
    if git(root, "rev-parse", "--is-inside-work-tree") is None:
        return None
    info = {"remotes": (git(root, "remote", "-v") or "").split("\n")[0:1]}
    authors = git(root, "log", "--all", "--format=%an <%ae>%n%cn <%ce>") or ""
    ids = sorted(set(a for a in authors.splitlines() if a.strip()))
    for a in ids:
        email = a[a.rfind("<") + 1:-1]
        if email and not SAFE_EMAIL.search(email):
            out.append({"type": "git-author-email", "severity": "High", "location": "git history (commit metadata)",
                        "value": a[:a.rfind("<")].strip() + " <" + mask(email) + ">", "placeholder_hint": False})
    if history:
        log = git(root, "log", "--all", "-p", "--no-color", "--format=commit %h")
        if log:
            commit, fpath, buf = "?", "?", []
            for line in log.splitlines():
                if line.startswith("commit "):
                    commit = line.split()[1]
                elif line.startswith("--- a/"):
                    fpath = line[6:]
                elif line.startswith("+++ b/"):
                    fpath = line[6:]
                elif line.startswith("-") and not line.startswith("---"):
                    buf.append((f"{commit}:{fpath}", line[1:]))  # removed lines = still in history
            seen = set()
            for where, l in buf:
                tmp = []
                scan_text(l, where, tmp)
                for t in tmp:
                    k = (t["type"], t["value"])
                    if k not in seen:
                        seen.add(k)
                        t["location"] = "history(deleted) " + t["location"].rsplit(":", 1)[0]
                        out.append(t)
        else:
            notes.append("git history not scanned (git log failed)")
    return info


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path", nargs="?", default=".")
    ap.add_argument("--history", action="store_true", help="also scan lines deleted in git history")
    ap.add_argument("--json", help="write full results to this file")
    ap.add_argument("--max-mb", type=float, default=5)
    a = ap.parse_args()
    root = os.path.abspath(a.path)
    out, notes = [], []
    files = scan_tree(root, int(a.max_mb * 1024 * 1024), out, notes)
    ginfo = scan_git(root, a.history, out, notes)
    # nested repos (e.g. a folder of skills, each its own git repo)
    for dp, dns, _ in os.walk(root):
        if ".git" in dns and os.path.abspath(dp) != root:
            sub = []
            if scan_git(dp, a.history, sub, notes) is not None:
                rel = os.path.relpath(dp, root)
                for c in sub:
                    c["location"] = f"[{rel}] " + c["location"]
                out.extend(sub)
        dns[:] = [d for d in dns if d not in SKIP_DIRS]

    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    out.sort(key=lambda x: (x["placeholder_hint"], order[x["severity"]], x["location"]))
    print(f"Scanned {files} text files under {root}" + (" (+git)" if ginfo else " (not a git repo)"))
    print(f"{len(out)} candidates (placeholder_hint=True means likely fake — verify)\n")
    for c in out[:300]:
        flag = " [placeholder?]" if c["placeholder_hint"] else ""
        print(f"[{c['severity']:<8}] {c['type']:<22} {c['location']}  {c['value']}{flag}")
    if len(out) > 300:
        print(f"... {len(out) - 300} more (use --json)")
    if notes:
        print("\nNot scanned / notes:")
        for n in notes[:50]:
            print("  - " + n)
        if len(notes) > 50:
            print(f"  ... {len(notes) - 50} more")
    if a.json:
        with open(a.json, "w") as f:
            json.dump({"root": root, "files": files, "git": ginfo, "candidates": out, "notes": notes}, f, indent=2)


if __name__ == "__main__":
    main()
