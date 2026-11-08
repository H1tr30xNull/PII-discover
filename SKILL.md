---
name: pii-discover
description: PII Discover — scan a repository, folder, or set of files BEFORE it is shared with AI agents (Claude, Cursor, Copilot, ChatGPT, Gemini, DeepSeek), contractors, third-party tools, or made public, and report real credentials, personal data, customer data, and internal business info worth removing — ranked by severity, with values masked. Use whenever the user asks "is there PII/secrets in here?", "can I safely share/publish/open-source this?", "check before I push to GitHub", "scan for API keys/tokens/passwords/emails", "leak check", "sanitize before upload", "before bug bounty writeup", or mentions making a repo public — even if they don't say "audit". Also checks git history and commit author emails, archives (zip/tar), notebooks, logs, and dumps. Read-only: reports, never deletes.
---

# PII Discover

## Purpose

Answer one practical question:

> **"Can I safely give this to Claude, Cursor, Copilot, ChatGPT, Gemini, DeepSeek,
> a contractor, or the public internet?"**

Find the sensitive things that would actually hurt if they leaked — credentials,
personal data, customer data, internal infrastructure details — and rank them so the
user fixes the few that matter instead of wading through hundreds of regex hits.

The goal is **risk awareness, not automatic deletion.** The audit is read-only: don't
delete, rewrite, or "sanitize" anything unless the user asks afterward.

**Never reproduce a full secret or full PII value in the report or chat.** The report
itself may get pasted into a ticket, a PR, or another AI tool. Mask values
(`AKIA…X7Q2`, `j***@gmail.com`, `+84 9** *** *21`) and point to `file:line` instead.

---

## Phase 1 — Repository Discovery

Map the scope first, so nothing is assumed to be checked when it wasn't.

1. **Define scope**: the path the user named, else the current working directory.
   Note whether it's a git repo and whether it has a remote (and if it's public).
2. **Inventory artifacts** that commonly hold sensitive data:
   - source code; config (`*.json`, `*.yaml`, `*.toml`, `*.ini`, `*.properties`, `*.xml`)
   - environment files (`.env*`, `*.env`, `secrets.*`, `credentials*`, `*.tfvars`)
   - keys & certs (`*.pem`, `*.key`, `id_rsa*`, `*.p12`, `*.pfx`, `*.jks`, `*.kdbx`)
   - logs, dumps, databases (`*.log`, `*.sql`, `*.sqlite`, `*.db`, `*.csv`, `*.xlsx`, `*.har`)
   - documents & notes (`*.md`, `*.txt`, `*.pdf`, `*.docx`), Jupyter notebooks (outputs!)
   - CI/CD (`.github/workflows`, `.gitlab-ci.yml`, `Jenkinsfile`), IaC (Terraform, k8s, Helm, Docker, Ansible)
   - archives (`*.zip`, `*.tar*`, `*.7z`) — their contents ship too
   - tool/agent state that leaks easily: `.vscode/`, `.idea/`, `.claude/`, `.cursor/`, shell history, `*.bak`
3. **Git layer** (if a repo): tracked vs ignored files (`git ls-files`, `git status --ignored`),
   **commit author/committer emails** (`git log --all --format='%an <%ae> | %cn <%ce>' | sort -u`),
   and **history** — secrets deleted in a later commit are still public.

Run the bundled scanner for a fast first pass (stdlib Python, no install):

```bash
python3 <skill-dir>/scripts/scan.py <path> [--history] [--json out.json]
```

It scans the working tree (skipping `.git`, `node_modules`, venvs, binaries), looks
inside zip archives, optionally scans git history, reports git author emails, and
prints **masked** candidates with `file:line`, type, and a placeholder guess. If
`gitleaks`, `trufflehog`, or `detect-secrets` are installed, run them too — more
detectors, fewer misses. Tool output is *candidates*, not findings: Phase 3 decides.

Skim manually what regexes miss: README/docs (names, phone numbers, internal URLs),
screenshots/PDFs named like reports or invoices, CSV/SQL dumps (open the header and a
few rows), notebook outputs, and infrastructure files.

---

## Phase 2 — Sensitive Data Detection

Look for four categories (patterns and examples in `references/detection-patterns.md`):

- **PII** — full names tied to other data, emails, phone numbers, physical addresses,
  passport / national ID numbers, employee or customer identifiers, dates of birth.
- **Credentials & secrets** — API keys, access tokens, JWT signing secrets, OAuth client
  secrets, AWS / Azure / GCP credentials (incl. service-account JSON), database URLs with
  passwords, SSH/TLS private keys, certificates with keys, webhook URLs (Slack/Discord),
  `.npmrc`/`.pypirc` tokens, kubeconfigs.
- **Internal business information** — internal hostnames/URLs/IPs, non-public endpoints,
  architecture diagrams, proprietary algorithms, internal ticket IDs/links, incident reports.
- **Customer data** — production records, user profiles, support conversations,
  payment data, transaction records.

---

## Phase 3 — Exposure Assessment

For each candidate, answer three questions. This is where most noise disappears.

**1. Is it real?**
`Production secret` · `Example value` · `Placeholder` · `Mock data`.
Signals of fake: `example`, `dummy`, `test`, `xxx`, `changeme`, `your_key_here`,
`<...>`, `${VAR}`, all-same characters, documented vendor example keys (e.g.
`AKIAIOSFODNN7EXAMPLE`), `example.com`/`555-` numbers, test fixtures. Signals of real:
high entropy, correct provider format and length, sits in `.env.production` / deploy
config, matches a real domain or org. **Don't verify a secret by calling the provider's
API** — that's using the credential. Judge from context, and when unsure say "likely
real — treat as real".

**2. Is it reachable?**
`Committed` (tracked, or in history) · `Generated` (build output, logs) ·
`Documented` (README, docs) · `Ignored` (in `.gitignore` — still ships in a zip, an
upload, or an AI agent's context!) · `Archived` (inside zip/tar). Note that "shared with
an AI tool" usually means the whole folder, ignored files included.

**3. Potential impact** — privacy · security · business · compliance (GDPR, PDPA,
HIPAA, PCI-DSS) — and blast radius (one test account vs production cloud root).

---

## Phase 4 — Risk Ranking

| Severity | Meaning |
|---|---|
| **Critical** | Immediate credential or customer-data exposure (live keys, private keys, prod DB creds, customer PII dumps, payment data) |
| **High** | Sensitive internal information or a likely-real secret of limited scope (internal endpoints + hostnames, personal email in public git history, internal incident reports, staging creds) |
| **Medium** | Potential privacy or operational risk (employee names/phones in docs, internal ticket links, IPs, verbose logs) |
| **Low** | Limited-impact disclosure (mock creds, example keys, public business contact info) |

Group repeated hits ("Same Stripe key in 4 files" = one finding). Already-public
information (a name on the user's own public GitHub profile) is Low unless combined
with something private.

---

## Output

Use `references/output-template.md`. Core shape:

```markdown
## PII & Secret Exposure Report — <scope>

**Verdict:** ❌ Not safe to share yet | ⚠️ Safe after fixing Critical/High | ✅ Safe to share

| # | Finding | Location | Severity | Real? | Remove before sharing? |
|---|---|---|---|---|---|
| 1 | AWS production access key (`AKIA…X7Q2`) | `.env.production:3` | Critical | Likely real | Yes |
| 2 | Customer emails (≈4,200 rows) | `data/users.csv` | Critical | Real | Yes |
| 3 | Personal email in commit author | git history (2 commits) | High | Real | Yes |
| 4 | Mock test credentials | `tests/fixtures/auth.json` | Low | Mock | Optional |

### Executive summary
Detected N potentially sensitive items — Critical: a · High: b · Medium: c · Low: d.
<one sentence answering "can I share this?">

### Fix first
Concrete steps for Critical/High only.
```

**Fix guidance** (offer, don't execute): for any secret that was ever committed or
pushed, **rotate/revoke it first** — deleting the file doesn't un-leak it. Then remove
from tree, add to `.gitignore`, and if history matters rewrite it (`git filter-repo`,
BFG) and force-push; for author emails, switch to the GitHub noreply address and amend/rewrite.
See `references/remediation.md`.

Match the user's language for the prose; keep paths, commands, and identifiers as-is.

---

## Core Rules

1. **Don't assume every hit is sensitive.** Validate context before reporting.
2. **Signal over noise.** Never flood the user with hundreds of trivial findings —
   group, filter, and put Low items in a collapsed/short list.
3. **Focus on what's worth reviewing before sharing.**
4. **Answer the practical question** — can this safely go to an AI tool, a contractor,
   or the public? Give a clear verdict.
5. **Prevent accidental disclosure, not compliance checkbox auditing.**
6. **Mask every value; never echo a full secret.** Don't send findings to external
   services. State what was *not* scanned (binaries, huge files, encrypted archives) so
   "no findings" isn't mistaken for "verified clean".
