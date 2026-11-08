# Remediation Guide

Offer these steps; run them only when the user asks. Rewriting history and force-pushing
are destructive — confirm first.

## Order matters

1. **Rotate / revoke** any secret that was ever committed, pushed, uploaded, or pasted
   into an AI tool. Assume it's compromised. Deleting the file does not un-leak it.
2. **Remove from the working tree** — move to a secret manager or a local `.env` that's ignored.
3. **Prevent recurrence** — add to `.gitignore`; add a pre-commit hook (gitleaks,
   detect-secrets); ship a `.env.example` with placeholders.
4. **Clean history** (only if the repo is or will be shared and the value can't be rotated,
   e.g. PII):
   ```bash
   # remove a file from all history
   git filter-repo --path path/to/file --invert-paths
   # replace strings across history (expressions in replacements.txt: literal==>REDACTED)
   git filter-repo --replace-text replacements.txt
   git push --force --all && git push --force --tags
   ```
   Forks and clones keep the old data; on GitHub, contact support to purge cached views
   for sensitive data.

## Commit author email leak

```bash
# future commits
git config --global user.email "<id>+<username>@users.noreply.github.com"
# single/last commit
git commit --amend --reset-author --no-edit && git push --force
# whole history
git filter-repo --email-callback 'return email.replace(b"old@gmail.com", b"<id>+<user>@users.noreply.github.com")'
```
GitHub → Settings → Emails: enable "Keep my email addresses private" and
"Block command line pushes that expose my email".

## Before giving a folder to an AI tool / contractor

- Remember ignored files are usually still visible to the tool.
- Copy a sanitized subset instead of the whole workspace, or use the tool's ignore file
  (`.cursorignore`, `.aiexclude`, Claude Code permission deny rules).
- Replace real datasets with synthetic samples.
