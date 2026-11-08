# Report Template

Mask every value. Point to `file:line`. Prose in the user's language.

```markdown
## PII & Secret Exposure Report — `<scope>`

> **Scanned:** <date> · **Git:** yes/no (remote: public/private/none) · **History scanned:** yes/no
> **Verdict:** ❌ Not safe to share yet | ⚠️ Safe after fixing Critical/High | ✅ Safe to share

| # | Finding | Location | Severity | Real? | Reachable | Remove before sharing? |
|---|---|---|---|---|---|---|
| 1 | AWS production access key (`AKIA…X7Q2`) | `.env.production:3` | Critical | Likely real | Committed | Yes — rotate first |
| 2 | Customer email list (≈4,200 rows) | `data/users.csv` | Critical | Real | Ignored (but ships in zip) | Yes |
| 3 | Internal API endpoint list | `docs/api-internal.md` | High | Real | Documented | Usually yes |
| 4 | Personal email as commit author (`m***@gmail.com`) | git history, 3 commits | High | Real | Committed | Yes (public repo) |
| 5 | Employee phone numbers | `docs/oncall.md:12-20` | Medium | Real | Documented | Recommended |
| 6 | Mock test credentials | `tests/fixtures/auth.json` | Low | Mock | Committed | Optional |

### Executive summary
Detected **6** potentially sensitive items.
Critical: 2 · High: 2 · Medium: 1 · Low: 1

Not safe to give this repo to an external AI tool or contractor yet — remove/rotate the
Critical and High findings first.

### Fix first
1. Revoke and rotate the AWS key, then remove `.env.production` and add it to `.gitignore`.
2. Move `data/users.csv` out of the project (or replace with synthetic data).
3. …

### Not scanned
- `assets/*.png` (images), `backup.7z` (encrypted), files > 5 MB: `dump.sql`
```

## Clean result

```markdown
## PII & Secret Exposure Report — `<scope>`

> **Verdict:** ✅ Safe to share

No credentials, personal data, or customer data found in N files (+ git history, M commits).

Low-impact notes:
- Public contact email in `README.md` — intended to be public.

Not scanned: <list, or "nothing skipped">.
```
