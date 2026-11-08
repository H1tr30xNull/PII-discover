# Detection Patterns

Starting points — regexes find candidates; context decides findings.

## Credentials & secrets

| Type | Pattern / signal | Notes |
|---|---|---|
| AWS access key ID | `(AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}` | `AKIAIOSFODNN7EXAMPLE` is AWS's doc example |
| AWS secret key | 40-char base64 near `aws_secret_access_key` | |
| GCP service account | JSON with `"type": "service_account"` + `"private_key"` | Critical |
| Google API key | `AIza[0-9A-Za-z_\-]{35}` | |
| Azure | `AccountKey=`, `DefaultEndpointsProtocol=`, client secrets near `tenant_id` | |
| GitHub token | `gh[pousr]_[A-Za-z0-9]{36,}`, `github_pat_[A-Za-z0-9_]{80,}` | |
| GitLab token | `glpat-[A-Za-z0-9_\-]{20}` | |
| Slack | `xox[baprs]-[A-Za-z0-9-]{10,}`, `hooks.slack.com/services/…` | webhook = post as you |
| Discord webhook | `discord(app)?.com/api/webhooks/\d+/…` | |
| Stripe | `sk_live_[0-9a-zA-Z]{24,}`, `rk_live_…` | `sk_test_` = Low/Medium |
| OpenAI / Anthropic | `sk-[A-Za-z0-9_\-]{20,}`, `sk-ant-[A-Za-z0-9_\-]{20,}` | |
| Twilio / SendGrid | `SK[0-9a-f]{32}`, `SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}` | |
| JWT | `eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+` | decode header/payload (no verification) to see issuer/expiry |
| Private key | `-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----` | Critical |
| DB / broker URL | `(postgres|mysql|mongodb(\+srv)?|redis|amqp)://user:pass@host` | |
| Generic assignment | `(password|passwd|secret|token|api_key|apikey|client_secret)\s*[:=]\s*['"]?[^\s'"]{8,}` | high noise — check entropy & context |
| Package tokens | `//registry.npmjs.org/:_authToken=`, `.pypirc` `password =` | |
| Kubeconfig | `client-key-data:`, `token:` under `users:` | |

## PII

| Type | Pattern / signal |
|---|---|
| Email | `[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}` — ignore `example.com/org`, `noreply`, `users.noreply.github.com`, package author fields of public libs |
| Phone | `\+?\d[\d\s\-().]{8,}\d` — VN: `(\+84|0)(3|5|7|8|9)\d{8}`; US fake range `555-01xx` |
| National ID | VN CCCD 12 digits / CMND 9 digits; US SSN `\d{3}-\d{2}-\d{4}`; passport `[A-Z]\d{7,8}` near "passport" |
| Payment card | 13–19 digits passing Luhn; ignore test cards (4242 4242 4242 4242) |
| IBAN | `[A-Z]{2}\d{2}[A-Z0-9]{11,30}` |
| Address / DOB | Free text — look in CSV headers (`address`, `dob`, `birth`), forms, fixtures |
| Names | Only matters when combined with other data (name + phone, name + ID) |

## Internal business info

- Internal hostnames: `*.internal`, `*.corp`, `*.local`, `*.lan`, `intranet.`, company-specific subdomains
- Private IPs: `10.x`, `172.16–31.x`, `192.168.x` (Low alone, Higher with creds/ports)
- Ticket links: `jira.`, `atlassian.net/browse/`, `linear.app/`, internal Confluence
- Files named like `incident`, `postmortem`, `architecture`, `diagram`, `roadmap`, `pricing`, `confidential`

## Where secrets hide

- Git history (deleted files, earlier versions), stashes, other branches, tags
- Commit metadata: author/committer email
- Jupyter notebook **outputs** and execution logs
- `.env.example` that someone filled with real values
- CI logs, HAR files, crash dumps, `*.log`
- Docker images / `docker-compose.yml` env sections, Helm `values.yaml`
- Archives (zip/tar) and backups (`*.bak`, `*~`, `*.orig`)
- Editor/agent state: `.vscode/settings.json`, `.idea/`, `.claude/`, `.cursor/`, shell history
- Screenshots and PDFs (can't regex — check filenames and open suspicious ones)
