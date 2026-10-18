# Threat Model (STRIDE)

A short threat model for the app and its delivery pipeline. Each threat maps to a control in this repo.

## Application

| Threat (STRIDE) | Example | Control |
|---|---|---|
| Tampering | SQL injection through a short code | Parameterized queries only; test `test_sql_injection_attempt_is_harmless` |
| Elevation / XSS | Storing a `javascript:` or `data:` link that runs in a victim's browser | Scheme allowlist (http, https); parametrized test of dangerous URLs |
| Information disclosure | Guessing other users' short codes | Codes from `secrets.token_urlsafe`; uniqueness test |
| Information disclosure / SSRF-style abuse | Short links pointing at internal hosts or the cloud metadata service | Block loopback, private, link-local, and reserved IPs plus `localhost`; parametrized tests |
| Denial of service | Very large payloads | URL length limit (2,048 characters) |
| Information disclosure | Clickjacking, MIME sniffing | CSP `frame-ancestors 'none'`, `X-Frame-Options`, `nosniff` headers |

## Container

| Threat | Control |
|---|---|
| Container escape or privilege escalation | Non-root user, all capabilities dropped, `no-new-privileges` |
| Attacker writes to the filesystem | Read-only root filesystem; only `/data` is writable |
| Vulnerable OS or Python packages | Trivy image scan fails the build on fixable CRITICAL/HIGH; Dependabot updates the base image |
| Extra attack surface | Multi-stage build; no compilers or test tools in the runtime image |

## Pipeline (supply chain)

| Threat | Control |
|---|---|
| Compromised third-party action | Actions pinned to full commit SHAs; zizmor and CodeQL (actions) lint workflows |
| Over-privileged workflow token | Default `contents: read`; write scopes only on the job that needs them |
| Leaked secrets in code or history | gitleaks scans full history on every push and PR |
| Vulnerable dependency added in a PR | pip-audit and dependency-review fail the check |
| Tampered or swapped image | Image signed by digest with cosign (keyless OIDC) and verified in the same job; SBOM and provenance attached |
| Unreviewed changes reaching main | Branch protection with required checks (repository setting) |

## Residual risks (known, accepted for a demo project)

- No authentication or rate limiting on link creation.
- SQLite is fine for a demo but not for multiple replicas.
- The base image is pinned by tag, not digest; Dependabot keeps it current.
