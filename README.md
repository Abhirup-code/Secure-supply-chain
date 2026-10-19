# Secure-supply-chain

[![CI](https://github.com/Abhirup-code/Secure-supply-chain/actions/workflows/ci.yml/badge.svg)](https://github.com/Abhirup-code/Secure-supply-chain/actions/workflows/ci.yml)
[![Security](https://github.com/Abhirup-code/Secure-supply-chain/actions/workflows/security.yml/badge.svg)](https://github.com/Abhirup-code/Secure-supply-chain/actions/workflows/security.yml)
[![CodeQL](https://github.com/Abhirup-code/Secure-supply-chain/actions/workflows/codeql.yml/badge.svg)](https://github.com/Abhirup-code/Secure-supply-chain/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/Abhirup-code/Secure-supply-chain/badge)](https://scorecard.dev/viewer/?uri=github.com/Abhirup-code/Secure-supply-chain)

A small link-shortener API delivered through a **hardened DevSecOps pipeline**: every change is linted, tested, scanned for secrets, vulnerable dependencies, code flaws, and container issues, then published as a **signed image with an SBOM and build provenance**.

The app is intentionally small. The point of the project is the pipeline and the security controls around it.

## Pipeline

```
push / PR
  ├─ CI ─────────── lint (ruff) → SAST (bandit) → tests + 90% coverage gate
  │                  → build → hardened smoke test → Trivy config scan → Trivy image scan
  │                  → [main only] push to GHCR + SBOM + provenance → cosign sign → cosign verify
  ├─ Security ───── gitleaks (full history) · pip-audit · dependency review (PRs) · zizmor
  ├─ CodeQL ─────── Python + GitHub Actions, security-extended queries
  └─ Scorecard ──── OpenSSF Scorecard supply-chain checks
Dependabot ──────── weekly updates for actions, pip, and the Docker base image
```

## Security controls

| Area | Control |
|---|---|
| Workflow token | Default `contents: read`; `packages: write` and `id-token: write` only in the publish job on `main` |
| Third-party actions | Pinned to full commit SHAs; `persist-credentials: false` on every checkout |
| Secrets | gitleaks on every push and PR; no long-lived keys (keyless signing via GitHub OIDC) |
| Dependencies | All pinned with SHA-256 hashes (`--require-hashes`) in CI and the image; pip-audit, dependency review, Dependabot |
| Code | ruff security rules, bandit, CodeQL security-extended |
| Container | Multi-stage build, non-root user, read-only filesystem, all capabilities dropped, `no-new-privileges`, health check |
| Image integrity | SBOM and SLSA provenance attached; image signed by digest with cosign and verified |
| App | http/https allowlist (blocks `javascript:` links), blocks internal and private addresses (localhost, 10.x, 192.168.x, cloud metadata), parameterized SQL, unguessable codes, per-IP rate limiting (429 + `Retry-After`), CSP and security headers |

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the STRIDE threat model and [SECURITY.md](SECURITY.md) for how to verify an image.

## Run locally

```bash
pip install --require-hashes -r requirements-dev.txt
pytest --cov=app            # 33 tests
ruff check . && bandit -c pyproject.toml -r app
```

```bash
docker compose up --build   # http://localhost:8000
curl -X POST -H 'Content-Type: application/json' -d '{"url":"https://example.com"}' localhost:8000/api/links
```

## API

| Method | Path | Description |
|---|---|---|
| POST | `/api/links` | Create a short link from `{"url": "https://..."}` (rate limited, default 30/minute per IP via `RATE_LIMIT_PER_MINUTE`) |
| GET | `/{code}` | Redirect to the original URL (302) and count the hit |
| GET | `/api/links/{code}` | Link details and hit count |
| DELETE | `/api/links/{code}` | Delete a short link (204, or 404 if unknown) |
| GET | `/health` | Health check |

## Updating dependencies

Dependencies are locked with hashes. Edit the `.in` file, then regenerate the lock file:

```bash
pip install uv
uv pip compile requirements.in --universal --python-version 3.14 --generate-hashes -o requirements.txt
uv pip compile requirements-dev.in --universal --python-version 3.14 --generate-hashes -o requirements-dev.txt
```

## Recommended repository settings

1. Settings > Code security: enable Dependabot alerts, Secret scanning, Push protection, Private vulnerability reporting.
2. Settings > Rules > Rulesets: protect `main` (require a pull request and passing CI, Security, and CodeQL checks).
3. Settings > Actions > General: Workflow permissions = "Read repository contents".
   
## Test
I tested my own pipeline by committing a fake AWS key. The secret scanner and the SAST lint both caught it, and the build stopped before an image was ever created.

<img width="1167" height="701" alt="Screenshot 2026-10-16 at 6 52 41 PM" src="https://github.com/user-attachments/assets/31d90ac7-ffb1-49e8-ba9d-291559d86b56" />

<img width="1116" height="514" alt="Screenshot 2026-10-16 at 5 59 31 PM" src="https://github.com/user-attachments/assets/647f3d2b-720d-4231-8c34-6dda31e5fac0" />

## Test 
# with rules

<img width="802" height="466" alt="Screenshot 2026-10-19 at 1 33 37 PM" src="https://github.com/user-attachments/assets/32b1b43e-3ec6-44be-8504-07fcef555d07" />


