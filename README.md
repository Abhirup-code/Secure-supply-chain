# secure-ship

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
| Dependencies | All pinned; pip-audit, dependency review, Dependabot |
| Code | ruff security rules, bandit, CodeQL security-extended |
| Container | Multi-stage build, non-root user, read-only filesystem, all capabilities dropped, `no-new-privileges`, health check |
| Image integrity | SBOM and SLSA provenance attached; image signed by digest with cosign and verified |
| App | http/https allowlist (blocks `javascript:` links), parameterized SQL, unguessable codes, CSP and security headers |

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the STRIDE threat model and [SECURITY.md](SECURITY.md) for how to verify an image.

## Run locally

```bash
pip install -r requirements-dev.txt
pytest --cov=app            # 15 tests, 96% coverage
ruff check . && bandit -c pyproject.toml -r app
```

```bash
docker compose up --build   # http://localhost:8000
curl -X POST -H 'Content-Type: application/json' -d '{"url":"https://example.com"}' localhost:8000/api/links
```

## API

| Method | Path | Description |
|---|---|---|
| POST | `/api/links` | Create a short link from `{"url": "https://..."}` |
| GET | `/{code}` | Redirect to the original URL (302) and count the hit |
| GET | `/api/links/{code}` | Link details and hit count |
| GET | `/health` | Health check |

## Recommended repository settings

1. Settings > Code security: enable Dependabot alerts, Secret scanning, Push protection, Private vulnerability reporting.
2. Settings > Rules > Rulesets: protect `main` (require a pull request and passing CI, Security, and CodeQL checks).
3. Settings > Actions > General: Workflow permissions = "Read repository contents".

Built with AI assistance; I reviewed, ran, and verified the code and pipeline.
