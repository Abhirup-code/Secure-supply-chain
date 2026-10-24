# Threat Model (STRIDE)

A short threat model for the app and its delivery pipeline. Each threat maps to a control in this repo.

## Application

| Threat (STRIDE) | Example | Control |
|---|---|---|
| Tampering | SQL injection through a short code | Parameterized queries only; test `test_sql_injection_attempt_is_harmless` |
| Elevation / XSS | Storing a `javascript:` or `data:` link that runs in a victim's browser | Scheme allowlist (http, https); parametrized test of dangerous URLs |
| Information disclosure | Guessing other users' short codes | Codes from `secrets.token_urlsafe`; uniqueness test |
| Information disclosure / SSRF-style abuse | Short links pointing at internal hosts or the cloud metadata service, including Unicode look-alikes (`localhost。`, full-width digits) | Block loopback, private, link-local, and reserved IPs plus `localhost`, checked on the IDNA-normalized hostname; parametrized tests; fuzzing |
| Tampering / header injection | Control characters (newline, tab) inside a URL | Rejected at creation; found and verified by fuzzing |
| Denial of service | Malformed JSON, non-object bodies, unparseable hosts or ports causing server errors | Validated and rejected with 400; Atheris fuzzes these inputs on every PR |
| Denial of service | Very large payloads | URL length limit (2,048 characters) |
| Denial of service / spam | Flooding the API with link creation | Per-IP rate limit on `POST /api/links` (default 30/minute) returning 429 with `Retry-After` |
| Information disclosure | Clickjacking, MIME sniffing | CSP `frame-ancestors 'none'`, `X-Frame-Options`, `nosniff` headers |

## Container

| Threat | Control |
|---|---|
| Container escape or privilege escalation | Fixed non-root UID, all capabilities dropped, `no-new-privileges` |
| Attacker writes to the filesystem | Read-only root filesystem; only `/data` is writable |
| Vulnerable OS or Python packages | Trivy (image) and Grype (SBOM) fail the build on fixable CRITICAL/HIGH; accepted risks need a written reason; Dependabot updates the base image |
| Flaws only visible at runtime | OWASP ZAP API scan of the running container; injection, XSS, and path traversal findings fail the build |
| Extra attack surface | Multi-stage build; no compilers or test tools in the runtime image |

## Pipeline (supply chain)

| Threat | Control |
|---|---|
| Compromised third-party action | Actions pinned to full commit SHAs; zizmor and CodeQL (actions) lint workflows |
| Over-privileged workflow token | Default `contents: read`; write scopes only on the job that needs them |
| Leaked secrets in code or history | gitleaks scans full history on every push and PR |
| Vulnerable dependency added in a PR | pip-audit and dependency-review fail the check |
| Tampered or swapped image | Image signed by digest with cosign (keyless OIDC); signed SBOM and SLSA provenance; all verified before the image is trusted |
| Compromised tool download in CI | Tools pinned to a version and SHA-256 checksum (`scripts/install-tools.sh`) |
| Release from unreviewed code | Release tags must point at a commit already on `main` |
| Unreviewed changes reaching main | Branch protection with required checks (repository setting) |

## Deployment (Kubernetes)

| Threat | Control |
|---|---|
| Unsigned or attacker-built image deployed | Kyverno `ImageValidatingPolicy` admits only images signed by this repo's publish workflow (from `main` or a release tag) |
| Image signed, but built somewhere else | Signed SLSA provenance must name this repository |
| Image with no known contents | A signed SBOM attestation is required |
| Tag moved to different content after review | Tags are rewritten to the verified digest at admission; a moved tag points at unsigned content and is denied |
| Public or look-alike image in the app namespace | `ValidatingPolicy` allows only this project's image |
| Over-privileged pod | `ValidatingPolicy` requires non-root, no privilege escalation, dropped capabilities, seccomp, read-only root filesystem, limits; the namespace also enforces the restricted Pod Security Standard |
| Lateral movement from a compromised pod | Default-deny NetworkPolicy (only port 8000 in, nothing out); no service account token |
| Policies that silently stop working | CI proves every rule in a real kind cluster with Kyverno on each pull request, and checks the production policy against every published digest |

## Residual risks (known, accepted for a demo project)

- No authentication on link creation.
- The rate limiter is in memory per worker; a shared store (for example Redis) would be needed across replicas.
- SQLite is fine for a demo but not for multiple replicas.
- Policies cover images from this project only; a real cluster would extend the signature policy to every namespace and registry it runs.
- In the CI cluster test, a temporary key stands in for the keyless GitHub identity (a pull request cannot obtain it). The production policy with the real identity is checked against each published image.
- An SBOM or provenance attestation is itself a signature by the trusted identity, so either one satisfies the signature check; all three are still required.
