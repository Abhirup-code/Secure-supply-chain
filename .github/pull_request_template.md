## What does this change?

<!-- One or two sentences. -->

## Why?

<!-- The problem or risk this addresses. -->

## Security checklist

- [ ] No secrets, tokens, or credentials in the diff
- [ ] New or changed dependencies are pinned with hashes (`uv pip compile --generate-hashes`)
- [ ] New input is validated and covered by tests
- [ ] Threat model updated if this changes the attack surface
- [ ] Kubernetes manifests or policies changed? Policy tests in `k8s/policies/tests` updated
- [ ] CI, Security, and CodeQL checks pass
