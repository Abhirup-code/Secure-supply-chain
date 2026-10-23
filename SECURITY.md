# Security Policy

## Reporting a vulnerability

Please do not open a public issue. Use the **Report a vulnerability** button under this
repository's Security tab (private vulnerability reporting).

## Verifying a published image

Every image from `main` and every release is signed with Sigstore keyless signing by this
repository's publish workflow, with a signed SPDX SBOM and SLSA build provenance attached.

```bash
IMAGE=ghcr.io/abhirup-code/secure-supply-chain:latest
SIGNER='^https://github\.com/Abhirup-code/Secure-supply-chain/\.github/workflows/publish\.yml@refs/(heads/main|tags/v[0-9]+\.[0-9]+\.[0-9]+)$'
ISSUER=https://token.actions.githubusercontent.com

# Signature
cosign verify "$IMAGE" --certificate-identity-regexp "$SIGNER" --certificate-oidc-issuer "$ISSUER"

# Signed SBOM
cosign verify-attestation --type spdxjson "$IMAGE" \
  --certificate-identity-regexp "$SIGNER" --certificate-oidc-issuer "$ISSUER"

# Build provenance (GitHub artifact attestation)
gh attestation verify "oci://$IMAGE" --repo Abhirup-code/Secure-supply-chain
```

In Kubernetes, the Kyverno policy in [k8s/policies/require-signed-images.yaml](k8s/policies/require-signed-images.yaml)
runs these same checks before a pod is allowed to start.
