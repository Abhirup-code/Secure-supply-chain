# Security Policy

## Reporting a vulnerability

Please do not open a public issue. Use the **Report a vulnerability** button under this
repository's Security tab (private vulnerability reporting).

## Verifying a published image

Every image on `main` is signed with Sigstore keyless signing. To verify one yourself:

```bash
cosign verify ghcr.io/abhirup-code/secure-supply-chain:latest \
  --certificate-identity-regexp "^https://github.com/Abhirup-code/Secure-supply-chain/" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```
