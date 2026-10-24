# Changelog

All notable changes to this project are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.2.0] - 2026-10-24

### Security
- Creating and deleting links now requires an API key. Only SHA-256 hashes of the
  keys are configured, keys are compared in constant time, failed attempts count
  toward the rate limit, and writes are refused when no keys are configured.

## [1.1.0] - 2026-10-23

### Security
- Fixed an internal-address blocklist bypass: Unicode look-alike hostnames such as
  `localhost。`, full-width `ｌｏｃａｌｈｏｓｔ`, and `169.254.169.254。` were accepted.
  Hostnames are now checked after IDNA normalization. Found by fuzzing.
- URLs containing control characters (newline, tab) are rejected. They broke the
  redirect for stored links.

### Fixed
- A JSON body that is not an object (for example `1` or `[]`) caused a server error.
- Unparseable hostnames and ports caused a server error or an unfollowable link.

### Added
- Atheris coverage-guided fuzzing of the link API, run for 5 minutes on every pull request.

### Changed
- License changed from MIT to Apache 2.0.

## [1.0.0] - 2026-10-23

### Added
- Kyverno admission policies: only images signed by this repository's publish workflow,
  with a signed SBOM and SLSA provenance, may run; hardened pods only; only the
  project's image in the app namespace.
- Admission tests in a real kind cluster on every pull request.
- Signed SPDX SBOM and SLSA build provenance for every published image, verified in CI.
- Grype SBOM vulnerability gate and an OWASP ZAP API scan of the running container.
- Hardened Kubernetes manifests checked with kube-linter.
- Release workflow that publishes signed images and a GitHub Release from version tags.

[Unreleased]: https://github.com/Abhirup-code/Secure-supply-chain/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/Abhirup-code/Secure-supply-chain/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/Abhirup-code/Secure-supply-chain/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/Abhirup-code/Secure-supply-chain/releases/tag/v1.0.0
