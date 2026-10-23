#!/usr/bin/env bash
# Make a test copy of the production policies for the throwaway CI cluster.
#
# The production policies trust images from GHCR signed keylessly by the publish workflow.
# A pull request cannot get that identity, so the test copy trusts a temporary key and a
# local registry instead. Every rule and check stays exactly the same; only who is trusted
# and where images live change.
#
# Usage: scripts/render-test-policies.sh <registry host:port> <public key file> <output dir>
set -euo pipefail

registry="$1"
public_key_file="$2"
out_dir="$3"
src_dir="$(cd "$(dirname "$0")/../k8s/policies" && pwd)"

mkdir -p "$out_dir"
for policy in require-signed-images restrict-image-registries require-hardened-pods; do
  sed "s#ghcr\.io/abhirup-code/secure-supply-chain#${registry}/secure-supply-chain#g" \
    "$src_dir/${policy}.yaml" > "$out_dir/${policy}.yaml"
done

# Swap the keyless GitHub identity for the temporary public key. The test key signs
# without a transparency log, so the log checks are skipped for this copy only.
PUBLIC_KEY="$(cat "$public_key_file")" yq -i '
  .spec.attestors[0].cosign = {
    "key": {"data": strenv(PUBLIC_KEY)},
    "ctlog": {"insecureIgnoreTlog": true, "insecureIgnoreSCT": true}
  }' "$out_dir/require-signed-images.yaml"

echo "test policies written to $out_dir (registry $registry)"
