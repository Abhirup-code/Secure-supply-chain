#!/usr/bin/env bash
# Prove, in a real Kubernetes cluster, that the admission policies let the right image in
# and keep everything else out.
#
# Expects: a kind cluster (k8s/kind/kind-config.yaml) and docker, kubectl, helm, kind,
# cosign, syft, and yq on PATH. CI runs this on every pull request.
#
# The production policies trust GHCR images signed keylessly by the publish workflow. A pull
# request cannot get that identity, so this test signs with a temporary key and serves images
# from a local registry (see scripts/render-test-policies.sh). The rules are unchanged.
set -euo pipefail

CLUSTER="${KIND_CLUSTER:-admission}"
KYVERNO_CHART_VERSION="3.9.2" # Kyverno v1.19.2
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
RESULTS="$WORK/results.md"
export COSIGN_PASSWORD="" # temporary test keys only

printf '| Scenario | Expected | Result |\n|---|---|---|\n' > "$RESULTS"

record() { # scenario, expected, outcome
  printf '| %s | %s | %s |\n' "$1" "$2" "$3" >> "$RESULTS"
}

die() {
  echo "FAIL: $*" >&2
  [ -n "${GITHUB_STEP_SUMMARY:-}" ] && cat "$RESULTS" >> "$GITHUB_STEP_SUMMARY"
  exit 1
}

echo "::group::Start a local registry on the kind network"
docker run -d --name kind-registry --network kind -p 127.0.0.1:5000:5000 registry:3 >/dev/null
REGISTRY_IP="$(docker inspect -f '{{.NetworkSettings.Networks.kind.IPAddress}}' kind-registry)"
# A private IP address: Kyverno, cosign, and syft all talk plain HTTP to it without extra flags.
REGISTRY="${REGISTRY_IP}:5000"
REPO="${REGISTRY}/secure-supply-chain"
for node in $(kind get nodes --name "$CLUSTER"); do
  docker exec "$node" mkdir -p "/etc/containerd/certs.d/${REGISTRY}"
  printf '[host."http://%s"]\n  capabilities = ["pull", "resolve"]\n' "$REGISTRY" |
    docker exec -i "$node" cp /dev/stdin "/etc/containerd/certs.d/${REGISTRY}/hosts.toml"
done
for _ in $(seq 1 30); do
  if curl -sf "http://${REGISTRY}/v2/" >/dev/null; then break; fi
  sleep 1
done
echo "registry at ${REGISTRY}"
echo "::endgroup::"

echo "::group::Install Kyverno ${KYVERNO_CHART_VERSION}"
helm repo add kyverno https://kyverno.github.io/kyverno/ >/dev/null
helm install kyverno kyverno/kyverno --namespace kyverno --create-namespace \
  --version "$KYVERNO_CHART_VERSION" \
  --set backgroundController.enabled=false \
  --set cleanupController.enabled=false \
  --set reportsController.enabled=false \
  --wait --timeout 5m
echo "::endgroup::"

echo "::group::Create signing keys and test policies"
(cd "$WORK" && cosign generate-key-pair --output-key-prefix trusted >/dev/null &&
  cosign generate-key-pair --output-key-prefix untrusted >/dev/null)
"$ROOT/scripts/render-test-policies.sh" "$REGISTRY" "$WORK/trusted.pub" "$WORK/policies"
kubectl apply -f "$ROOT/k8s/app/namespace.yaml"
kubectl apply -f "$WORK/policies/"
echo "::endgroup::"

echo "::group::Build, push, sign, and attest test images"
docker build -q -t "localhost:5000/secure-supply-chain:base" "$ROOT" >/dev/null
docker push -q "localhost:5000/secure-supply-chain:base" >/dev/null

# The digest the registry serves for a tag (the same lookup Kyverno does at admission).
registry_digest() { # tag
  curl -sfI \
    -H "Accept: application/vnd.oci.image.index.v1+json" \
    -H "Accept: application/vnd.docker.distribution.manifest.list.v2+json" \
    -H "Accept: application/vnd.oci.image.manifest.v1+json" \
    -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
    "http://localhost:5000/v2/secure-supply-chain/manifests/$1" |
    tr -d '\r' | awk -F': ' 'tolower($1) == "docker-content-digest" {print $2}'
}

# Each variant gets a unique label, so each has its own digest.
push_variant() { # name -> prints digest
  printf 'FROM localhost:5000/secure-supply-chain:base\nLABEL test.variant=%s\n' "$1" |
    docker build -q -t "localhost:5000/secure-supply-chain:$1" - >/dev/null
  docker push -q "localhost:5000/secure-supply-chain:$1" >/dev/null
  local digest
  digest="$(registry_digest "$1")"
  [[ "$digest" == sha256:* ]] || die "no digest for test image $1"
  echo "$digest"
}
sign() { # key digest
  cosign sign --yes --key "$WORK/$1.key" --signing-config "$ROOT/k8s/kind/signing-config-offline.json" \
    --allow-http-registry "${REPO}@$2" >/dev/null
}
attest() { # key type predicate digest
  cosign attest --yes --key "$WORK/$1.key" --signing-config "$ROOT/k8s/kind/signing-config-offline.json" \
    --allow-http-registry --type "$2" --predicate "$3" "${REPO}@$4" >/dev/null
}

GOOD="$(push_variant good)"
SYFT_REGISTRY_INSECURE_USE_HTTP=true syft -q "registry:${REPO}@${GOOD}" -o "spdx-json=$WORK/sbom.spdx.json"
PROVENANCE="$ROOT/k8s/kind/test-provenance.json"
sed 's#Abhirup-code/Secure-supply-chain#someone-else/fork#' "$PROVENANCE" > "$WORK/fork-provenance.json"

sign trusted "$GOOD"
attest trusted spdxjson "$WORK/sbom.spdx.json" "$GOOD"
attest trusted slsaprovenance1 "$PROVENANCE" "$GOOD"

UNSIGNED="$(push_variant unsigned)"

WRONG_KEY="$(push_variant wrong-key)"
sign untrusted "$WRONG_KEY"
attest untrusted spdxjson "$WORK/sbom.spdx.json" "$WRONG_KEY"
attest untrusted slsaprovenance1 "$PROVENANCE" "$WRONG_KEY"

NO_PROVENANCE="$(push_variant no-provenance)"
sign trusted "$NO_PROVENANCE"
attest trusted spdxjson "$WORK/sbom.spdx.json" "$NO_PROVENANCE"

FORK="$(push_variant fork-provenance)"
sign trusted "$FORK"
attest trusted spdxjson "$WORK/sbom.spdx.json" "$FORK"
attest trusted slsaprovenance1 "$WORK/fork-provenance.json" "$FORK"

# A tag that points at the good, signed image (used for the tampering test)
docker tag "localhost:5000/secure-supply-chain:good" "localhost:5000/secure-supply-chain:release"
docker push -q "localhost:5000/secure-supply-chain:release" >/dev/null
[ "$(registry_digest release)" = "$GOOD" ] || die "release tag does not point at the signed image"
echo "::endgroup::"

# Render the real deployment with a different name and image, plus an optional yq edit.
render() { # name image [yq-edit]
  local edit="${3:-.}"
  yq ".metadata.name = \"$1\" | .spec.template.spec.containers[0].image = \"$2\" | ${edit}" \
    "$ROOT/k8s/app/deployment.yaml" > "$WORK/$1.yaml"
  echo "$WORK/$1.yaml"
}

expect_denied() { # scenario name image message [yq-edit]
  local file out
  file="$(render "$2" "$3" "${5:-.}")"
  if out="$(kubectl apply --dry-run=server -f "$file" 2>&1)"; then
    echo "$out"
    record "$1" "Denied" "Admitted"
    die "$1: the cluster admitted it"
  fi
  echo "$out"
  if [[ "$out" != *"$4"* ]]; then
    record "$1" "Denied" "Denied for another reason"
    die "$1: denied, but not with \"$4\""
  fi
  record "$1" "Denied" "Denied: $4"
  echo "PASS: $1"
}

echo "::group::Wait for the policies to take effect"
# Policies take a moment to reach the webhook, so retry until an unsigned image is refused.
for i in $(seq 1 30); do
  if ! kubectl apply --dry-run=server -f "$(render probe "${REPO}@${UNSIGNED}")" >/dev/null 2>&1; then
    echo "policies active after ${i} attempt(s)"
    break
  fi
  [ "$i" = 30 ] && die "policies never took effect"
  sleep 5
done
echo "::endgroup::"

echo "::group::1. Signed image with SBOM and provenance is admitted and runs"
kubectl apply -f "$(render links "${REPO}:release")"
kubectl -n links rollout status deploy/links --timeout=180s
IMAGE_IN_CLUSTER="$(kubectl -n links get deploy links -o jsonpath='{.spec.template.spec.containers[0].image}')"
echo "image as admitted: ${IMAGE_IN_CLUSTER}"
[[ "$IMAGE_IN_CLUSTER" == *"@${GOOD}" ]] || die "tag was not pinned to the signed digest"
kubectl -n links port-forward deploy/links 18080:8000 >/dev/null 2>&1 &
PF_PID=$!
for _ in $(seq 1 20); do
  if curl -sf http://127.0.0.1:18080/health >/dev/null; then break; fi
  sleep 1
done
curl -sf http://127.0.0.1:18080/health || die "app is not healthy"
echo
kill "$PF_PID"
record "Signed image with SBOM and provenance" "Admitted" "Admitted, pinned to signed digest, healthy"
echo "PASS: signed image admitted"
echo "::endgroup::"

echo "::group::2-8. Everything else is refused"
expect_denied "Unsigned image" unsigned "${REPO}@${UNSIGNED}" \
  "Image is not signed by this repository's publish workflow"
expect_denied "Signed with an untrusted key" wrong-key "${REPO}@${WRONG_KEY}" \
  "Image is not signed by this repository's publish workflow"
expect_denied "Signed, but no build provenance" no-provenance "${REPO}@${NO_PROVENANCE}" \
  "Image has no signed build provenance attestation"
expect_denied "Provenance from another repository" fork "${REPO}@${FORK}" \
  "Build provenance does not name this repository"

# Tampering: move the release tag to different, unsigned content.
docker tag "localhost:5000/secure-supply-chain:unsigned" "localhost:5000/secure-supply-chain:release"
docker push -q "localhost:5000/secure-supply-chain:release" >/dev/null
[ "$(registry_digest release)" = "$UNSIGNED" ] || die "release tag was not moved"
expect_denied "Release tag moved to unsigned content" tampered "${REPO}:release" \
  "Image is not signed by this repository's publish workflow"

expect_denied "Public image (nginx)" public-image "docker.io/library/nginx:1.29" \
  "Images in the links namespace must come from"
expect_denied "Signed image, but privileged" privileged "${REPO}@${GOOD}" \
  "Containers must not be privileged" \
  '.spec.template.spec.containers[0].securityContext.privileged = true | .spec.template.spec.containers[0].securityContext.allowPrivilegeEscalation = true'
echo "::endgroup::"

# The running deployment is still the signed digest, even though its tag was moved.
STILL_RUNNING="$(kubectl -n links get pods -l app.kubernetes.io/name=links -o jsonpath='{.items[0].spec.containers[0].image}')"
[[ "$STILL_RUNNING" == *"@${GOOD}" ]] || die "running pod is no longer the signed digest"
record "Running app after the tag was moved" "Still the signed digest" "Still the signed digest"

echo
cat "$RESULTS"
[ -n "${GITHUB_STEP_SUMMARY:-}" ] && { echo "## Admission control tests"; cat "$RESULTS"; } >> "$GITHUB_STEP_SUMMARY"
echo "All admission tests passed."
