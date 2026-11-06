#!/usr/bin/env bash
# E2E test on a throwaway kind cluster.
#
# The cluster kubeconfig is generated under .e2e/ at the repo root and
# KUBECONFIG is pointed there for every command: user kubeconfigs in ~/.kube
# are never read or written.
set -euo pipefail
cd "$(dirname "$0")/.."

E2E_DIR=".e2e"
KUBECONFIG_FILE="$PWD/$E2E_DIR/kubeconfig"
CLUSTER_NAME="hcc-e2e"
IMAGE="home-cloud-controller-manager:dev"

export KUBECONFIG="$KUBECONFIG_FILE"
mkdir -p "$E2E_DIR"

cleanup() {
  kind delete cluster --name "$CLUSTER_NAME" --kubeconfig "$KUBECONFIG_FILE" || true
}
trap cleanup EXIT

echo "==> creating throwaway kind cluster $CLUSTER_NAME"
kind create cluster --name "$CLUSTER_NAME" --kubeconfig "$KUBECONFIG_FILE" --wait 120s

echo "==> building controller image"
docker build -t "$IMAGE" .
kind load docker-image "$IMAGE" --name "$CLUSTER_NAME"

echo "==> deploying controller"
kustomize build deploy/overlays/kind | kubectl apply -f -
kubectl -n home-cloud wait --for=condition=Available deployment/home-cloud-controller-manager --timeout=180s

NODE=$(kubectl get nodes -o jsonpath='{.items[0].metadata.name}')
echo "==> using node $NODE"

submit_csr() { # $1 = name, $2 = CN
  local name="$1" cn="$2"
  openssl req -new -newkey rsa:2048 -nodes \
    -keyout "$E2E_DIR/$name.key" -out "$E2E_DIR/$name.csr" \
    -subj "/CN=$cn/O=system:nodes" 2>/dev/null
  local req_b64
  req_b64=$(base64 -w0 "$E2E_DIR/$name.csr")
  kubectl apply -f - <<EOF
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: $name
spec:
  request: $req_b64
  signerName: kubernetes.io/kube-apiserver-client-kubelet
  usages: ["digital signature", "key encipherment", "client auth"]
EOF
}

echo "==> positive case: CSR for existing node $NODE must be Approved"
submit_csr "e2e-$NODE" "system:node:$NODE"
kubectl wait --for=jsonpath='{.status.conditions[?(@.type=="Approved")].type}' \
  csr "e2e-$NODE" --timeout=60s
echo "OK: CSR for existing node approved"

echo "==> negative case: CSR for unknown node must NOT be approved"
submit_csr "e2e-ghost-node" "system:node:ghost-node"
sleep 15
if kubectl get csr e2e-ghost-node -o jsonpath='{.status.conditions}' | grep -q Approved; then
  echo "FAIL: CSR for unknown node was approved" >&2
  exit 1
fi
echo "OK: CSR for unknown node left untouched"

echo "==> negative case: forbidden signerName must NOT be approved"
submit_csr "e2e-bad-signer" "system:node:$NODE"
kubectl patch csr e2e-bad-signer --type=merge \
  -p '{"spec":{"signerName":"kubernetes.io/kube-apiserver-client"}}' || true
sleep 15
if kubectl get csr e2e-bad-signer -o jsonpath='{.status.conditions}' | grep -q Approved; then
  echo "FAIL: CSR with forbidden signerName was approved" >&2
  exit 1
fi
echo "OK: CSR with forbidden signerName left untouched"

echo "ALL E2E CHECKS PASSED"
