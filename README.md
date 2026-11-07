# home-cloud-controller-manager

A mini Kubernetes controller written in Rust that watches
`CertificateSigningRequest` objects (`certificates.k8s.io/v1`) and
**automatically approves the ones whose node already exists** in the cluster.

Approving a CSR does not sign anything by itself: the controller only adds the
`Approved` condition on the `certificatesigningrequests/approval` subresource.
The official `kube-controller-manager` signer then issues the certificate.

See [docs/architecture.md](docs/architecture.md) for the architecture and
security model.

## Requirements

- Rust (stable toolchain; the crate uses edition 2024)
- A Kubernetes cluster to run against (in-cluster, or via `--kubeconfig`)
- For e2e tests only: `kind` and `kubectl` (a throwaway cluster is created
  under `.e2e/`; user kubeconfigs in `~/.kube` are never touched)

## Build

```sh
cargo build --release --all-targets
```

## Run

In-cluster (uses the pod ServiceAccount):

```sh
home-cloud-controller-manager
```

Out-of-cluster (points at a kubeconfig file you own):

```sh
home-cloud-controller-manager --kubeconfig /path/to/kubeconfig --context my-cluster
```

If `--kubeconfig` is not given, only the in-cluster config is used: the
controller **never** reads `~/.kube/config` or any default `KUBECONFIG` path.

## Deploy (kustomize)

In-cluster is the default mode: no kubeconfig is mounted, the pod uses its
ServiceAccount token automatically. To use a mounted kubeconfig instead,
mount it read-only and set `KUBECONFIG` (or pass `--kubeconfig`) pointing at
the mounted file — see the comment in `deploy/base/deployment.yaml`.

```sh
docker build -t home-cloud-controller-manager:dev .
kustomize build deploy/overlays/kind | kubectl apply -f -
```

On kind, load the image into the cluster first:

```sh
kind load docker-image home-cloud-controller-manager:dev --name <cluster-name>
```

Stack layout: `deploy/base` (Namespace `home-cloud` with PodSecurity
`restricted`, dedicated ServiceAccount, minimal ClusterRole, hardened
single-replica Deployment; no NetworkPolicy in base) with netpol components
under `deploy/base/components/` — `netpol-classic` (vanilla NetworkPolicy,
egress TCP/443+6443 to the API server + kube-dns 53) and `netpol-cilium`
(CiliumNetworkPolicy with the reserved `kube-apiserver` entity, which also
matches hostNetwork apiservers without pod labels). Overlays select one:
`deploy/overlays/netpol-classic`, `deploy/overlays/netpol-cilium`, and
`deploy/overlays/kind` (image retag for local e2e, classic netpol). The image
is a static musl binary in a distroless image (`Dockerfile`).

The workflow `.github/workflows/docker.yml` builds the image for `linux/amd64`
and `linux/arm64` and pushes it to the project's own GHCR repo
(`ghcr.io/nerzhul/home-cloud-controller`): tag `latest` on pushes to `main`,
semver tags on `v*` tags, plus the short SHA. It authenticates with the
built-in `GITHUB_TOKEN` (`packages: write`). Pull requests build both
arches but do not push.

The Deployment wires kubelet `livenessProbe` (`/healthz`) and
`readinessProbe` (`/readyz`) on the `health` port 8080 (served by
`src/health.rs`); readiness stays 503 until the node cache and the initial
CSR list have succeeded. The NetworkPolicy allows ingress on the health port
only (kubelet probes come from the node, not a pod; in the Cilium flavor this
is the `host`/`remote-node` entities).

## What it does

- Watches all `CertificateSigningRequest` objects; CSRs that already carry an
  `Approved`/`Denied` condition are never touched again.
- For pending CSRs whose `signerName` matches `--signer-name`, decodes the
  PKCS#10 in `spec.request` and validates: subject `CN=system:node:<node>` +
  `O=system:nodes`, exact usage set (`digital signature`, `key encipherment`,
  `client auth`), key strength (RSA >= 2048 bits, ECDSA P-256/P-384, Ed25519),
  EKU limited to `clientAuth`, SANs matching the node addresses, and the node
  itself (exists, not terminating, not blocked by annotation, carries the
  required label when `--node-label` is set).
- Approves valid CSRs through the `certificatesigningrequests/approval`
  subresource (merge patch, retry on 409 conflict). Signing is left to the
  cluster's official signer.
- Rate limits approvals (`--max-approvals-per-minute`, plus one approval per
  node per hour) and audits every decision: structured JSON log + Kubernetes
  Event on approved CSRs (visible with `kubectl describe csr`).
- Invalid CSRs are **never touched**: no `Denied` condition is ever set, and
  by default no Event either — they are only logged. `--emit-rejection-events`
  opts into emitting a Warning Event on invalid CSRs.

## Configuration

All options are CLI flags with an environment-variable equivalent.

| Flag | Env var | Default | Description |
|---|---|---|---|
| `--kubeconfig <path>` | `KUBECONFIG` | in-cluster | Path to a kubeconfig file |
| `--context <name>` | `KUBE_CONTEXT` | current context | Kubeconfig context to use |
| `--signer-name <name>` | `SIGNER_NAME` | `kubernetes.io/kube-apiserver-client-kubelet` | Only approve CSRs with this signerName |
| `--node-label <key=value>` | `NODE_LABEL` | (all nodes) | If set, only approve CSRs for nodes carrying this label |
| `--max-approvals-per-minute <n>` | `MAX_APPROVALS_PER_MINUTE` | `10` | Global approval rate limit |
| `--max-csr-request-bytes <n>` | `MAX_CSR_REQUEST_BYTES` | `65536` | Max accepted size of the decoded `spec.request` |
| `--health-addr <addr>` | `HEALTH_ADDR` | `0.0.0.0:8080` | Health server address; serves `/healthz` (liveness) and `/readyz` (readiness) |
| `--emit-rejection-events` | `EMIT_REJECTION_EVENTS` | `false` | Emit a Warning Event on CSRs that fail validation (default: log only, CSR never touched) |

## Tests

```sh
cargo fmt --all -- --check
cargo build --all-targets
cargo clippy --all-targets -- -D warnings
cargo test --all
cargo audit
```

E2E (creates and destroys a throwaway kind cluster; kubeconfig under `.e2e/`):

```sh
./scripts/e2e-kind.sh
```

## CI

`.github/workflows/ci.yml` runs on every push/PR: `cargo fmt --check`,
`cargo build --all-targets`, `cargo clippy -D warnings`, `cargo test`,
`cargo audit`.

## Repository rules

See [AGENTS.md](AGENTS.md). Highlights: all repo content is in English;
run the test suite and linters before considering any task done; never commit
or push without an explicit user instruction; keep documentation in sync with
build/runtime configuration changes.
