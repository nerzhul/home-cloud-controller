# Architecture — home-cloud-controller-manager

Mini Kubernetes controller (Rust) that watches `CertificateSigningRequest`
(`certificates.k8s.io/v1`) and **approves the ones whose node already exists**
in the cluster.

The controller never signs certificates itself: approving a CSR only adds the
`Approved` condition on the `certificatesigningrequests/approval` subresource;
the official signer of `kube-controller-manager` performs the signature.

## Scope

In scope: watch CSRs, validate strictly, approve kubelet client CSRs for
existing nodes via the `approval` subresource. Out of scope (v1): signing
ourselves, `kubelet-serving` CSRs (manual approval), any custom API/UI.

## Crate layout

The crate lives at the repository root (package `home-cloud-controller-manager`).

```
src/
├── main.rs        # bootstrap: config parsing, tracing init, controller launch
├── config.rs      # CLI/env configuration (clap)
├── controller.rs  # main loop: CSR watcher + reconciliation, retry/backoff
├── csr.rs         # CSR status/conditions, approval patch construction
├── health.rs      # HTTP probes: /healthz (liveness), /readyz (readiness)
├── validate.rs    # validation policy (pure, unit-testable functions)
├── security.rs    # hardening: usages, signerName, key size, SANs, rate limit
├── nodes.rs       # node cache (informer) for O(1) lookup by name
├── kube.rs        # kube client, retry-on-conflict, approval subresource patch
└── audit.rs       # decision audit: structured logs + Kubernetes Events
```

## Data flow

```
watch CSR ──► already Approved/Denied? ──yes──► ignore
                   │ no
                   ▼
       signerName allowed? ──no──► ignore (+ log)
                   │ yes
                   ▼
   parse spec.request (PKCS#10) ── invalid ──► log (+ Warning Event only if --emit-rejection-events)
                   │ ok
                   ▼
   extract CN / O / SANs / usages / public key
                   │
                   ▼
   validate.rs: all rules pass? ──no──► log (+ Warning Event only if --emit-rejection-events)
                   │ yes
                   ▼
   node <node> exists in cache? ──no──► ignore (node may join later)
                   │ yes
                   ▼
   rate limit ok? ──no──► requeue with delay
                   │ yes
                   ▼
   PATCH certificatesigningrequests/approval (Approved, retry on conflict)
                   │
                   ▼
   log + Event "Approved" on the CSR
```

### Watch resilience (no idle controller after a connection loss)
- `kube::runtime::watcher` restarts the watch **by itself**: after a transient
  error it re-watches from the last known `resourceVersion` (the state machine
  in kube-runtime keeps it and resumes with `WatchPhase::Resumed`); on
  `410 Gone` it falls back to `State::default()` = full re-list
  (`Init` → `InitApply`… → `InitDone`). Watch HTTP calls have a server-side
  timeout (~5 min), so no stream can hang forever.
- Both streams (CSR + nodes) are wrapped in `.default_backoff()`
  (`WatchStreamExt`, client-go conventions): after an error we wait with an
  exponential backoff before polling again, instead of hot-looping.
- Our consume loops (`drive()` in `controller.rs`, the task in `nodes.rs`) use
  `while let Some(...)` + `match`, **never** `try_*` combinators (which
  terminate eagerly on the first `Err`): an `Err` is logged and the loop keeps
  polling, which is exactly what lets kube-runtime recover the stream. This is
  covered by the `drive_continues_after_watch_errors` test.
- On `Event::Init` the node cache is cleared and rebuilt from `InitApply`
  events, so nodes deleted during an outage do not linger.
- If the process dies, the Deployment restarts the pod; at boot the initial
  node list completes **before** the CSR list and before readiness flips to
  200, so no decision is ever made with an empty cache.

## Security model

An attacker able to create CSRs must **not** be able to obtain a valid
certificate for an existing node. Approving a CSR authorizes the API server to
issue a certificate, so the request content is validated strictly.

### Detailed rules
- **signerName**: only `--signer-name` (default
  `kubernetes.io/kube-apiserver-client-kubelet`); never
  `kubernetes.io/kube-apiserver-client` (admin cert), never `kubelet-serving`.
- **Subject**: `CN=system:node:<nodeName>` **and** `O=system:nodes`, exactly.
  `<nodeName>` must match an existing Node object.
- **Usages**: exactly `{digital signature, key encipherment, client auth}`.
- **EKU**: if present in the PKCS#10, must be exactly `clientAuth`.
- **SANs**: if present, must match the node's addresses exactly (a rogue SAN
  would let an attacker present the certificate from their own server).
- **Public key**: RSA >= 2048 bits, ECDSA P-256/P-384, or Ed25519.
- **Size**: max `--max-csr-request-bytes` (default 64 KiB decoded, anti-DoS).
- **Node checks**: exists, not terminating (`deletionTimestamp`), not
  annotated `home-cloud.io/csr-approval: blocked`, carries `--node-label` if
  set.
- **Rate limiting**: global sliding window `--max-approvals-per-minute`
  (default 10) + at most one approval per node per hour.
- **Rejections are never acted upon**: no `Denied` condition is ever set (it
  would block other approvers); a Warning Event is emitted only with
  `--emit-rejection-events` (default: log only).

### Threat table
| Threat | Mitigation |
|---|---|
| CSR for an existing node, created by an attacker | subject/usages/SANs/key validation + rate limit + audit |
| CSR with an admin signerName | signerName whitelist |
| CSR with a rogue SAN | SANs must match node addresses |
| CSR with a weak key | key algorithm/size check |
| CSR spam | global + per-node rate limit |
| Controller token theft | minimal RBAC, NetworkPolicy, restricted pod |
| CSR approved by mistake | Events + audit logs, decided CSRs never re-touched |

Summary:

- **Whitelist signerName** (`kubernetes.io/kube-apiserver-client-kubelet` by
  default; never `kubernetes.io/kube-apiserver-client`, never
  `kubelet-serving` in auto mode).
- **Exact subject**: `CN=system:node:<nodeName>`, `O=system:nodes`.
- **Exact usages**: `digital signature`, `key encipherment`, `client auth`.
  Any extra usage → reject.
- **SANs**: none allowed for a kubelet client cert; if present they must match
  the node addresses exactly, otherwise reject.
- **Key**: RSA >= 2048 bits, ECDSA P-256/P-384, or Ed25519.
- **Node must exist**, must not be terminating, and (if `NODE_LABEL` is set)
  must carry the label.
- **Rate limiting** global (per minute) + per node; dedup by public-key
  fingerprint.
- **Audit**: every decision is logged as structured JSON (CSR uid, node,
  public-key fingerprint, matching rule) and emitted as a Kubernetes Event on
  the CSR.
- **Credential redaction (AGENTS.md §6)**: no credential is ever logged or
  returned in an error path. The CSR's `spec.request` contains a *public* key,
  but we only log its SHA-256 fingerprint, never the raw DER.

## RBAC (minimal)

Dedicated ServiceAccount, ClusterRole limited to:

| apiGroup | resource | verbs |
|---|---|---|
| `certificates.k8s.io` | `certificatesigningrequests` | get, list, watch |
| `certificates.k8s.io` | `certificatesigningrequests/approval` | update, patch |
| `""` | `nodes` | get, list, watch |
| `""` | `events` | create, patch |

## Runtime hardening

Pod `securityContext`: `runAsNonRoot`, non-root uid, `seccompProfile:
RuntimeDefault`, `allowPrivilegeEscalation: false`, `drop: [ALL]`,
`readOnlyRootFilesystem: true`, resource limits, PodSecurity `restricted`.
Static musl binary in a distroless image. NetworkPolicy: egress only to the
API server (443) + DNS, no ingress.

## Deployment

`deploy/base` (kustomize): Namespace `home-cloud` (PodSecurity `restricted`),
dedicated ServiceAccount, minimal ClusterRole (see RBAC above), hardened
single-replica Deployment, egress-only NetworkPolicy (API server TCP/443 +
kube-dns UDP/TCP 53). `deploy/overlays/kind` retags the image for local e2e.
The container image is a static musl binary in a distroless image (`Dockerfile`).

Runtime mode: in-cluster by default (the ServiceAccount token is mounted
automatically); an explicit `--kubeconfig` / `KUBECONFIG` pointing at a
read-only mounted file also works. The controller never reads `~/.kube/config`.

Probes: `src/health.rs` serves `/healthz` (liveness) and `/readyz` (readiness)
on `--health-addr` (default `0.0.0.0:8080`); readiness flips to 200 only after
the node cache sync and the initial CSR list succeeded.

## Testing

- Unit tests: pure validation rules, with CSRs generated in tests (`rcgen`).
- E2E: `scripts/e2e-kind.sh` spins up a **throwaway kind cluster** with its own
  kubeconfig generated under `.e2e/` (gitignored). User kubeconfigs in
  `~/.kube` are never read or written.
