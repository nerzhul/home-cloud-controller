//! Controller configuration: CLI flags (clap) > environment variables > defaults.

use clap::Parser;

/// Controller that automatically approves kubelet client CSRs for existing nodes.
#[derive(Debug, Parser)]
#[command(name = "home-cloud-controller-manager", version, about)]
pub struct Config {
    /// Path to a kubeconfig file. If unset, the in-cluster config is used.
    #[arg(long, env = "KUBECONFIG")]
    pub kubeconfig: Option<String>,

    /// Kubeconfig context to use.
    #[arg(long, env = "KUBE_CONTEXT")]
    pub context: Option<String>,

    /// Only approve CSRs carrying this signerName.
    #[arg(
        long,
        env = "SIGNER_NAME",
        default_value = "kubernetes.io/kube-apiserver-client-kubelet"
    )]
    pub signer_name: String,

    /// If set, only approve CSRs for nodes carrying this `key=value` label.
    #[arg(long, env = "NODE_LABEL")]
    pub node_label: Option<String>,

    /// Maximum number of approvals per minute (global rate limit).
    #[arg(long, env = "MAX_APPROVALS_PER_MINUTE", default_value_t = 10)]
    pub max_approvals_per_minute: u32,

    /// Maximum accepted size for `spec.request` (base64 decoded), in bytes.
    #[arg(long, env = "MAX_CSR_REQUEST_BYTES", default_value_t = 65536)]
    pub max_csr_request_bytes: usize,

    /// Address of the health server (kube probes): `/healthz` liveness, `/readyz` readiness.
    #[arg(long, env = "HEALTH_ADDR", default_value = "0.0.0.0:8080")]
    pub health_addr: String,

    /// Emit a Warning Event on CSRs that fail validation. Off by default:
    /// invalid CSRs are only logged and never touched (no Denied condition).
    #[arg(long, env = "EMIT_REJECTION_EVENTS", default_value_t = false)]
    pub emit_rejection_events: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejection_events_are_opt_in() {
        let config = Config::try_parse_from(["home-cloud-controller-manager"]).unwrap();
        assert!(!config.emit_rejection_events);
        let config =
            Config::try_parse_from(["home-cloud-controller-manager", "--emit-rejection-events"])
                .unwrap();
        assert!(config.emit_rejection_events);
    }
}
