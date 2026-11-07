//! Kubernetes client construction from an explicit kubeconfig or in-cluster config.

use kube::Client;
use kube::Config as KubeClientConfig;
use kube::config::{InClusterError, Kubeconfig, KubeconfigError};
use thiserror::Error;

use crate::config::Config;

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("failed to read kubeconfig at {path}: {source}")]
    ReadKubeconfig {
        path: String,
        source: KubeconfigError,
    },
    #[error("failed to build API client: {0}")]
    Build(#[from] kube::Error),
    #[error("no --kubeconfig given and not running in-cluster: {0}")]
    NotInCluster(#[from] InClusterError),
}

/// Build a Kubernetes client.
///
/// An explicit `--kubeconfig` path wins; otherwise in-cluster config is
/// required. We deliberately never fall back to `~/.kube/config` or the
/// `KUBECONFIG` default: user kubeconfigs are off-limits (repo rule).
pub fn build_client(config: &Config) -> Result<Client, ClientError> {
    match &config.kubeconfig {
        Some(path) => {
            let mut kubeconfig =
                Kubeconfig::read_from(path).map_err(|source| ClientError::ReadKubeconfig {
                    path: path.clone(),
                    source,
                })?;
            if let Some(context) = &config.context {
                kubeconfig.current_context = Some(context.clone());
            }
            Ok(Client::try_from(kubeconfig)?)
        }
        None => {
            let incluster = KubeClientConfig::incluster()?;
            // Log the target API server URL so a later "client error (Connect)"
            // is immediately attributable to network (NetworkPolicy, routes)
            // rather than to the token or the CA bundle.
            tracing::info!(cluster_url = %incluster.cluster_url, "in-cluster config loaded");
            Ok(Client::try_from(incluster)?)
        }
    }
}
