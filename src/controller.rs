//! Main controller loop: CSR watch + reconciliation.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use futures::{Stream, StreamExt};
use k8s_openapi::api::certificates::v1::CertificateSigningRequest;
use kube::api::ListParams;
use kube::runtime::WatchStreamExt;
use kube::runtime::watcher::{self, Event};
use kube::{Api, Client, ResourceExt};

use crate::config::Config;
use crate::nodes::NodeStore;
use crate::security::RateLimiter;
use crate::validate::{self, Decision, Policy};

/// Entry point of the controller loop.
pub async fn run(config: Config) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Health server starts first so kubelet probes get an answer even while we
    // are still connecting; readiness flips to true only after the initial
    // node cache and CSR list have succeeded.
    let ready = crate::health::new_ready_flag();
    let server_ready = ready.clone();
    let health_addr = config.health_addr.clone();
    tokio::spawn(async move {
        if let Err(err) = crate::health::serve(&health_addr, server_ready).await {
            tracing::error!(error = %err, "health server terminated");
        }
    });

    let client = crate::kube::build_client(&config)?;
    tracing::info!("kubernetes client built");

    let nodes = NodeStore::start(client.clone()).await?;
    tracing::info!(node_count = nodes.len().await, "node cache initialized");

    let csr_api: Api<CertificateSigningRequest> = Api::all(client.clone());
    let list = csr_api.list(&ListParams::default()).await?;
    tracing::info!(csr_count = list.items.len(), "listed existing CSRs");

    ready.store(true, Ordering::SeqCst);
    tracing::info!("controller ready");

    let policy = Policy::from_config(&config);
    let limiter = Arc::new(RateLimiter::new(config.max_approvals_per_minute));
    let emit_rejections = config.emit_rejection_events;

    // default_backoff(): after an error, wait with an exponential backoff
    // (client-go conventions) before polling the stream again.
    let stream = watcher::watcher(csr_api, watcher::Config::default()).default_backoff();
    tokio::pin!(stream);

    let (h_client, h_nodes, h_policy, h_limiter) = (
        client.clone(),
        nodes.clone(),
        policy.clone(),
        limiter.clone(),
    );
    drive(stream, move |csr| {
        let (client, nodes, policy, limiter) = (
            h_client.clone(),
            h_nodes.clone(),
            h_policy.clone(),
            h_limiter.clone(),
        );
        async move {
            if let Err(err) = handle_csr(
                &client,
                &nodes,
                &policy,
                limiter.as_ref(),
                emit_rejections,
                &csr,
            )
            .await
            {
                tracing::warn!(csr = %csr.name_any(), error = %err, "failed to handle CSR");
            }
        }
    })
    .await;
    Ok(())
}

/// Consume watcher events until the stream ends.
///
/// An `Err` is logged and the loop **keeps polling**: kube's watcher recovers
/// the stream by itself on the next poll (re-watch from the last known
/// resourceVersion, or full re-list on 410 Gone). We deliberately do NOT use
/// `try_*` stream combinators here — they terminate eagerly on the first `Err`.
async fn drive<S, H, Fut>(mut stream: S, mut on_csr: H)
where
    S: Stream<Item = watcher::Result<Event<CertificateSigningRequest>>> + Unpin,
    H: FnMut(CertificateSigningRequest) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    while let Some(event) = stream.next().await {
        match event {
            Ok(Event::Apply(csr)) | Ok(Event::InitApply(csr)) => on_csr(csr).await,
            Ok(Event::Delete(csr)) => {
                tracing::info!(csr = %csr.name_any(), "CSR deleted");
            }
            Ok(Event::Init) | Ok(Event::InitDone) => {}
            Err(err) => {
                tracing::warn!(error = %err, "CSR watcher error; stream recovers on next poll")
            }
        }
    }
}

/// Validate one pending CSR and approve it if all rules pass.
async fn handle_csr(
    client: &Client,
    nodes: &NodeStore,
    policy: &Policy,
    limiter: &RateLimiter,
    emit_rejections: bool,
    csr: &CertificateSigningRequest,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Never touch a CSR that already carries a decision.
    if crate::csr::is_decided(csr) {
        tracing::debug!(
            csr = %csr.name_any(),
            conditions = ?crate::csr::condition_types(csr),
            "CSR already decided, skipping"
        );
        return Ok(());
    }

    // Foreign signerNames are not ours to judge: ignore quietly.
    if csr.spec.signer_name != policy.signer_name {
        crate::audit::log_decision(
            csr,
            "Ignore",
            &format!("signerName {:?} not handled", csr.spec.signer_name),
            None,
            "-",
        );
        return Ok(());
    }

    let parsed = match validate::parse_request(&csr.spec.request.0) {
        Ok(parsed) => parsed,
        Err(reason) => {
            // Never touch the CSR: log only, Warning Event only if opted in.
            crate::audit::log_decision(csr, "Reject", &reason, None, "-");
            if emit_rejections {
                emit_quietly(client, csr, "Warning", "Rejected", &reason).await;
            }
            return Ok(());
        }
    };

    let node = match &parsed.node_name {
        Some(name) => nodes.get(name).await,
        None => None,
    };
    let decision = validate::decide(csr, policy, &parsed, node.as_ref());
    match decision {
        Decision::Ignore(reason) => {
            crate::audit::log_decision(
                csr,
                "Ignore",
                &reason,
                parsed.node_name.as_deref(),
                &parsed.fingerprint,
            );
        }
        Decision::Reject(reason) => {
            // Never touch the CSR: log only, Warning Event only if opted in.
            crate::audit::log_decision(
                csr,
                "Reject",
                &reason,
                parsed.node_name.as_deref(),
                &parsed.fingerprint,
            );
            if emit_rejections {
                emit_quietly(client, csr, "Warning", "Rejected", &reason).await;
            }
        }
        Decision::Approve { node } => {
            if !limiter.try_acquire(&node).await {
                crate::audit::log_decision(
                    csr,
                    "Ignore",
                    "rate limit exceeded",
                    Some(&node),
                    &parsed.fingerprint,
                );
                return Ok(());
            }
            crate::csr::approve(client, csr).await?;
            crate::audit::log_decision(
                csr,
                "Approve",
                "node exists and CSR passed all validation rules",
                Some(&node),
                &parsed.fingerprint,
            );
            emit_quietly(
                client,
                csr,
                "Normal",
                "Approved",
                &format!(
                    "Auto-approved: node {node} exists and the CSR passed all validation rules"
                ),
            )
            .await;
        }
    }
    Ok(())
}

/// Emit an audit Event; a failure must never break the reconcile loop.
async fn emit_quietly(
    client: &Client,
    csr: &CertificateSigningRequest,
    event_type: &str,
    reason: &str,
    message: &str,
) {
    if let Err(err) = crate::audit::emit_event(client, csr, event_type, reason, message).await {
        tracing::warn!(csr = %csr.name_any(), error = %err, "failed to emit audit event");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::stream;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    use std::sync::atomic::AtomicUsize;

    fn csr(name: &str) -> CertificateSigningRequest {
        CertificateSigningRequest {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn drive_continues_after_watch_errors() {
        let handled = Arc::new(AtomicUsize::new(0));
        let counter = handled.clone();
        let events: Vec<watcher::Result<Event<CertificateSigningRequest>>> = vec![
            Err(watcher::Error::NoResourceVersion),
            Ok(Event::InitApply(csr("a"))),
            Err(watcher::Error::NoResourceVersion),
            Ok(Event::Apply(csr("b"))),
            Ok(Event::Delete(csr("c"))),
            Ok(Event::Init),
            Ok(Event::InitDone),
        ];
        drive(stream::iter(events), move |_csr| {
            let counter = counter.clone();
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
            }
        })
        .await;
        assert_eq!(
            handled.load(Ordering::SeqCst),
            2,
            "both CSR events must be handled despite interleaved errors"
        );
    }
}
