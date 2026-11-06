//! Decision auditing: structured logs + Kubernetes Events on CSRs.
//!
//! AGENTS.md §6: no credential is ever logged — only the CSR name/uid, the node
//! name and the SHA-256 fingerprint of the public key.

use k8s_openapi::api::certificates::v1::CertificateSigningRequest;
use k8s_openapi::api::core::v1::{Event, EventSource, ObjectReference};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{ObjectMeta, Time};
use kube::api::PostParams;
use kube::{Api, Client, ResourceExt};

/// Events are namespaced resources; cluster-scoped CSR events are surfaced by
/// `kubectl describe csr` from the `default` namespace.
pub const EVENT_NAMESPACE: &str = "default";

/// Structured audit log row for one decision.
pub fn log_decision(
    csr: &CertificateSigningRequest,
    decision: &str,
    reason: &str,
    node: Option<&str>,
    fingerprint: &str,
) {
    tracing::info!(
        csr = %csr.name_any(),
        uid = %csr.metadata.uid.clone().unwrap_or_default(),
        decision,
        reason,
        node = ?node,
        key_fingerprint = fingerprint,
        "CSR decision"
    );
}

/// Emit a Kubernetes Event on the CSR (visible via `kubectl describe csr`).
pub async fn emit_event(
    client: &Client,
    csr: &CertificateSigningRequest,
    event_type: &str,
    reason: &str,
    message: &str,
) -> Result<(), kube::Error> {
    let api: Api<Event> = Api::namespaced(client.clone(), EVENT_NAMESPACE);
    let now = Time(k8s_openapi::jiff::Timestamp::now());
    let event = Event {
        metadata: ObjectMeta {
            generate_name: Some(format!("hcc-{}-", csr.name_any())),
            namespace: Some(EVENT_NAMESPACE.to_string()),
            ..Default::default()
        },
        involved_object: ObjectReference {
            api_version: Some("certificates.k8s.io/v1".to_string()),
            kind: Some("CertificateSigningRequest".to_string()),
            name: Some(csr.name_any()),
            uid: csr.metadata.uid.clone(),
            ..Default::default()
        },
        reason: Some(reason.to_string()),
        message: Some(message.to_string()),
        type_: Some(event_type.to_string()),
        source: Some(EventSource {
            component: Some("home-cloud-controller-manager".to_string()),
            ..Default::default()
        }),
        first_timestamp: Some(now.clone()),
        last_timestamp: Some(now),
        count: Some(1),
        ..Default::default()
    };
    api.create(&PostParams::default(), &event).await?;
    Ok(())
}
