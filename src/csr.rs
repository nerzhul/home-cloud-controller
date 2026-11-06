//! CertificateSigningRequest handling: status, conditions, approval patch.

use k8s_openapi::api::certificates::v1::{
    CertificateSigningRequest, CertificateSigningRequestCondition,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
use kube::api::{Patch, PatchParams};
use kube::{Api, Client, ResourceExt};
use serde_json::json;

/// A CSR is "decided" once it carries at least one condition (Approved/Denied).
pub fn is_decided(csr: &CertificateSigningRequest) -> bool {
    csr.status
        .as_ref()
        .and_then(|status| status.conditions.as_ref())
        .is_some_and(|conditions| !conditions.is_empty())
}

/// Condition types currently set on the CSR, for logging.
pub fn condition_types(csr: &CertificateSigningRequest) -> Vec<String> {
    csr.status
        .as_ref()
        .and_then(|status| status.conditions.as_ref())
        .map(|conditions| {
            conditions
                .iter()
                .map(|condition| condition.type_.clone())
                .collect()
        })
        .unwrap_or_default()
}

/// The `Approved` condition we add via the approval subresource.
pub fn approval_condition() -> CertificateSigningRequestCondition {
    let now = Time(k8s_openapi::jiff::Timestamp::now());
    CertificateSigningRequestCondition {
        type_: "Approved".to_string(),
        status: "True".to_string(),
        reason: Some("AutoApproved".to_string()),
        message: Some("Node exists and the CSR passed all validation rules".to_string()),
        last_update_time: Some(now.clone()),
        last_transition_time: Some(now),
    }
}

/// Approve a CSR through the `certificatesigningrequests/approval` subresource.
///
/// Merge-patch with retry on 409 Conflict: on conflict we re-fetch the CSR and
/// give up silently if another approver decided it in the meantime.
pub async fn approve(client: &Client, csr: &CertificateSigningRequest) -> Result<(), kube::Error> {
    let api: Api<CertificateSigningRequest> = Api::all(client.clone());
    let name = csr.name_any();
    let patch = Patch::Merge(json!({
        "status": { "conditions": [approval_condition()] }
    }));

    let mut attempt: u64 = 0;
    loop {
        let result = api
            .patch_subresource("approval", &name, &PatchParams::default(), &patch)
            .await;
        match result {
            Ok(_) => return Ok(()),
            Err(err) => {
                let is_conflict =
                    matches!(&err, kube::Error::Api(status) if status.reason == "Conflict");
                if is_conflict && attempt < 3 {
                    attempt += 1;
                    let fresh = api.get(&name).await?;
                    if is_decided(&fresh) {
                        return Ok(());
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(100 * attempt)).await;
                } else {
                    return Err(err);
                }
            }
        }
    }
}
