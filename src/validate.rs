//! CSR validation policy (pure functions, unit-testable).
//!
//! Security rules (docs/architecture.md): whitelist signerName, exact subject
//! `CN=system:node:<name>` + `O=system:nodes`, exact usage set, key strength,
//! SANs must match node addresses, node must exist and not be terminating.

use std::collections::BTreeSet;

use k8s_openapi::api::certificates::v1::CertificateSigningRequest;
use k8s_openapi::api::core::v1::Node;
use x509_parser::certification_request::X509CertificationRequest;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::FromDer;

use crate::security;

// Attribute/extension OIDs in dotted form (compared via `Oid::to_id_string()`).
const OID_CN: &str = "2.5.4.3";
const OID_O: &str = "2.5.4.10";

/// The exact usages a kubelet client CSR is allowed to carry (k8s string form).
pub const KUBELET_CLIENT_USAGES: [&str; 3] =
    ["client auth", "digital signature", "key encipherment"];

/// Node annotation that blocks auto-approval for that node.
pub const BLOCK_ANNOTATION: &str = "home-cloud.io/csr-approval";

#[derive(Debug, Clone)]
pub struct Policy {
    pub signer_name: String,
    pub node_label: Option<(String, String)>,
    pub max_request_bytes: usize,
    pub allowed_usages: BTreeSet<String>,
}

impl Policy {
    pub fn from_config(config: &crate::config::Config) -> Self {
        let allowed_usages = KUBELET_CLIENT_USAGES
            .iter()
            .map(|u| u.to_string())
            .collect();
        let node_label = config
            .node_label
            .as_deref()
            .and_then(|s| s.split_once('='))
            .map(|(k, v)| (k.to_string(), v.to_string()));
        Self {
            signer_name: config.signer_name.clone(),
            node_label,
            max_request_bytes: config.max_csr_request_bytes,
            allowed_usages,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Approve {
        node: String,
    },
    /// Content violates a security rule: logged; a Warning Event is emitted only
    /// when `--emit-rejection-events` is set. We never set a Denied condition.
    Reject(String),
    /// Not our business (foreign signer, unknown node): log only.
    Ignore(String),
}

/// Data extracted from the PKCS#10 in `spec.request`.
#[derive(Debug, Clone)]
pub struct ParsedRequest {
    /// Node name extracted from `CN=system:node:<name>`, if well-formed.
    pub node_name: Option<String>,
    pub has_system_nodes_org: bool,
    /// SANs normalized as `dns:<name>` / `ip:<addr>` / `other:<debug>`.
    pub sans: Vec<String>,
    pub key_algorithm: String,
    pub key_size_bits: usize,
    pub ec_curve: Option<String>,
    pub eku: Option<Eku>,
    /// SHA-256 hex of the SPKI (audit only, never the raw key).
    pub fingerprint: String,
}

#[derive(Debug, Clone, Default)]
pub struct Eku {
    pub any: bool,
    pub server_auth: bool,
    pub client_auth: bool,
    pub code_signing: bool,
    pub email_protection: bool,
    pub time_stamping: bool,
    pub ocsp_signing: bool,
    pub other: Vec<String>,
}

impl Eku {
    /// True if the EKU allows anything beyond clientAuth.
    pub fn broader_than_client_auth(&self) -> bool {
        self.any
            || self.server_auth
            || self.code_signing
            || self.email_protection
            || self.time_stamping
            || self.ocsp_signing
            || !self.other.is_empty()
    }
}

fn format_ip(bytes: &[u8]) -> String {
    match bytes.len() {
        4 => bytes
            .iter()
            .map(|o| o.to_string())
            .collect::<Vec<_>>()
            .join("."),
        16 => bytes
            .chunks(2)
            .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
            .collect::<Vec<_>>()
            .join(":"),
        _ => format!("{bytes:02x?}"),
    }
}

/// Parse the DER-encoded PKCS#10 from `spec.request`.
pub fn parse_request(der: &[u8]) -> Result<ParsedRequest, String> {
    let (_, req) =
        X509CertificationRequest::from_der(der).map_err(|e| format!("invalid PKCS#10: {e}"))?;
    let info = &req.certification_request_info;

    let mut cn: Option<String> = None;
    let mut orgs: Vec<String> = Vec::new();
    for attr in info.subject.iter_attributes() {
        let oid = attr.attr_type().to_id_string();
        let value = attr
            .attr_value()
            .as_str()
            .map_err(|e| format!("non-UTF8 subject attribute: {e}"))?
            .to_string();
        match oid.as_str() {
            OID_CN => cn = Some(value),
            OID_O => orgs.push(value),
            _ => {}
        }
    }
    let node_name = cn
        .as_deref()
        .and_then(|c| c.strip_prefix("system:node:"))
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    let spki = &info.subject_pki;
    let fingerprint = security::spki_fingerprint(spki.raw);
    let key_algorithm = spki.algorithm.algorithm.to_id_string();
    let ec_curve = spki
        .algorithm
        .parameters
        .as_ref()
        .and_then(|p| p.as_oid().ok())
        .map(|o| o.to_id_string());
    let key = spki
        .parsed()
        .map_err(|e| format!("unparsable public key: {e}"))?;
    let key_size_bits = key.key_size();

    let mut sans: Vec<String> = Vec::new();
    let mut eku: Option<Eku> = None;
    if let Some(extensions) = req.requested_extensions() {
        for ext in extensions {
            match ext {
                ParsedExtension::SubjectAlternativeName(san) => {
                    for gn in &san.general_names {
                        match gn {
                            GeneralName::DNSName(d) => sans.push(format!("dns:{d}")),
                            GeneralName::IPAddress(b) => sans.push(format!("ip:{}", format_ip(b))),
                            other => sans.push(format!("other:{other:?}")),
                        }
                    }
                }
                ParsedExtension::ExtendedKeyUsage(e) => {
                    eku = Some(Eku {
                        any: e.any,
                        server_auth: e.server_auth,
                        client_auth: e.client_auth,
                        code_signing: e.code_signing,
                        email_protection: e.email_protection,
                        time_stamping: e.time_stamping,
                        ocsp_signing: e.ocsp_signing,
                        other: e.other.iter().map(|o| o.to_id_string()).collect(),
                    });
                }
                _ => {}
            }
        }
    }

    Ok(ParsedRequest {
        node_name,
        has_system_nodes_org: orgs.iter().any(|o| o == "system:nodes"),
        sans,
        key_algorithm,
        key_size_bits,
        ec_curve,
        eku,
        fingerprint,
    })
}

/// Apply the full validation policy to a pending CSR.
///
/// `node` is the cluster Node matching the CN, if it exists (looked up by the
/// caller in the node cache).
pub fn decide(
    csr: &CertificateSigningRequest,
    policy: &Policy,
    parsed: &ParsedRequest,
    node: Option<&Node>,
) -> Decision {
    if csr.spec.signer_name != policy.signer_name {
        return Decision::Ignore(format!(
            "signerName {:?} is not handled by this controller",
            csr.spec.signer_name
        ));
    }
    if csr.spec.request.0.len() > policy.max_request_bytes {
        return Decision::Reject(format!(
            "request too large: {} bytes (max {})",
            csr.spec.request.0.len(),
            policy.max_request_bytes
        ));
    }
    let Some(node_name) = &parsed.node_name else {
        return Decision::Reject("subject CN is not of the form system:node:<name>".to_string());
    };
    if !parsed.has_system_nodes_org {
        return Decision::Reject("subject is missing O=system:nodes".to_string());
    }
    let usages: BTreeSet<String> = csr
        .spec
        .usages
        .clone()
        .unwrap_or_default()
        .into_iter()
        .collect();
    if usages != policy.allowed_usages {
        return Decision::Reject(format!("unexpected usages: {usages:?}"));
    }
    if let Err(reason) = security::check_key(
        &parsed.key_algorithm,
        parsed.key_size_bits,
        parsed.ec_curve.as_deref(),
    ) {
        return Decision::Reject(reason);
    }
    if let Some(eku) = &parsed.eku
        && (eku.broader_than_client_auth() || !eku.client_auth)
    {
        return Decision::Reject("extended key usage must be exactly clientAuth".to_string());
    }

    let Some(node) = node else {
        return Decision::Ignore(format!("node {node_name} not found in cache"));
    };
    if node.metadata.deletion_timestamp.is_some() {
        return Decision::Reject(format!("node {node_name} is terminating"));
    }
    if node
        .metadata
        .annotations
        .as_ref()
        .and_then(|a| a.get(BLOCK_ANNOTATION))
        .map(|v| v.as_str())
        == Some("blocked")
    {
        return Decision::Reject(format!("node {node_name} has {BLOCK_ANNOTATION}=blocked"));
    }
    if let Some((key, value)) = &policy.node_label {
        let has_label = node
            .metadata
            .labels
            .as_ref()
            .and_then(|l| l.get(key))
            .map(|v| v.as_str())
            == Some(value.as_str());
        if !has_label {
            return Decision::Reject(format!(
                "node {node_name} lacks required label {key}={value}"
            ));
        }
    }
    if !parsed.sans.is_empty() {
        let addresses: Vec<String> = node
            .status
            .as_ref()
            .and_then(|s| s.addresses.clone())
            .unwrap_or_default()
            .iter()
            .map(|a| match a.type_.as_str() {
                "InternalIP" | "ExternalIP" => format!("ip:{}", a.address),
                "Hostname" => format!("dns:{}", a.address),
                other => format!("{other}:{}", a.address),
            })
            .collect();
        for san in &parsed.sans {
            if !addresses.contains(san) {
                return Decision::Reject(format!(
                    "SAN {san} does not match any address of node {node_name}"
                ));
            }
        }
    }
    Decision::Approve {
        node: node_name.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::ByteString;
    use k8s_openapi::api::certificates::v1::CertificateSigningRequestSpec;
    use k8s_openapi::api::core::v1::{NodeAddress, NodeStatus};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    use rcgen::{
        CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, KeyPair,
        KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, PKCS_ED25519, PKCS_RSA_SHA256, SanType,
    };
    use std::net::IpAddr;

    const SIGNER: &str = "kubernetes.io/kube-apiserver-client-kubelet";

    fn make_csr_der(
        cn: &str,
        org: Option<&str>,
        sans: Vec<SanType>,
        alg: &'static rcgen::SignatureAlgorithm,
        eku: Vec<ExtendedKeyUsagePurpose>,
    ) -> Vec<u8> {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, cn);
        if let Some(org) = org {
            dn.push(DnType::OrganizationName, org);
        }
        params.distinguished_name = dn;
        params.subject_alt_names = sans;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = eku;
        let key = KeyPair::generate_for(alg).unwrap();
        params.serialize_request(&key).unwrap().der().to_vec()
    }

    fn csr_object(der: Vec<u8>, signer: &str, usages: &[&str]) -> CertificateSigningRequest {
        CertificateSigningRequest {
            metadata: ObjectMeta {
                name: Some("test-csr".to_string()),
                uid: Some("uid-1".to_string()),
                ..Default::default()
            },
            spec: CertificateSigningRequestSpec {
                request: ByteString(der),
                signer_name: signer.to_string(),
                usages: Some(usages.iter().map(|s| s.to_string()).collect()),
                ..Default::default()
            },
            status: None,
        }
    }

    fn kubelet_usages() -> Vec<&'static str> {
        vec!["digital signature", "key encipherment", "client auth"]
    }

    fn make_node(
        name: &str,
        labels: Vec<(&str, &str)>,
        annotations: Vec<(&str, &str)>,
        addresses: Vec<(&str, &str)>,
        terminating: bool,
    ) -> Node {
        Node {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                labels: Some(
                    labels
                        .into_iter()
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                        .collect(),
                ),
                annotations: Some(
                    annotations
                        .into_iter()
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                        .collect(),
                ),
                deletion_timestamp: terminating.then(|| {
                    k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                        k8s_openapi::jiff::Timestamp::now(),
                    )
                }),
                ..Default::default()
            },
            status: Some(NodeStatus {
                addresses: Some(
                    addresses
                        .into_iter()
                        .map(|(t, a)| NodeAddress {
                            type_: t.to_string(),
                            address: a.to_string(),
                        })
                        .collect(),
                ),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn policy() -> Policy {
        Policy {
            signer_name: SIGNER.to_string(),
            node_label: None,
            max_request_bytes: 65536,
            allowed_usages: KUBELET_CLIENT_USAGES
                .iter()
                .map(|u| u.to_string())
                .collect(),
        }
    }

    fn legit_der() -> Vec<u8> {
        make_csr_der(
            "system:node:worker-1",
            Some("system:nodes"),
            vec![],
            &PKCS_RSA_SHA256,
            vec![ExtendedKeyUsagePurpose::ClientAuth],
        )
    }

    fn decide_on(
        csr: &CertificateSigningRequest,
        policy: &Policy,
        node: Option<&Node>,
    ) -> Decision {
        let parsed = parse_request(&csr.spec.request.0).unwrap();
        decide(csr, policy, &parsed, node)
    }

    #[test]
    fn parses_rsa_key_size() {
        let parsed = parse_request(&legit_der()).unwrap();
        assert_eq!(parsed.node_name.as_deref(), Some("worker-1"));
        assert!(parsed.has_system_nodes_org);
        assert_eq!(parsed.key_algorithm, security::OID_RSA);
        assert_eq!(parsed.key_size_bits, 2048);
        assert!(parsed.sans.is_empty());
        assert_eq!(parsed.fingerprint.len(), 64);
        assert!(
            parsed
                .eku
                .as_ref()
                .is_some_and(|e| e.client_auth && !e.broader_than_client_auth())
        );
    }

    #[test]
    fn legit_rsa_csr_is_approved_for_existing_node() {
        let csr = csr_object(legit_der(), SIGNER, &kubelet_usages());
        let node = make_node(
            "worker-1",
            vec![],
            vec![],
            vec![("InternalIP", "10.0.0.1")],
            false,
        );
        assert_eq!(
            decide_on(&csr, &policy(), Some(&node)),
            Decision::Approve {
                node: "worker-1".to_string()
            }
        );
    }

    #[test]
    fn ecdsa_and_ed25519_keys_are_accepted() {
        for alg in [&PKCS_ECDSA_P256_SHA256, &PKCS_ED25519] {
            let der = make_csr_der(
                "system:node:worker-1",
                Some("system:nodes"),
                vec![],
                alg,
                vec![ExtendedKeyUsagePurpose::ClientAuth],
            );
            let csr = csr_object(der, SIGNER, &kubelet_usages());
            let node = make_node("worker-1", vec![], vec![], vec![], false);
            assert_eq!(
                decide_on(&csr, &policy(), Some(&node)),
                Decision::Approve {
                    node: "worker-1".to_string()
                }
            );
        }
    }

    #[test]
    fn foreign_signer_is_ignored() {
        let csr = csr_object(
            legit_der(),
            "kubernetes.io/kube-apiserver-client",
            &kubelet_usages(),
        );
        let node = make_node("worker-1", vec![], vec![], vec![], false);
        assert!(matches!(
            decide_on(&csr, &policy(), Some(&node)),
            Decision::Ignore(_)
        ));
    }

    #[test]
    fn bad_cn_is_rejected() {
        let der = make_csr_der(
            "evil-admin",
            Some("system:nodes"),
            vec![],
            &PKCS_RSA_SHA256,
            vec![],
        );
        let csr = csr_object(der, SIGNER, &kubelet_usages());
        assert!(matches!(
            decide_on(&csr, &policy(), None),
            Decision::Reject(_)
        ));
    }

    #[test]
    fn missing_system_nodes_org_is_rejected() {
        let der = make_csr_der(
            "system:node:worker-1",
            None,
            vec![],
            &PKCS_RSA_SHA256,
            vec![],
        );
        let csr = csr_object(der, SIGNER, &kubelet_usages());
        let node = make_node("worker-1", vec![], vec![], vec![], false);
        assert!(matches!(
            decide_on(&csr, &policy(), Some(&node)),
            Decision::Reject(_)
        ));
    }

    #[test]
    fn extra_usage_is_rejected() {
        let mut usages = kubelet_usages();
        usages.push("server auth");
        let csr = csr_object(legit_der(), SIGNER, &usages);
        let node = make_node("worker-1", vec![], vec![], vec![], false);
        assert!(matches!(
            decide_on(&csr, &policy(), Some(&node)),
            Decision::Reject(_)
        ));
    }

    #[test]
    fn rogue_san_is_rejected() {
        let der = make_csr_der(
            "system:node:worker-1",
            Some("system:nodes"),
            vec![SanType::DnsName("evil.example.com".try_into().unwrap())],
            &PKCS_RSA_SHA256,
            vec![],
        );
        let csr = csr_object(der, SIGNER, &kubelet_usages());
        let node = make_node(
            "worker-1",
            vec![],
            vec![],
            vec![("InternalIP", "10.0.0.1")],
            false,
        );
        assert!(matches!(
            decide_on(&csr, &policy(), Some(&node)),
            Decision::Reject(_)
        ));
    }

    #[test]
    fn san_matching_node_ip_is_approved() {
        let der = make_csr_der(
            "system:node:worker-1",
            Some("system:nodes"),
            vec![SanType::IpAddress(IpAddr::from([10, 0, 0, 1]))],
            &PKCS_RSA_SHA256,
            vec![ExtendedKeyUsagePurpose::ClientAuth],
        );
        let csr = csr_object(der, SIGNER, &kubelet_usages());
        let node = make_node(
            "worker-1",
            vec![],
            vec![],
            vec![("InternalIP", "10.0.0.1")],
            false,
        );
        assert_eq!(
            decide_on(&csr, &policy(), Some(&node)),
            Decision::Approve {
                node: "worker-1".to_string()
            }
        );
    }

    #[test]
    fn unknown_node_is_ignored() {
        let csr = csr_object(legit_der(), SIGNER, &kubelet_usages());
        assert!(matches!(
            decide_on(&csr, &policy(), None),
            Decision::Ignore(_)
        ));
    }

    #[test]
    fn terminating_node_is_rejected() {
        let csr = csr_object(legit_der(), SIGNER, &kubelet_usages());
        let node = make_node("worker-1", vec![], vec![], vec![], true);
        assert!(matches!(
            decide_on(&csr, &policy(), Some(&node)),
            Decision::Reject(_)
        ));
    }

    #[test]
    fn blocked_annotation_is_rejected() {
        let csr = csr_object(legit_der(), SIGNER, &kubelet_usages());
        let node = make_node(
            "worker-1",
            vec![],
            vec![(BLOCK_ANNOTATION, "blocked")],
            vec![],
            false,
        );
        assert!(matches!(
            decide_on(&csr, &policy(), Some(&node)),
            Decision::Reject(_)
        ));
    }

    #[test]
    fn required_label_must_be_present() {
        let mut p = policy();
        p.node_label = Some((
            "home-cloud.io/auto-approve-csr".to_string(),
            "true".to_string(),
        ));
        let csr = csr_object(legit_der(), SIGNER, &kubelet_usages());
        let unlabelled = make_node("worker-1", vec![], vec![], vec![], false);
        assert!(matches!(
            decide_on(&csr, &p, Some(&unlabelled)),
            Decision::Reject(_)
        ));
        let labelled = make_node(
            "worker-1",
            vec![("home-cloud.io/auto-approve-csr", "true")],
            vec![],
            vec![],
            false,
        );
        assert_eq!(
            decide_on(&csr, &p, Some(&labelled)),
            Decision::Approve {
                node: "worker-1".to_string()
            }
        );
    }

    #[test]
    fn server_auth_eku_is_rejected() {
        let der = make_csr_der(
            "system:node:worker-1",
            Some("system:nodes"),
            vec![],
            &PKCS_RSA_SHA256,
            vec![ExtendedKeyUsagePurpose::ServerAuth],
        );
        let csr = csr_object(der, SIGNER, &kubelet_usages());
        let node = make_node("worker-1", vec![], vec![], vec![], false);
        assert!(matches!(
            decide_on(&csr, &policy(), Some(&node)),
            Decision::Reject(_)
        ));
    }

    #[test]
    fn corrupt_der_is_rejected() {
        let csr = csr_object(vec![0x30, 0x03, 0x01, 0x02], SIGNER, &kubelet_usages());
        assert!(parse_request(&csr.spec.request.0).is_err());
    }

    #[test]
    fn oversized_request_is_rejected() {
        let mut p = policy();
        p.max_request_bytes = 16;
        let csr = csr_object(legit_der(), SIGNER, &kubelet_usages());
        let parsed = parse_request(&csr.spec.request.0).unwrap();
        assert!(matches!(
            decide(&csr, &p, &parsed, None),
            Decision::Reject(_)
        ));
    }
}
