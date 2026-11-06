//! Hardening helpers: key strength checks, SPKI fingerprint, rate limiting.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

// Key algorithm OIDs (dotted form).
pub const OID_RSA: &str = "1.2.840.113549.1.1.1";
pub const OID_EC: &str = "1.2.840.10045.2.1";
pub const OID_ED25519: &str = "1.3.101.112";
// Supported EC curves: P-256 and P-384.
pub const OID_EC_P256: &str = "1.2.840.10045.3.1.7";
pub const OID_EC_P384: &str = "1.3.132.0.34";

pub const MIN_RSA_BITS: usize = 2048;

/// SHA-256 hex fingerprint of a DER-encoded SubjectPublicKeyInfo.
///
/// Used in audit logs instead of the raw key material (AGENTS.md §6: never log
/// credentials; the SPKI contains only a public key, but we log just its hash).
pub fn spki_fingerprint(spki_der: &[u8]) -> String {
    let digest = Sha256::digest(spki_der);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// Check the public key algorithm and size against the allowed set:
/// RSA >= 2048 bits, ECDSA on P-256/P-384, or Ed25519.
pub fn check_key(
    algorithm_oid: &str,
    key_size_bits: usize,
    ec_curve_oid: Option<&str>,
) -> Result<(), String> {
    match algorithm_oid {
        OID_RSA => {
            if key_size_bits < MIN_RSA_BITS {
                Err(format!(
                    "RSA key too weak: {key_size_bits} bits (min {MIN_RSA_BITS})"
                ))
            } else {
                Ok(())
            }
        }
        OID_EC => match ec_curve_oid {
            Some(OID_EC_P256) | Some(OID_EC_P384) => Ok(()),
            other => Err(format!("unsupported EC curve: {other:?}")),
        },
        OID_ED25519 => Ok(()),
        other => Err(format!("unsupported key algorithm OID: {other}")),
    }
}

/// Sliding-window rate limiter: global approvals per minute + one approval per
/// node per hour. `try_acquire` reserves a slot atomically (check + record).
pub struct RateLimiter {
    max_per_minute: usize,
    per_node_interval: Duration,
    global: Mutex<VecDeque<Instant>>,
    per_node: Mutex<HashMap<String, Instant>>,
}

impl RateLimiter {
    pub fn new(max_per_minute: u32) -> Self {
        Self {
            max_per_minute: max_per_minute as usize,
            per_node_interval: Duration::from_secs(3600),
            global: Mutex::new(VecDeque::new()),
            per_node: Mutex::new(HashMap::new()),
        }
    }

    /// Reserve one approval slot for `node`; returns false if a limit is exceeded.
    pub async fn try_acquire(&self, node: &str) -> bool {
        let now = Instant::now();
        let mut global = self.global.lock().await;
        while global
            .front()
            .is_some_and(|t| now.duration_since(*t) > Duration::from_secs(60))
        {
            global.pop_front();
        }
        if global.len() >= self.max_per_minute {
            return false;
        }
        let mut per_node = self.per_node.lock().await;
        if let Some(last) = per_node.get(node)
            && now.duration_since(*last) < self.per_node_interval
        {
            return false;
        }
        global.push_back(now);
        per_node.insert(node.to_string(), now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_sha256_hex() {
        let fp = spki_fingerprint(b"hello");
        assert_eq!(fp.len(), 64);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(fp, spki_fingerprint(b"hello"));
        assert_ne!(fp, spki_fingerprint(b"world"));
    }

    #[test]
    fn key_checks() {
        assert!(check_key(OID_RSA, 2048, None).is_ok());
        assert!(check_key(OID_RSA, 4096, None).is_ok());
        assert!(check_key(OID_RSA, 1024, None).is_err());
        assert!(check_key(OID_EC, 256, Some(OID_EC_P256)).is_ok());
        assert!(check_key(OID_EC, 384, Some(OID_EC_P384)).is_ok());
        assert!(check_key(OID_EC, 256, Some("1.3.132.0.10")).is_err()); // secp256k1
        assert!(check_key(OID_EC, 256, None).is_err());
        assert!(check_key(OID_ED25519, 256, None).is_ok());
        assert!(check_key("1.2.840.113549.1.1.5", 2048, None).is_err()); // md5WithRSA
    }

    #[tokio::test]
    async fn rate_limiter_enforces_global_and_per_node_limits() {
        let limiter = RateLimiter::new(2);
        assert!(limiter.try_acquire("node-a").await);
        assert!(limiter.try_acquire("node-b").await);
        assert!(!limiter.try_acquire("node-c").await, "global window full");
        assert!(
            !limiter.try_acquire("node-a").await,
            "per-node interval not elapsed"
        );
    }
}
