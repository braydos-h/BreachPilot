//! bp-evidence: hash-chained evidence capture + artifact integrity.
//! Each record links prev_hash -> hash (sha256), so tampering breaks the chain.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// One evidence record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    pub run_id: String,
    pub sequence: u64,
    pub kind: String,
    pub body: String,
    pub prev_hash: String,
    pub hash: String,
}

fn hash_of(run_id: &str, seq: u64, kind: &str, body: &str, prev: &str) -> String {
    let mut h = Sha256::new();
    h.update(run_id.as_bytes());
    h.update(seq.to_be_bytes());
    h.update(kind.as_bytes());
    h.update(body.as_bytes());
    h.update(prev.as_bytes());
    hex::encode(h.finalize())
}

/// Append a record to the chain.
pub fn append(chain: &mut Vec<Record>, run_id: &str, kind: &str, body: &str) -> Record {
    let prev = chain
        .last()
        .map(|r| r.hash.clone())
        .unwrap_or_else(|| "GENESIS".into());
    let rec = Record {
        run_id: run_id.into(),
        sequence: chain.len() as u64 + 1,
        kind: kind.into(),
        body: body.into(),
        prev_hash: prev.clone(),
        hash: hash_of(run_id, chain.len() as u64 + 1, kind, body, &prev),
    };
    chain.push(rec.clone());
    rec
}

/// Verify the whole chain. Returns first bad index, if any.
pub fn verify(chain: &[Record]) -> Option<usize> {
    let mut prev = "GENESIS".to_string();
    for (i, r) in chain.iter().enumerate() {
        if r.prev_hash != prev {
            return Some(i);
        }
        if r.hash != hash_of(&r.run_id, r.sequence, &r.kind, &r.body, &r.prev_hash) {
            return Some(i);
        }
        prev = r.hash.clone();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_verifies() {
        let mut c = vec![];
        append(&mut c, "run-1", "exec", "nmap ok");
        append(&mut c, "run-1", "finding", "xss confirmed");
        assert_eq!(verify(&c), None);
    }

    #[test]
    fn tamper_detected() {
        let mut c = vec![];
        append(&mut c, "run-1", "exec", "nmap ok");
        append(&mut c, "run-1", "finding", "xss confirmed");
        c[1].body = "rce confirmed".into();
        assert_eq!(verify(&c), Some(1));
    }
}
