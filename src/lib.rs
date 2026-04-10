/*!
# cuda-did

Decentralized Identity for autonomous agents.

Every vessel in the fleet has a cryptographically verifiable identity:
- DID (Decentralized Identifier) — unique, self-sovereign
- SPIFFE-like trust bundle — workload identity for agent-to-agent auth
- Attestation — proofs of capability, reputation, fleet membership
- Verification — any agent can verify any other agent's claims

No central authority. The fleet IS the trust network.
*/

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Decentralized Identifier for an agent
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentDID {
    /// did:fleet:<authority>:<agent-id>
    pub did: String,
    pub agent_id: String,
    pub authority: String,
    pub public_key: Vec<u8>,
    pub created: u64,
    pub version: u32,
    /// Capabilities this agent claims
    pub capabilities: Vec<String>,
    /// Fleet memberships
    pub fleets: Vec<String>,
}

impl AgentDID {
    pub fn new(agent_id: &str, authority: &str) -> Self {
        let did = format!("did: fleet:{}:{}", authority, agent_id);
        AgentDID {
            did,
            agent_id: agent_id.to_string(),
            authority: authority.to_string(),
            public_key: vec![],
            created: now(),
            version: 1,
            capabilities: vec![],
            fleets: vec![],
        }
    }

    pub fn add_capability(&mut self, cap: &str) { self.capabilities.push(cap.to_string()); }

    pub fn join_fleet(&mut self, fleet_id: &str) { self.fleets.push(fleet_id.to_string()); }

    /// Generate a simple public key hash (placeholder for real crypto)
    pub fn generate_key(&mut self) {
        let seed = format!("{}{}{}", self.agent_id, self.authority, self.created);
        self.public_key = simple_hash(seed.as_bytes());
    }

    /// Verify this DID's signature on data (simplified)
    pub fn verify(&self, data: &[u8], signature: &[u8]) -> bool {
        if self.public_key.is_empty() { return false; }
        let expected = simple_hash(&[data, &self.public_key].concat());
        expected == signature
    }
}

/// An attestation — a claim about an agent verified by another agent
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Attestation {
    pub id: u64,
    pub subject_did: String,   // who is attested
    pub issuer_did: String,    // who attests
    pub claim_type: ClaimType,
    pub claim_value: serde_json::Value,
    pub confidence: f64,       // issuer's confidence in this claim
    pub expires: u64,
    pub revoked: bool,
    pub signature: Vec<u8>,    // issuer's signature
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClaimType {
    Capability,       // agent has this capability
    Reputation,       // agent has this reputation score
    FleetMembership,  // agent belongs to this fleet
    Role,             // agent has this role
    Compliance,       // agent complies with this policy
    TrustEndorsement, // issuer trusts this agent
}

impl Attestation {
    pub fn new(subject: &str, issuer: &str, claim: ClaimType, value: serde_json::Value, confidence: f64) -> Self {
        Attestation {
            id: now(),
            subject_did: subject.to_string(),
            issuer_did: issuer.to_string(),
            claim_type: claim,
            claim_value: value,
            confidence: confidence.clamp(0.0, 1.0),
            expires: now() + 86400_000, // 24h
            revoked: false,
            signature: vec![],
        }
    }

    pub fn is_valid(&self) -> bool {
        !self.revoked && now() < self.expires
    }

    pub fn sign(&mut self, key: &[u8]) {
        let data = format!("{}:{}:{:?}", self.subject_did, self.issuer_did, self.claim_type);
        self.signature = simple_hash(&[data.as_bytes(), key].concat());
    }
}

/// DID Document — the public record of an agent's identity
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DIDDocument {
    pub did: AgentDID,
    pub attestations: Vec<Attestation>,
    pub service_endpoints: Vec<ServiceEndpoint>,
    pub verification_methods: Vec<VerificationMethod>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServiceEndpoint {
    pub id: String,
    pub service_type: String, // "a2a", "mcp", "http", "grpc"
    pub endpoint: String,     // URL or address
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerificationMethod {
    pub id: String,
    pub method_type: String,  // "ed25519", "hash", "none"
    pub public_key: Vec<u8>,
}

impl DIDDocument {
    pub fn new(did: AgentDID) -> Self {
        DIDDocument { did, attestations: vec![], service_endpoints: vec![], verification_methods: vec![] }
    }

    pub fn add_attestation(&mut self, att: Attestation) {
        self.attestations.push(att);
    }

    pub fn add_service(&mut self, id: &str, svc_type: &str, endpoint: &str) {
        self.service_endpoints.push(ServiceEndpoint { id: id.to_string(), service_type: svc_type.to_string(), endpoint: endpoint.to_string() });
    }

    /// Verify a claim by checking attestations
    pub fn verify_claim(&self, claim: ClaimType, required_confidence: f64) -> bool {
        let valid: Vec<_> = self.attestations.iter()
            .filter(|a| a.claim_type == claim && a.is_valid() && a.confidence >= required_confidence)
            .collect();
        !valid.is_empty()
    }

    /// Aggregate reputation from trust endorsements
    pub fn reputation_score(&self) -> f64 {
        let endorsements: Vec<_> = self.attestations.iter()
            .filter(|a| a.claim_type == ClaimType::TrustEndorsement && a.is_valid())
            .collect();
        if endorsements.is_empty() { return 0.5; }
        let sum: f64 = endorsements.iter().map(|a| a.confidence).sum();
        sum / endorsements.len() as f64
    }

    /// List capabilities verified by attestations
    pub fn verified_capabilities(&self) -> Vec<String> {
        let mut caps: Vec<String> = self.attestations.iter()
            .filter(|a| a.claim_type == ClaimType::Capability && a.is_valid())
            .filter_map(|a| a.claim_value.as_str().map(String::from))
            .collect();
        caps.sort(); caps.dedup();
        caps
    }
}

/// Trust Registry — fleet-wide reputation and identity tracking
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrustRegistry {
    pub agents: HashMap<String, DIDDocument>,
    pub revocation_list: Vec<u64>, // revoked attestation IDs
}

impl TrustRegistry {
    pub fn new() -> Self { TrustRegistry { agents: HashMap::new(), revocation_list: vec![] } }

    pub fn register(&mut self, doc: DIDDocument) { self.agents.insert(doc.did.did.clone(), doc); }

    pub fn lookup(&self, did: &str) -> Option<&DIDDocument> { self.agents.get(did) }

    pub fn lookup_mut(&mut self, did: &str) -> Option<&mut DIDDocument> { self.agents.get_mut(did) }

    /// Issue an attestation from one agent to another
    pub fn attest(&mut self, issuer: &str, subject: &str, claim: ClaimType, value: serde_json::Value, confidence: f64) -> Option<Attestation> {
        let issuer_doc = self.agents.get(issuer)?;
        let mut att = Attestation::new(subject, issuer, claim, value, confidence);
        att.sign(&issuer_doc.did.public_key);
        let att_copy = att.clone();
        if let Some(subj_doc) = self.agents.get_mut(subject) {
            subj_doc.attestations.push(att);
        }
        Some(att_copy)
    }

    /// Revoke an attestation
    pub fn revoke(&mut self, att_id: u64) {
        self.revocation_list.push(att_id);
        for doc in self.agents.values_mut() {
            for att in &mut doc.attestations {
                if att.id == att_id { att.revoked = true; }
            }
        }
    }

    /// Find agents by capability
    pub fn find_by_capability(&self, cap: &str) -> Vec<String> {
        self.agents.iter()
            .filter(|(_, doc)| doc.verify_claim(ClaimType::Capability, 0.3) &&
                    doc.attestations.iter().any(|a| a.claim_type == ClaimType::Capability && a.is_valid() &&
                    a.claim_value.as_str().map_or(false, |s| s == cap)))
            .map(|(did, _)| did.clone())
            .collect()
    }

    /// Fleet-wide reputation summary
    pub fn reputation_summary(&self) -> Vec<(String, f64)> {
        let mut reps: Vec<(String, f64)> = self.agents.iter()
            .map(|(did, doc)| (did.clone(), doc.reputation_score()))
            .collect();
        reps.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        reps
    }
}

/// SPIFFE-like trust bundle — a signed collection of agent identities
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrustBundle {
    pub bundle_id: String,
    pub fleet_id: String,
    pub agent_dids: Vec<AgentDID>,
    pub trust_root: Vec<u8>,
    pub issued: u64,
    pub expires: u64,
}

impl TrustBundle {
    pub fn new(fleet_id: &str) -> Self {
        TrustBundle { bundle_id: format!("bundle:{}", fleet_id), fleet_id: fleet_id.to_string(), agent_dids: vec![], trust_root: vec![], issued: now(), expires: now() + 86400_000 * 30 }
    }

    pub fn add_agent(&mut self, did: AgentDID) { self.agent_dids.push(did); }

    pub fn is_valid(&self) -> bool { now() < self.expires }

    /// Find agent DID by agent_id
    pub fn find(&self, agent_id: &str) -> Option<&AgentDID> {
        self.agent_dids.iter().find(|d| d.agent_id == agent_id)
    }
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as u64
}

/// Simple deterministic hash (NOT crypto-grade — placeholder for real ed25519)
fn simple_hash(data: &[u8]) -> Vec<u8> {
    let mut hash = vec![0u8; 32];
    let seed = 0xDEADBEEFu64;
    let mut state = seed;
    for &byte in data {
        state = state.wrapping_mul(31).wrapping_add(byte as u64);
        let idx = (state % 32) as usize;
        hash[idx] = hash[idx].wrapping_add(byte).wrapping_mul(7);
    }
    // Second pass for diffusion
    let mut state2 = seed.wrapping_mul(17);
    for i in 0..32 {
        state2 = state2.wrapping_mul(13).wrapping_add(hash[i] as u64);
        hash[i] = hash[i].wrapping_add((state2 % 256) as u8);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_did_creation() {
        let did = AgentDID::new("agent-1", "lucineer");
        assert!(did.did.contains("agent-1"));
        assert!(did.did.contains("lucineer"));
    }

    #[test]
    fn test_key_generation() {
        let mut did = AgentDID::new("agent-1", "lucineer");
        did.generate_key();
        assert!(!did.public_key.is_empty());
        assert_eq!(did.public_key.len(), 32);
    }

    #[test]
    fn test_attestation_sign_verify() {
        let mut did = AgentDID::new("agent-1", "lucineer");
        did.generate_key();
        let mut att = Attestation::new("did: fleet:lucineer:agent-2", &did.did, ClaimType::Capability, serde_json::json!("navigate"), 0.9);
        att.sign(&did.public_key);
        assert!(!att.signature.is_empty());
    }

    #[test]
    fn test_attestation_expiry() {
        let mut att = Attestation::new("sub", "iss", ClaimType::Capability, serde_json::json!("x"), 0.9);
        att.expires = 0; // already expired
        assert!(!att.is_valid());
    }

    #[test]
    fn test_revocation() {
        let mut att = Attestation::new("sub", "iss", ClaimType::Capability, serde_json::json!("x"), 0.9);
        assert!(att.is_valid());
        att.revoked = true;
        assert!(!att.is_valid());
    }

    #[test]
    fn test_did_document_claim_verification() {
        let mut did = AgentDID::new("a", "fleet");
        did.generate_key();
        let mut doc = DIDDocument::new(did);
        let att = Attestation::new(&doc.did.did, "issuer", ClaimType::Capability, serde_json::json!("navigate"), 0.8);
        doc.add_attestation(att);
        assert!(doc.verify_claim(ClaimType::Capability, 0.5));
        assert!(!doc.verify_claim(ClaimType::Role, 0.5));
    }

    #[test]
    fn test_reputation_score() {
        let mut doc = DIDDocument::new(AgentDID::new("a", "f"));
        doc.add_attestation(Attestation::new("a", "b", ClaimType::TrustEndorsement, serde_json::json!(0.9), 0.9));
        doc.add_attestation(Attestation::new("a", "c", ClaimType::TrustEndorsement, serde_json::json!(0.7), 0.7));
        let rep = doc.reputation_score();
        assert!((rep - 0.8).abs() < 0.01);
    }

    #[test]
    fn test_trust_registry() {
        let mut reg = TrustRegistry::new();
        let mut did_a = AgentDID::new("a", "fleet"); did_a.generate_key();
        let mut did_b = AgentDID::new("b", "fleet"); did_b.generate_key();
        reg.register(DIDDocument::new(did_a.clone()));
        reg.register(DIDDocument::new(did_b.clone()));
        reg.attest(&did_a.did, &did_b.did, ClaimType::Capability, serde_json::json!("navigate"), 0.9);
        let caps = reg.find_by_capability("navigate");
        assert!(caps.iter().any(|c| c.contains("b")));
    }

    #[test]
    fn test_registry_revoke() {
        let mut reg = TrustRegistry::new();
        let mut did = AgentDID::new("a", "f"); did.generate_key();
        reg.register(DIDDocument::new(did));
        let att = reg.attest("a", "a", ClaimType::Capability, serde_json::json!("x"), 0.9).unwrap();
        assert!(reg.lookup("a").unwrap().attestations[0].is_valid());
        reg.revoke(att.id);
        assert!(!reg.lookup("a").unwrap().attestations[0].is_valid());
    }

    #[test]
    fn test_trust_bundle() {
        let mut bundle = TrustBundle::new("fleet-1");
        bundle.add_agent(AgentDID::new("a", "fleet"));
        bundle.add_agent(AgentDID::new("b", "fleet"));
        assert!(bundle.find("a").is_some());
        assert!(bundle.find("c").is_none());
        assert!(bundle.is_valid());
    }

    #[test]
    fn test_capability_add() {
        let mut did = AgentDID::new("a", "f");
        did.add_capability("navigate");
        did.add_capability("communicate");
        assert_eq!(did.capabilities.len(), 2);
    }

    #[test]
    fn test_fleet_membership() {
        let mut did = AgentDID::new("a", "f");
        did.join_fleet("fleet-1");
        did.join_fleet("fleet-2");
        assert_eq!(did.fleets.len(), 2);
    }

    #[test]
    fn test_service_endpoints() {
        let mut doc = DIDDocument::new(AgentDID::new("a", "f"));
        doc.add_service("a2a-1", "a2a", "ws://localhost:8080");
        assert_eq!(doc.service_endpoints.len(), 1);
    }

    #[test]
    fn test_reputation_summary() {
        let mut reg = TrustRegistry::new();
        let did_a = AgentDID::new("a", "f");
        let did_b = AgentDID::new("b", "f");
        reg.register(DIDDocument::new(did_a));
        reg.register(DIDDocument::new(did_b));
        let summary = reg.reputation_summary();
        assert_eq!(summary.len(), 2);
    }

    #[test]
    fn test_verified_capabilities() {
        let mut doc = DIDDocument::new(AgentDID::new("a", "f"));
        doc.add_attestation(Attestation::new("a", "iss", ClaimType::Capability, serde_json::json!("navigate"), 0.8));
        doc.add_attestation(Attestation::new("a", "iss", ClaimType::Capability, serde_json::json!("communicate"), 0.9));
        let caps = doc.verified_capabilities();
        assert!(caps.contains(&"navigate".to_string()));
        assert!(caps.contains(&"communicate".to_string()));
    }
}
