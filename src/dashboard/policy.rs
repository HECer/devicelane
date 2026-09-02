use super::model::{
    ActivityId, ApprovalDecision, DeviceId, HostId, OperationId, PolicyEffect, PolicyOrigin,
    PolicyRule, PrincipalId, ResourceClass, RuleId, ValidationError,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

const MAX_APPROVAL_LIFETIME_MS: u64 = 5 * 60 * 1_000;
pub const MAX_POLICY_RULES: usize = super::model::MAX_COLLECTION_ITEMS;
pub const MAX_PENDING_APPROVALS: usize = super::model::MAX_COLLECTION_ITEMS;
const NONCE_GENERATION_ATTEMPTS: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessRequest {
    pub activity_id: ActivityId,
    pub principal_id: PrincipalId,
    pub source_host_id: HostId,
    pub target_host_id: HostId,
    pub device_id: Option<DeviceId>,
    pub operation: OperationId,
    pub resources: Vec<ResourceClass>,
    pub physical_device: bool,
    pub user_present: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccessRequestWire {
    activity_id: ActivityId,
    principal_id: PrincipalId,
    source_host_id: HostId,
    target_host_id: HostId,
    device_id: Option<DeviceId>,
    operation: OperationId,
    resources: Vec<ResourceClass>,
    physical_device: bool,
    user_present: bool,
}

impl From<&AccessRequest> for AccessRequestWire {
    fn from(value: &AccessRequest) -> Self {
        Self {
            activity_id: value.activity_id.clone(),
            principal_id: value.principal_id.clone(),
            source_host_id: value.source_host_id.clone(),
            target_host_id: value.target_host_id.clone(),
            device_id: value.device_id.clone(),
            operation: value.operation.clone(),
            resources: value.resources.clone(),
            physical_device: value.physical_device,
            user_present: value.user_present,
        }
    }
}

impl TryFrom<AccessRequestWire> for AccessRequest {
    type Error = PolicyError;

    fn try_from(value: AccessRequestWire) -> Result<Self, Self::Error> {
        let request = Self {
            activity_id: value.activity_id,
            principal_id: value.principal_id,
            source_host_id: value.source_host_id,
            target_host_id: value.target_host_id,
            device_id: value.device_id,
            operation: value.operation,
            resources: value.resources,
            physical_device: value.physical_device,
            user_present: value.user_present,
        };
        validate_request(&request)?;
        Ok(request)
    }
}

impl Serialize for AccessRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        validate_request(self).map_err(serde::ser::Error::custom)?;
        AccessRequestWire::from(self).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for AccessRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        AccessRequest::try_from(AccessRequestWire::deserialize(deserializer)?)
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyError {
    InvalidRequest,
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("invalid access request")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyDecision {
    Allowed { rule_id: RuleId },
    Denied { rule_id: RuleId },
    ApprovalRequired { reason: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalChallenge {
    pub nonce: String,
    pub expires_at_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalOutcome {
    pub decision: ApprovalDecision,
    pub created_rule: Option<PolicyRule>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApprovalError {
    InvalidRequest,
    InvalidLifetime,
    UnknownNonce,
    WrongTarget,
    RequestMismatch,
    Expired,
    AlreadyUsed,
    ApprovalLimitExceeded,
    RuleLimitExceeded,
    NonceGenerationFailed,
    UnauthenticatedTargetSession,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyConfigurationError {
    InvalidRule(ValidationError),
    RuleLimitExceeded,
    DuplicateRuleId,
    ManagedOriginRequiresVerification,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TrustError {
    TransportTargetMismatch,
    ManagedPolicyVerificationFailed,
    InvalidCapability,
}

pub trait ManagedPolicyVerifier: Send + Sync {
    fn verify(&self, rules_digest: &[u8; 32]) -> bool;
}

pub struct TransportAuthentication {
    authenticated_host_id: HostId,
}

impl TransportAuthentication {
    #[allow(dead_code)]
    pub(crate) fn new(authenticated_host_id: HostId) -> Self {
        Self {
            authenticated_host_id,
        }
    }
}

pub struct PolicyTrustAuthority {
    secret: [u8; 32],
    managed_verifier: Box<dyn ManagedPolicyVerifier>,
}

impl PolicyTrustAuthority {
    #[allow(dead_code)]
    pub(crate) fn new(managed_verifier: Box<dyn ManagedPolicyVerifier>) -> Self {
        let mut secret = [0_u8; 32];
        rand::thread_rng().fill_bytes(&mut secret);
        Self {
            secret,
            managed_verifier,
        }
    }

    pub fn issue_target_session(
        &self,
        transport: &TransportAuthentication,
        requested_target: &HostId,
    ) -> Result<AuthenticatedTargetSession, TrustError> {
        if &transport.authenticated_host_id != requested_target {
            return Err(TrustError::TransportTargetMismatch);
        }
        let mac = trust_mac(
            &self.secret,
            b"target-session",
            requested_target.as_str().as_bytes(),
        );
        Ok(AuthenticatedTargetSession {
            target_host_id: requested_target.clone(),
            mac,
        })
    }

    pub fn verify_managed_rules(
        &self,
        rules: Vec<PolicyRule>,
    ) -> Result<VerifiedManagedPolicyBundle, TrustError> {
        let digest = rules_digest(&rules)?;
        if !self.managed_verifier.verify(&digest) {
            return Err(TrustError::ManagedPolicyVerificationFailed);
        }
        Ok(VerifiedManagedPolicyBundle {
            rules,
            digest,
            mac: trust_mac(&self.secret, b"managed-rules", &digest),
        })
    }

    fn verifies_session(&self, session: &AuthenticatedTargetSession) -> bool {
        session.mac
            == trust_mac(
                &self.secret,
                b"target-session",
                session.target_host_id.as_str().as_bytes(),
            )
    }

    fn verifies_bundle(&self, bundle: &VerifiedManagedPolicyBundle) -> bool {
        rules_digest(&bundle.rules).is_ok_and(|digest| digest == bundle.digest)
            && bundle.mac == trust_mac(&self.secret, b"managed-rules", &bundle.digest)
    }
}

/// Proof that the caller was authenticated as the target host.
///
/// ```compile_fail
/// use device_development_mesh::dashboard::{HostId, policy::AuthenticatedTargetSession};
/// let _ = AuthenticatedTargetSession { target_host_id: HostId::parse("forged").unwrap() };
/// ```
pub struct AuthenticatedTargetSession {
    target_host_id: HostId,
    mac: [u8; 32],
}

pub struct VerifiedManagedPolicyBundle {
    rules: Vec<PolicyRule>,
    digest: [u8; 32],
    mac: [u8; 32],
}

#[derive(Clone, Debug)]
struct PendingApproval {
    request_digest: [u8; 32],
    target_host_id: HostId,
    expires_at_ms: u64,
    used: bool,
}

#[derive(Debug)]
pub struct PolicyEngine {
    rules: Vec<PolicyRule>,
    approvals: HashMap<String, PendingApproval>,
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            approvals: HashMap::new(),
        }
    }

    pub fn with_rules(rules: Vec<PolicyRule>) -> Result<Self, PolicyConfigurationError> {
        validate_rule_set(&rules, false)?;
        Ok(Self {
            rules,
            approvals: HashMap::new(),
        })
    }

    pub fn add_verified_managed_rules(
        &mut self,
        authority: &PolicyTrustAuthority,
        bundle: VerifiedManagedPolicyBundle,
    ) -> Result<(), PolicyConfigurationError> {
        if !authority.verifies_bundle(&bundle) {
            return Err(PolicyConfigurationError::ManagedOriginRequiresVerification);
        }
        validate_rule_set(&bundle.rules, true)?;
        if self.rules.len().saturating_add(bundle.rules.len()) > MAX_POLICY_RULES {
            return Err(PolicyConfigurationError::RuleLimitExceeded);
        }
        let existing: HashSet<_> = self.rules.iter().map(|rule| &rule.id).collect();
        if bundle.rules.iter().any(|rule| existing.contains(&rule.id)) {
            return Err(PolicyConfigurationError::DuplicateRuleId);
        }
        self.rules.extend(bundle.rules);
        Ok(())
    }

    pub fn rules(&self) -> &[PolicyRule] {
        &self.rules
    }

    pub fn evaluate(
        &self,
        request: &AccessRequest,
        now_ms: u64,
    ) -> Result<PolicyDecision, PolicyError> {
        validate_request(request)?;
        let matching: Vec<&PolicyRule> = self
            .rules
            .iter()
            .filter(|rule| rule_matches(rule, request, now_ms))
            .collect();

        if let Some(rule) = select_rule(&matching, PolicyEffect::Deny) {
            return Ok(PolicyDecision::Denied {
                rule_id: rule.id.clone(),
            });
        }

        if is_high_risk(request) {
            let managed: Vec<_> = matching
                .iter()
                .copied()
                .filter(|rule| rule.origin == PolicyOrigin::Managed)
                .collect();
            if let Some(rule) = select_rule(&managed, PolicyEffect::Allow) {
                return Ok(PolicyDecision::Allowed {
                    rule_id: rule.id.clone(),
                });
            }
            return Ok(PolicyDecision::ApprovalRequired {
                reason: "fresh_target_confirmation".to_owned(),
            });
        }

        let allow = select_rule(&matching, PolicyEffect::Allow);
        Ok(match allow {
            Some(rule) => PolicyDecision::Allowed {
                rule_id: rule.id.clone(),
            },
            None => PolicyDecision::ApprovalRequired {
                reason: "no_matching_rule".to_owned(),
            },
        })
    }

    pub fn create_approval(
        &mut self,
        request: &AccessRequest,
        now_ms: u64,
        lifetime_ms: u64,
    ) -> Result<ApprovalChallenge, ApprovalError> {
        validate_request(request).map_err(|_| ApprovalError::InvalidRequest)?;
        if lifetime_ms == 0 {
            return Err(ApprovalError::InvalidLifetime);
        }
        self.approvals
            .retain(|_, approval| !approval.used && approval.expires_at_ms > now_ms);
        if self.approvals.len() >= MAX_PENDING_APPROVALS {
            return Err(ApprovalError::ApprovalLimitExceeded);
        }
        let expires_at_ms = now_ms.saturating_add(lifetime_ms.min(MAX_APPROVAL_LIFETIME_MS));
        let mut nonce = None;
        for _ in 0..NONCE_GENERATION_ATTEMPTS {
            let mut bytes = [0_u8; 32];
            rand::thread_rng().fill_bytes(&mut bytes);
            let candidate = hex(&bytes);
            let rule_id = generated_rule_id(&candidate);
            if !self.approvals.contains_key(&candidate)
                && self
                    .approvals
                    .keys()
                    .all(|pending_nonce| generated_rule_id(pending_nonce) != rule_id)
                && self.rules.iter().all(|rule| rule.id != rule_id)
            {
                nonce = Some(candidate);
                break;
            }
        }
        let nonce = nonce.ok_or(ApprovalError::NonceGenerationFailed)?;
        self.approvals.insert(
            nonce.clone(),
            PendingApproval {
                request_digest: request_digest(request),
                target_host_id: request.target_host_id.clone(),
                expires_at_ms,
                used: false,
            },
        );
        Ok(ApprovalChallenge {
            nonce,
            expires_at_ms,
        })
    }

    pub fn decide(
        &mut self,
        authority: &PolicyTrustAuthority,
        nonce: &str,
        session: &AuthenticatedTargetSession,
        request: &AccessRequest,
        decision: ApprovalDecision,
        now_ms: u64,
    ) -> Result<ApprovalOutcome, ApprovalError> {
        validate_request(request).map_err(|_| ApprovalError::InvalidRequest)?;
        if !authority.verifies_session(session) {
            return Err(ApprovalError::UnauthenticatedTargetSession);
        }
        let pending = self
            .approvals
            .get_mut(nonce)
            .ok_or(ApprovalError::UnknownNonce)?;
        if pending.used {
            return Err(ApprovalError::AlreadyUsed);
        }
        if now_ms >= pending.expires_at_ms {
            return Err(ApprovalError::Expired);
        }
        if session.target_host_id != pending.target_host_id {
            return Err(ApprovalError::WrongTarget);
        }
        if request_digest(request) != pending.request_digest {
            return Err(ApprovalError::RequestMismatch);
        }

        let creates_rule = matches!(
            decision,
            ApprovalDecision::AllowAndRemember | ApprovalDecision::DenyAndBlock
        );
        if creates_rule && self.rules.len() >= MAX_POLICY_RULES {
            return Err(ApprovalError::RuleLimitExceeded);
        }
        pending.used = true;
        let created_rule = match decision {
            ApprovalDecision::AllowAndRemember => Some(exact_rule(
                request,
                PolicyEffect::Allow,
                next_revision(&self.rules),
                nonce,
            )),
            ApprovalDecision::DenyAndBlock => Some(exact_rule(
                request,
                PolicyEffect::Deny,
                next_revision(&self.rules),
                nonce,
            )),
            ApprovalDecision::AllowOnce | ApprovalDecision::DenyOnce => None,
        };
        if let Some(rule) = &created_rule {
            self.rules.push(rule.clone());
        }
        Ok(ApprovalOutcome {
            decision,
            created_rule,
        })
    }
}

fn validate_request(request: &AccessRequest) -> Result<(), PolicyError> {
    if request.resources.len() > super::model::MAX_COLLECTION_ITEMS {
        return Err(PolicyError::InvalidRequest);
    }
    let unique: HashSet<_> = request.resources.iter().collect();
    if unique.len() != request.resources.len() {
        return Err(PolicyError::InvalidRequest);
    }
    Ok(())
}

fn validate_rule_set(
    rules: &[PolicyRule],
    verified_managed: bool,
) -> Result<(), PolicyConfigurationError> {
    if rules.len() > MAX_POLICY_RULES {
        return Err(PolicyConfigurationError::RuleLimitExceeded);
    }
    let mut ids = HashSet::with_capacity(rules.len());
    for rule in rules {
        rule.validate()
            .map_err(PolicyConfigurationError::InvalidRule)?;
        if !ids.insert(rule.id.clone()) {
            return Err(PolicyConfigurationError::DuplicateRuleId);
        }
        if (rule.origin == PolicyOrigin::Managed) != verified_managed {
            return Err(PolicyConfigurationError::ManagedOriginRequiresVerification);
        }
    }
    Ok(())
}

fn rule_matches(rule: &PolicyRule, request: &AccessRequest, now_ms: u64) -> bool {
    rule.enabled
        && rule.expires_at_ms.is_none_or(|expiry| expiry > now_ms)
        && rule
            .principal_id
            .as_ref()
            .is_none_or(|value| value == &request.principal_id)
        && rule
            .source_host_id
            .as_ref()
            .is_none_or(|value| value == &request.source_host_id)
        && rule
            .target_host_id
            .as_ref()
            .is_none_or(|value| value == &request.target_host_id)
        && if rule.match_device_exact {
            rule.device_id == request.device_id
        } else {
            rule.device_id
                .as_ref()
                .is_none_or(|value| request.device_id.as_ref() == Some(value))
        }
        && rule
            .operation
            .as_ref()
            .is_none_or(|value| value == &request.operation)
        && if rule.match_resources_exact {
            same_resources(&rule.resources, &request.resources)
        } else {
            rule.resources.is_empty() || same_resources(&rule.resources, &request.resources)
        }
        && (!rule.require_user_presence || request.user_present)
        && rule
            .user_presence
            .is_none_or(|value| value == request.user_present)
        && rule
            .physical_device
            .is_none_or(|value| value == request.physical_device)
}

fn same_resources(left: &[ResourceClass], right: &[ResourceClass]) -> bool {
    left.len() == right.len() && left.iter().all(|resource| right.contains(resource))
}

fn select_rule<'a>(rules: &[&'a PolicyRule], effect: PolicyEffect) -> Option<&'a PolicyRule> {
    rules
        .iter()
        .copied()
        .filter(|rule| rule.effect == effect)
        .max_by_key(|rule| (specificity(rule), rule.revision, rule.id.as_str()))
}

fn specificity(rule: &PolicyRule) -> u8 {
    u8::from(rule.principal_id.is_some())
        + u8::from(rule.source_host_id.is_some())
        + u8::from(rule.target_host_id.is_some())
        + u8::from(rule.device_id.is_some() || rule.match_device_exact)
        + u8::from(rule.operation.is_some())
        + u8::from(!rule.resources.is_empty() || rule.match_resources_exact)
        + u8::from(rule.require_user_presence || rule.user_presence.is_some())
        + u8::from(rule.physical_device.is_some())
}

fn is_high_risk(request: &AccessRequest) -> bool {
    let operation = request.operation.as_str();
    request.resources.iter().any(|resource| {
        matches!(
            resource,
            ResourceClass::Debugger
                | ResourceClass::Signing
                | ResourceClass::Microphone
                | ResourceClass::ScreenCapture
        )
    }) || operation.starts_with("keychain.")
        || operation.starts_with("devicelane.policy.")
        || operation.starts_with("devicelane.service.")
        || (request.physical_device
            && request
                .resources
                .contains(&ResourceClass::ApplicationInstall))
}

fn request_digest(request: &AccessRequest) -> [u8; 32] {
    let mut canonical = request.clone();
    canonical.resources.sort_unstable();
    canonical.resources.dedup();
    let encoded = serde_json::to_vec(&canonical).expect("typed access request serializes");
    Sha256::digest(encoded).into()
}

fn exact_rule(
    request: &AccessRequest,
    effect: PolicyEffect,
    revision: u64,
    nonce: &str,
) -> PolicyRule {
    let mut resources = request.resources.clone();
    resources.sort_unstable();
    resources.dedup();
    PolicyRule {
        id: generated_rule_id(nonce),
        revision,
        effect,
        principal_id: Some(request.principal_id.clone()),
        source_host_id: Some(request.source_host_id.clone()),
        target_host_id: Some(request.target_host_id.clone()),
        device_id: request.device_id.clone(),
        operation: Some(request.operation.clone()),
        resources,
        expires_at_ms: None,
        require_user_presence: false,
        user_presence: Some(request.user_present),
        physical_device: Some(request.physical_device),
        match_device_exact: true,
        match_resources_exact: true,
        enabled: true,
        origin: PolicyOrigin::User,
    }
}

fn generated_rule_id(nonce: &str) -> RuleId {
    RuleId::parse(format!("approval-{}", &nonce[..32])).expect("nonce creates valid 128-bit id")
}

fn next_revision(rules: &[PolicyRule]) -> u64 {
    rules
        .iter()
        .map(|rule| rule.revision)
        .max()
        .unwrap_or(0)
        .saturating_add(1)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(DIGITS[(byte >> 4) as usize] as char);
        encoded.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn trust_mac(secret: &[u8; 32], domain: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(secret);
    digest.update(domain);
    digest.update((payload.len() as u64).to_be_bytes());
    digest.update(payload);
    digest.finalize().into()
}

fn rules_digest(rules: &[PolicyRule]) -> Result<[u8; 32], TrustError> {
    let mut canonical = rules.to_vec();
    canonical.sort_by(|left, right| left.id.cmp(&right.id));
    for rule in &mut canonical {
        rule.resources.sort_unstable();
        rule.resources.dedup();
    }
    let encoded =
        serde_json::to_vec(&canonical).map_err(|_| TrustError::ManagedPolicyVerificationFailed)?;
    Ok(Sha256::digest(encoded).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 5_000;

    struct AllowManaged;

    impl ManagedPolicyVerifier for AllowManaged {
        fn verify(&self, _rules_digest: &[u8; 32]) -> bool {
            true
        }
    }

    fn authority() -> PolicyTrustAuthority {
        PolicyTrustAuthority::new(Box::new(AllowManaged))
    }

    fn target_session(
        authority: &PolicyTrustAuthority,
        host_id: &HostId,
    ) -> AuthenticatedTargetSession {
        let transport = TransportAuthentication::new(host_id.clone());
        authority.issue_target_session(&transport, host_id).unwrap()
    }

    #[test]
    fn request_target_cannot_issue_capability_without_matching_transport_identity() {
        let authority = authority();
        let transport = TransportAuthentication::new(HostId::parse("source").unwrap());
        assert!(matches!(
            authority.issue_target_session(&transport, &HostId::parse("target").unwrap()),
            Err(TrustError::TransportTargetMismatch)
        ));
    }

    fn request(resources: Vec<ResourceClass>) -> AccessRequest {
        AccessRequest {
            activity_id: ActivityId::parse("activity").unwrap(),
            principal_id: PrincipalId::parse("principal").unwrap(),
            source_host_id: HostId::parse("source").unwrap(),
            target_host_id: HostId::parse("target").unwrap(),
            device_id: None,
            operation: OperationId::parse("workspace.write").unwrap(),
            resources,
            physical_device: false,
            user_present: false,
        }
    }

    fn managed_rule() -> PolicyRule {
        PolicyRule {
            id: RuleId::parse("managed-rule").unwrap(),
            revision: 1,
            effect: PolicyEffect::Allow,
            principal_id: None,
            source_host_id: None,
            target_host_id: Some(HostId::parse("target").unwrap()),
            device_id: None,
            operation: Some(OperationId::parse("debug.attach").unwrap()),
            resources: vec![ResourceClass::Debugger],
            expires_at_ms: None,
            require_user_presence: false,
            user_presence: None,
            physical_device: None,
            match_device_exact: false,
            match_resources_exact: true,
            enabled: true,
            origin: PolicyOrigin::Managed,
        }
    }

    #[test]
    fn only_authenticated_target_session_can_decide_and_nonce_is_one_use() {
        let authority = authority();
        let req = request(vec![ResourceClass::WorkspaceWrite]);
        let mut engine = PolicyEngine::new();
        let approval = engine.create_approval(&req, NOW, 100).unwrap();
        let source = target_session(&authority, &req.source_host_id);
        assert_eq!(
            engine.decide(
                &authority,
                &approval.nonce,
                &source,
                &req,
                ApprovalDecision::AllowOnce,
                NOW + 1,
            ),
            Err(ApprovalError::WrongTarget)
        );
        let other_authority = PolicyTrustAuthority::new(Box::new(AllowManaged));
        let foreign_target = target_session(&other_authority, &req.target_host_id);
        assert_eq!(
            engine.decide(
                &authority,
                &approval.nonce,
                &foreign_target,
                &req,
                ApprovalDecision::AllowOnce,
                NOW + 1,
            ),
            Err(ApprovalError::UnauthenticatedTargetSession)
        );
        let target = target_session(&authority, &req.target_host_id);
        assert!(
            engine
                .decide(
                    &authority,
                    &approval.nonce,
                    &target,
                    &req,
                    ApprovalDecision::AllowOnce,
                    NOW + 1,
                )
                .is_ok()
        );
        assert_eq!(
            engine.decide(
                &authority,
                &approval.nonce,
                &target,
                &req,
                ApprovalDecision::AllowOnce,
                NOW + 2,
            ),
            Err(ApprovalError::AlreadyUsed)
        );
    }

    #[test]
    fn canonical_resource_order_is_bound_to_the_same_approval_digest() {
        let authority = authority();
        let req = request(vec![
            ResourceClass::WorkspaceWrite,
            ResourceClass::WorkspaceRead,
        ]);
        let mut reordered = req.clone();
        reordered.resources.reverse();
        let mut engine = PolicyEngine::new();
        let approval = engine.create_approval(&req, NOW, 100).unwrap();
        let target = target_session(&authority, &req.target_host_id);
        assert!(
            engine
                .decide(
                    &authority,
                    &approval.nonce,
                    &target,
                    &reordered,
                    ApprovalDecision::AllowOnce,
                    NOW + 1,
                )
                .is_ok()
        );
    }

    #[test]
    fn remembered_rule_binds_absent_device_empty_resources_and_uses_unique_128_bit_ids() {
        let authority = authority();
        let req = request(vec![]);
        let target = target_session(&authority, &req.target_host_id);
        let mut engine = PolicyEngine::new();
        let mut ids = HashSet::new();
        for index in 0..32 {
            let mut distinct = req.clone();
            distinct.activity_id = ActivityId::parse(format!("activity-{index}")).unwrap();
            let approval = engine.create_approval(&distinct, NOW, 100).unwrap();
            let rule = engine
                .decide(
                    &authority,
                    &approval.nonce,
                    &target,
                    &distinct,
                    ApprovalDecision::AllowAndRemember,
                    NOW + 1,
                )
                .unwrap()
                .created_rule
                .unwrap();
            assert!(rule.match_device_exact);
            assert!(rule.match_resources_exact);
            assert!(rule.id.as_str().strip_prefix("approval-").unwrap().len() >= 32);
            assert!(ids.insert(rule.id));
        }
        let mut with_device = req.clone();
        with_device.device_id = Some(DeviceId::parse("phone").unwrap());
        assert!(matches!(
            engine.evaluate(&with_device, NOW + 2).unwrap(),
            PolicyDecision::ApprovalRequired { .. }
        ));
        let mut with_resource = req;
        with_resource.resources = vec![ResourceClass::WorkspaceRead];
        assert!(matches!(
            engine.evaluate(&with_resource, NOW + 2).unwrap(),
            PolicyDecision::ApprovalRequired { .. }
        ));
    }

    #[test]
    fn blocking_rule_binds_absent_device_and_empty_resources_exactly() {
        let authority = authority();
        let req = request(vec![]);
        let target = target_session(&authority, &req.target_host_id);
        let mut engine = PolicyEngine::new();
        let approval = engine.create_approval(&req, NOW, 100).unwrap();
        let block = engine
            .decide(
                &authority,
                &approval.nonce,
                &target,
                &req,
                ApprovalDecision::DenyAndBlock,
                NOW + 1,
            )
            .unwrap()
            .created_rule
            .unwrap();
        assert!(block.match_device_exact);
        assert!(block.match_resources_exact);

        let mut with_device = req.clone();
        with_device.device_id = Some(DeviceId::parse("phone").unwrap());
        assert!(matches!(
            engine.evaluate(&with_device, NOW + 2).unwrap(),
            PolicyDecision::ApprovalRequired { .. }
        ));
        let mut with_resource = req;
        with_resource.resources = vec![ResourceClass::WorkspaceRead];
        assert!(matches!(
            engine.evaluate(&with_resource, NOW + 2).unwrap(),
            PolicyDecision::ApprovalRequired { .. }
        ));
    }

    #[test]
    fn verified_managed_bundle_is_the_only_high_risk_bypass() {
        let authority = authority();
        let rule = managed_rule();
        let mut user_allow = rule.clone();
        user_allow.id = RuleId::parse("specific-user-allow").unwrap();
        user_allow.origin = PolicyOrigin::User;
        user_allow.principal_id = Some(PrincipalId::parse("principal").unwrap());
        let bundle = authority.verify_managed_rules(vec![rule.clone()]).unwrap();
        let mut engine = PolicyEngine::with_rules(vec![user_allow]).unwrap();
        engine
            .add_verified_managed_rules(&authority, bundle)
            .unwrap();
        let mut req = request(vec![ResourceClass::Debugger]);
        req.operation = OperationId::parse("debug.attach").unwrap();
        assert_eq!(
            engine.evaluate(&req, NOW).unwrap(),
            PolicyDecision::Allowed { rule_id: rule.id }
        );

        let mut user_deny = managed_rule();
        user_deny.id = RuleId::parse("user-deny").unwrap();
        user_deny.origin = PolicyOrigin::User;
        user_deny.effect = PolicyEffect::Deny;
        let managed = managed_rule();
        let bundle = authority.verify_managed_rules(vec![managed]).unwrap();
        let mut denied = PolicyEngine::with_rules(vec![user_deny.clone()]).unwrap();
        denied
            .add_verified_managed_rules(&authority, bundle)
            .unwrap();
        assert_eq!(
            denied.evaluate(&req, NOW).unwrap(),
            PolicyDecision::Denied {
                rule_id: user_deny.id
            }
        );
    }

    #[test]
    fn approval_expires_at_boundary() {
        let authority = authority();
        let req = request(vec![]);
        let target = target_session(&authority, &req.target_host_id);
        let mut engine = PolicyEngine::new();
        let approval = engine.create_approval(&req, NOW, 10).unwrap();
        assert_eq!(
            engine.decide(
                &authority,
                &approval.nonce,
                &target,
                &req,
                ApprovalDecision::DenyOnce,
                NOW + 10,
            ),
            Err(ApprovalError::Expired)
        );
    }

    #[test]
    fn remembered_decision_cannot_overflow_rule_bound_or_consume_nonce() {
        let authority = authority();
        let rules = (0..MAX_POLICY_RULES)
            .map(|index| {
                let mut rule = managed_rule();
                rule.id = RuleId::parse(format!("user-rule-{index}")).unwrap();
                rule.origin = PolicyOrigin::User;
                rule
            })
            .collect();
        let mut engine = PolicyEngine::with_rules(rules).unwrap();
        let req = request(vec![]);
        let target = target_session(&authority, &req.target_host_id);
        let approval = engine.create_approval(&req, NOW, 100).unwrap();
        assert_eq!(
            engine.decide(
                &authority,
                &approval.nonce,
                &target,
                &req,
                ApprovalDecision::AllowAndRemember,
                NOW + 1,
            ),
            Err(ApprovalError::RuleLimitExceeded)
        );
        assert!(
            engine
                .decide(
                    &authority,
                    &approval.nonce,
                    &target,
                    &req,
                    ApprovalDecision::AllowOnce,
                    NOW + 2,
                )
                .is_ok()
        );
    }
}
