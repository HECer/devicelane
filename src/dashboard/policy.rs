use super::managed_policy::VerifiedManagedPolicyBundle;
use super::model::{
    ActivityId, ApprovalDecision, DeviceId, HostId, OperationId, PolicyEffect, PolicyOrigin,
    PolicyRule, PrincipalId, ResourceClass, RuleId, ValidationError,
};
use crate::local_ipc::AuthenticatedTargetSession;
use crate::remote_apple_protocol::AppleOperation;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

const MAX_APPROVAL_LIFETIME_MS: u64 = 5 * 60 * 1_000;
pub const MAX_POLICY_RULES: usize = super::model::MAX_COLLECTION_ITEMS;
pub const MAX_PENDING_APPROVALS: usize = super::model::MAX_COLLECTION_ITEMS;
const NONCE_GENERATION_ATTEMPTS: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteOperationGrant {
    pub request_id: String,
    pub workspace_path: String,
    pub device_id: Option<DeviceId>,
    pub operation: AppleOperation,
    canonical_sha256: String,
}

#[derive(Serialize)]
struct RemoteOperationEnvelope<'a> {
    request_id: &'a str,
    workspace_path: &'a str,
    device_id: &'a Option<DeviceId>,
    operation: &'a AppleOperation,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RemoteOperationGrantWire {
    request_id: String,
    workspace_path: String,
    device_id: Option<DeviceId>,
    operation: AppleOperation,
    canonical_sha256: String,
}

impl RemoteOperationGrant {
    pub fn new(
        request_id: impl Into<String>,
        workspace_path: impl Into<String>,
        device_id: Option<DeviceId>,
        operation: AppleOperation,
    ) -> Result<Self, PolicyError> {
        let mut grant = Self {
            request_id: request_id.into(),
            workspace_path: workspace_path.into(),
            device_id,
            operation,
            canonical_sha256: String::new(),
        };
        grant.validate_fields()?;
        grant.canonical_sha256 = grant.compute_digest();
        Ok(grant)
    }

    pub fn canonical_sha256(&self) -> &str {
        &self.canonical_sha256
    }

    fn validate(&self) -> Result<(), PolicyError> {
        self.validate_fields()?;
        (self.canonical_sha256 == self.compute_digest())
            .then_some(())
            .ok_or(PolicyError::InvalidRequest)
    }

    fn validate_fields(&self) -> Result<(), PolicyError> {
        if self.request_id.is_empty()
            || self.request_id.len() > 128
            || !self
                .request_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
            || !valid_relative_remote_path(&self.workspace_path)
            || self.operation.requires_device() != self.device_id.is_some()
        {
            return Err(PolicyError::InvalidRequest);
        }
        Ok(())
    }

    fn compute_digest(&self) -> String {
        let encoded = serde_json::to_vec(&RemoteOperationEnvelope {
            request_id: &self.request_id,
            workspace_path: &self.workspace_path,
            device_id: &self.device_id,
            operation: &self.operation,
        })
        .expect("typed remote operation serializes");
        hex(&Sha256::digest(encoded))
    }
}

impl Serialize for RemoteOperationGrant {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.validate().map_err(serde::ser::Error::custom)?;
        RemoteOperationGrantWire {
            request_id: self.request_id.clone(),
            workspace_path: self.workspace_path.clone(),
            device_id: self.device_id.clone(),
            operation: self.operation.clone(),
            canonical_sha256: self.canonical_sha256.clone(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for RemoteOperationGrant {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = RemoteOperationGrantWire::deserialize(deserializer)?;
        let grant = Self {
            request_id: wire.request_id,
            workspace_path: wire.workspace_path,
            device_id: wire.device_id,
            operation: wire.operation,
            canonical_sha256: wire.canonical_sha256,
        };
        grant.validate().map_err(serde::de::Error::custom)?;
        Ok(grant)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessRequest {
    pub activity_id: ActivityId,
    pub principal_id: PrincipalId,
    pub source_host_id: HostId,
    pub target_host_id: HostId,
    pub device_id: Option<DeviceId>,
    pub operation: OperationId,
    pub resources: Vec<ResourceClass>,
    pub remote_operation: Option<RemoteOperationGrant>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    remote_operation: Option<RemoteOperationGrant>,
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
            remote_operation: value.remote_operation.clone(),
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
            remote_operation: value.remote_operation,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingApproval {
    request_digest: [u8; 32],
    target_host_id: HostId,
    expires_at_ms: u64,
    used: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
        bundle: VerifiedManagedPolicyBundle,
    ) -> Result<(), PolicyConfigurationError> {
        let rules = bundle.into_rules();
        validate_rule_set(&rules, true)?;
        if self.rules.len().saturating_add(rules.len()) > MAX_POLICY_RULES {
            return Err(PolicyConfigurationError::RuleLimitExceeded);
        }
        let existing: HashSet<_> = self.rules.iter().map(|rule| &rule.id).collect();
        if rules.iter().any(|rule| existing.contains(&rule.id)) {
            return Err(PolicyConfigurationError::DuplicateRuleId);
        }
        self.rules.extend(rules);
        Ok(())
    }

    pub fn rules(&self) -> &[PolicyRule] {
        &self.rules
    }

    pub(crate) fn is_verified_managed_rule(&self, id: &RuleId) -> bool {
        self.rules
            .iter()
            .any(|rule| &rule.id == id && rule.origin == PolicyOrigin::Managed)
    }

    pub(crate) fn validate_restored(&self) -> Result<(), PolicyConfigurationError> {
        validate_mixed_rule_set(&self.rules)?;
        if self.approvals.len() > MAX_PENDING_APPROVALS {
            return Err(PolicyConfigurationError::RuleLimitExceeded);
        }
        Ok(())
    }

    pub(crate) fn restore_checkpoint(
        &mut self,
        checkpoint: PolicyEngine,
    ) -> Result<(), PolicyConfigurationError> {
        checkpoint.validate_restored()?;
        let trusted_managed: Vec<_> = self
            .rules
            .iter()
            .filter(|rule| rule.origin == PolicyOrigin::Managed)
            .cloned()
            .collect();
        let checkpoint_managed: Vec<_> = checkpoint
            .rules
            .iter()
            .filter(|rule| rule.origin == PolicyOrigin::Managed)
            .cloned()
            .collect();
        if checkpoint_managed.len() != trusted_managed.len()
            || checkpoint_managed
                .iter()
                .any(|rule| !trusted_managed.contains(rule))
        {
            return Err(PolicyConfigurationError::ManagedOriginRequiresVerification);
        }
        let mut restored_rules: Vec<_> = checkpoint
            .rules
            .into_iter()
            .filter(|rule| rule.origin == PolicyOrigin::User)
            .collect();
        validate_rule_set(&restored_rules, false)?;
        restored_rules.extend(trusted_managed);
        validate_mixed_rule_set(&restored_rules)?;
        self.rules = restored_rules;
        self.approvals = checkpoint.approvals;
        Ok(())
    }

    pub fn put_user_rule(&mut self, rule: PolicyRule) -> Result<(), PolicyConfigurationError> {
        rule.validate()
            .map_err(PolicyConfigurationError::InvalidRule)?;
        if rule.origin != PolicyOrigin::User {
            return Err(PolicyConfigurationError::ManagedOriginRequiresVerification);
        }
        if let Some(existing) = self.rules.iter_mut().find(|item| item.id == rule.id) {
            if existing.origin == PolicyOrigin::Managed || rule.revision <= existing.revision {
                return Err(PolicyConfigurationError::ManagedOriginRequiresVerification);
            }
            *existing = rule;
            return Ok(());
        }
        if self.rules.len() >= MAX_POLICY_RULES {
            return Err(PolicyConfigurationError::RuleLimitExceeded);
        }
        self.rules.push(rule);
        Ok(())
    }

    pub fn delete_user_rule(&mut self, id: &RuleId) -> Result<bool, PolicyConfigurationError> {
        if self
            .rules
            .iter()
            .any(|rule| &rule.id == id && rule.origin == PolicyOrigin::Managed)
        {
            return Err(PolicyConfigurationError::ManagedOriginRequiresVerification);
        }
        let before = self.rules.len();
        self.rules.retain(|rule| &rule.id != id);
        Ok(before != self.rules.len())
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
        nonce: &str,
        session: &AuthenticatedTargetSession,
        request: &AccessRequest,
        decision: ApprovalDecision,
        now_ms: u64,
    ) -> Result<ApprovalOutcome, ApprovalError> {
        validate_request(request).map_err(|_| ApprovalError::InvalidRequest)?;
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
        if session.local_host_id() != &pending.target_host_id {
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
    if let Some(remote) = &request.remote_operation {
        remote.validate()?;
        let expected_operation = match remote.operation {
            AppleOperation::InstallApp { .. } => "apple.install_app",
            AppleOperation::LaunchApp { .. } => "apple.launch_app",
            AppleOperation::ReadAppLogs { .. } => "apple.read_app_logs",
            AppleOperation::BuildApp { .. } => "apple.build_app",
            AppleOperation::RunXcTest { .. } => "apple.run_xctest",
            AppleOperation::HardwareGate { .. } => "apple.hardware_gate",
            AppleOperation::Discovery => "apple.discovery",
            AppleOperation::PhysicalDevice => "apple.physical_device",
            AppleOperation::Diagnostics => "apple.diagnostics",
            AppleOperation::DiscoverProject { .. } => "apple.discover_project",
            AppleOperation::DiscoverSimulator => "apple.discover_simulator",
        };
        if request.operation.as_str() != expected_operation
            || request.device_id != remote.device_id
            || matches!(remote.operation, AppleOperation::InstallApp { .. })
                && (!request.resources.contains(&ResourceClass::WorkspaceRead)
                    || !request.resources.contains(&ResourceClass::DeviceLease)
                    || !request
                        .resources
                        .contains(&ResourceClass::ApplicationInstall))
        {
            return Err(PolicyError::InvalidRequest);
        }
    }
    Ok(())
}

fn valid_relative_remote_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1024
        && !value.starts_with(['/', '\\'])
        && !value.contains('\0')
        && value
            .split(['/', '\\'])
            .all(|part| !part.is_empty() && part != "." && part != "..")
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

fn validate_mixed_rule_set(rules: &[PolicyRule]) -> Result<(), PolicyConfigurationError> {
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

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 5_000;

    fn target_session(host_id: &HostId) -> AuthenticatedTargetSession {
        crate::local_ipc::authenticated_target_session_for_test(host_id.clone())
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
            remote_operation: None,
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
        let req = request(vec![ResourceClass::WorkspaceWrite]);
        let mut engine = PolicyEngine::new();
        let approval = engine.create_approval(&req, NOW, 100).unwrap();
        let source = target_session(&req.source_host_id);
        assert_eq!(
            engine.decide(
                &approval.nonce,
                &source,
                &req,
                ApprovalDecision::AllowOnce,
                NOW + 1,
            ),
            Err(ApprovalError::WrongTarget)
        );
        let target = target_session(&req.target_host_id);
        assert!(
            engine
                .decide(
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
        let req = request(vec![
            ResourceClass::WorkspaceWrite,
            ResourceClass::WorkspaceRead,
        ]);
        let mut reordered = req.clone();
        reordered.resources.reverse();
        let mut engine = PolicyEngine::new();
        let approval = engine.create_approval(&req, NOW, 100).unwrap();
        let target = target_session(&req.target_host_id);
        assert!(
            engine
                .decide(
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
        let req = request(vec![]);
        let target = target_session(&req.target_host_id);
        let mut engine = PolicyEngine::new();
        let mut ids = HashSet::new();
        for index in 0..32 {
            let mut distinct = req.clone();
            distinct.activity_id = ActivityId::parse(format!("activity-{index}")).unwrap();
            let approval = engine.create_approval(&distinct, NOW, 100).unwrap();
            let rule = engine
                .decide(
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
        let req = request(vec![]);
        let target = target_session(&req.target_host_id);
        let mut engine = PolicyEngine::new();
        let approval = engine.create_approval(&req, NOW, 100).unwrap();
        let block = engine
            .decide(
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
    fn approval_expires_at_boundary() {
        let req = request(vec![]);
        let target = target_session(&req.target_host_id);
        let mut engine = PolicyEngine::new();
        let approval = engine.create_approval(&req, NOW, 10).unwrap();
        assert_eq!(
            engine.decide(
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
    fn checkpoint_cannot_forge_managed_origin_without_reverified_rule() {
        let forged = PolicyEngine {
            rules: vec![managed_rule()],
            approvals: HashMap::new(),
        };
        let mut trusted = PolicyEngine::new();
        assert_eq!(
            trusted.restore_checkpoint(forged),
            Err(PolicyConfigurationError::ManagedOriginRequiresVerification)
        );
    }

    #[test]
    fn remembered_decision_cannot_overflow_rule_bound_or_consume_nonce() {
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
        let target = target_session(&req.target_host_id);
        let approval = engine.create_approval(&req, NOW, 100).unwrap();
        assert_eq!(
            engine.decide(
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
