use super::model::{
    ActivityId, ApprovalDecision, DeviceId, HostId, OperationId, PolicyEffect, PolicyOrigin,
    PolicyRule, PrincipalId, ResourceClass, RuleId, ValidationError,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

const MAX_APPROVAL_LIFETIME_MS: u64 = 5 * 60 * 1_000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
}

#[derive(Clone)]
struct PendingApproval {
    request_digest: [u8; 32],
    target_host_id: HostId,
    expires_at_ms: u64,
    used: bool,
}

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

    pub fn with_rules(rules: Vec<PolicyRule>) -> Result<Self, ValidationError> {
        for rule in &rules {
            rule.validate()?;
        }
        Ok(Self {
            rules,
            approvals: HashMap::new(),
        })
    }

    pub fn rules(&self) -> &[PolicyRule] {
        &self.rules
    }

    pub fn evaluate(&self, request: &AccessRequest, now_ms: u64) -> PolicyDecision {
        let matching: Vec<&PolicyRule> = self
            .rules
            .iter()
            .filter(|rule| rule_matches(rule, request, now_ms))
            .collect();

        if let Some(rule) = select_rule(&matching, PolicyEffect::Deny) {
            return PolicyDecision::Denied {
                rule_id: rule.id.clone(),
            };
        }

        let allow = select_rule(&matching, PolicyEffect::Allow);
        if is_high_risk(request) {
            if let Some(rule) = allow.filter(|rule| rule.origin == PolicyOrigin::Managed) {
                return PolicyDecision::Allowed {
                    rule_id: rule.id.clone(),
                };
            }
            return PolicyDecision::ApprovalRequired {
                reason: "fresh_target_confirmation".to_owned(),
            };
        }

        match allow {
            Some(rule) => PolicyDecision::Allowed {
                rule_id: rule.id.clone(),
            },
            None => PolicyDecision::ApprovalRequired {
                reason: "no_matching_rule".to_owned(),
            },
        }
    }

    pub fn create_approval(
        &mut self,
        request: &AccessRequest,
        now_ms: u64,
        lifetime_ms: u64,
    ) -> Result<ApprovalChallenge, ApprovalError> {
        validate_request(request)?;
        if lifetime_ms == 0 {
            return Err(ApprovalError::InvalidLifetime);
        }
        let expires_at_ms = now_ms.saturating_add(lifetime_ms.min(MAX_APPROVAL_LIFETIME_MS));
        let nonce = loop {
            let mut bytes = [0_u8; 32];
            rand::thread_rng().fill_bytes(&mut bytes);
            let candidate = hex(&bytes);
            if !self.approvals.contains_key(&candidate) {
                break candidate;
            }
        };
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
        deciding_host_id: &HostId,
        request: &AccessRequest,
        decision: ApprovalDecision,
        now_ms: u64,
    ) -> Result<ApprovalOutcome, ApprovalError> {
        validate_request(request)?;
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
        if deciding_host_id != &pending.target_host_id {
            return Err(ApprovalError::WrongTarget);
        }
        if request_digest(request) != pending.request_digest {
            return Err(ApprovalError::RequestMismatch);
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

fn validate_request(request: &AccessRequest) -> Result<(), ApprovalError> {
    if request.resources.len() > super::model::MAX_COLLECTION_ITEMS {
        return Err(ApprovalError::InvalidRequest);
    }
    let unique: HashSet<_> = request.resources.iter().collect();
    if unique.len() != request.resources.len() {
        return Err(ApprovalError::InvalidRequest);
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
        && rule
            .device_id
            .as_ref()
            .is_none_or(|value| request.device_id.as_ref() == Some(value))
        && rule
            .operation
            .as_ref()
            .is_none_or(|value| value == &request.operation)
        && (rule.resources.is_empty() || same_resources(&rule.resources, &request.resources))
        && rule
            .require_user_presence
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
        + u8::from(rule.device_id.is_some())
        + u8::from(rule.operation.is_some())
        + u8::from(!rule.resources.is_empty())
        + u8::from(rule.require_user_presence.is_some())
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
    let encoded = serde_json::to_vec(request).expect("typed access request serializes");
    Sha256::digest(encoded).into()
}

fn exact_rule(
    request: &AccessRequest,
    effect: PolicyEffect,
    revision: u64,
    nonce: &str,
) -> PolicyRule {
    PolicyRule {
        id: RuleId::parse(format!("approval-{}", &nonce[..16])).expect("nonce creates valid id"),
        revision,
        effect,
        principal_id: Some(request.principal_id.clone()),
        source_host_id: Some(request.source_host_id.clone()),
        target_host_id: Some(request.target_host_id.clone()),
        device_id: request.device_id.clone(),
        operation: Some(request.operation.clone()),
        resources: request.resources.clone(),
        expires_at_ms: None,
        require_user_presence: Some(request.user_present),
        physical_device: Some(request.physical_device),
        enabled: true,
        origin: PolicyOrigin::User,
    }
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
