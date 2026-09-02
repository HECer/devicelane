use super::audit::{
    AuditError, AuditExport, AuditFilter, AuditSigner, AuditStore, RawAuditRecord,
    read_activity_checkpoint, write_activity_checkpoint,
};
use super::event_log::{AcknowledgeError, EventJournal, EventRead, ReadLimit};
use super::policy::{AccessRequest, ApprovalError, PolicyDecision, PolicyEngine};
use super::topology::TopologyProjector;
use super::{
    ActivityEvent, ActivityId, ActivityState, ApprovalDecision, ApprovalId, ApprovalRequest,
    AuditResult, Authorization, CursorPage, DashboardScope, DashboardSnapshot, EventCursor, HostId,
    MetricSnapshot, MetricValue, OperationId, PolicyEffect, PolicyRule, PrincipalId, ResourceClass,
    RuleId, SafeCode, SubscriberId,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExistingJobs {
    Finish,
    Cancel,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DashboardServiceError {
    PermissionDenied,
    ApprovalExpired,
    AuditUnavailable,
    CursorAhead,
    ResyncRequired,
    LimitExceeded,
    InvalidRequest,
    NotFound,
}

impl DashboardServiceError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::PermissionDenied => "permission_denied",
            Self::ApprovalExpired => "approval_expired",
            Self::AuditUnavailable => "audit_unavailable",
            Self::CursorAhead => "cursor_ahead",
            Self::ResyncRequired => "resync_required",
            Self::LimitExceeded => "limit_exceeded",
            Self::InvalidRequest => "invalid_request",
            Self::NotFound => "not_found",
        }
    }
}

struct Pending {
    nonce: String,
    request: ApprovalRequest,
    access: AccessRequest,
}

pub struct DashboardService {
    local_host_id: HostId,
    topology: TopologyProjector,
    events: EventJournal,
    audit: Arc<Mutex<AuditStore>>,
    policy: PolicyEngine,
    pending: BTreeMap<ApprovalId, Pending>,
    activities: HashMap<ActivityId, ActivityEvent>,
    paused: bool,
    next_audit_sequence: u64,
    checkpoint_path: Option<PathBuf>,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivityCheckpoint {
    version: u16,
    audit_sequence: u64,
    activities: Vec<ActivityEvent>,
    digest: String,
}

#[derive(serde::Serialize)]
struct ActivityCheckpointPayload<'a> {
    version: u16,
    audit_sequence: u64,
    activities: &'a [ActivityEvent],
}

impl DashboardService {
    pub fn new(
        local_host_id: HostId,
        topology: TopologyProjector,
        events: EventJournal,
        audit: Arc<Mutex<AuditStore>>,
        policy: PolicyEngine,
    ) -> Self {
        let next_audit_sequence = audit
            .lock()
            .ok()
            .map(|store| store.last_sequence().saturating_add(1))
            .unwrap_or(1);
        Self {
            local_host_id,
            topology,
            events,
            audit,
            policy,
            pending: BTreeMap::new(),
            activities: HashMap::new(),
            paused: false,
            next_audit_sequence,
            checkpoint_path: None,
        }
    }

    pub fn new_persistent(
        local_host_id: HostId,
        topology: TopologyProjector,
        events: EventJournal,
        audit: Arc<Mutex<AuditStore>>,
        policy: PolicyEngine,
    ) -> Result<Self, DashboardServiceError> {
        let (checkpoint_path, audit_sequence) = {
            let store = audit
                .lock()
                .map_err(|_| DashboardServiceError::AuditUnavailable)?;
            (store.activity_checkpoint_path(), store.last_sequence())
        };
        let checkpoint = read_activity_checkpoint(&checkpoint_path)
            .map_err(|_| DashboardServiceError::AuditUnavailable)?
            .map(|bytes| {
                serde_json::from_slice::<ActivityCheckpoint>(&bytes)
                    .map_err(|_| DashboardServiceError::AuditUnavailable)
            })
            .transpose()?;
        let mut service = Self::new(local_host_id, topology, events, audit, policy);
        service.checkpoint_path = Some(checkpoint_path);
        if let Some(checkpoint) = checkpoint {
            if checkpoint.version != 1 || checkpoint.activities.len() > 1_000 {
                return Err(DashboardServiceError::AuditUnavailable);
            }
            if checkpoint.audit_sequence > audit_sequence {
                return Err(DashboardServiceError::AuditUnavailable);
            }
            if checkpoint_digest(checkpoint.audit_sequence, &checkpoint.activities)?
                != checkpoint.digest
            {
                return Err(DashboardServiceError::AuditUnavailable);
            }
            for activity in checkpoint.activities {
                activity
                    .validate()
                    .map_err(|_| DashboardServiceError::AuditUnavailable)?;
                if service.activities.contains_key(&activity.activity_id) {
                    return Err(DashboardServiceError::AuditUnavailable);
                }
                service
                    .events
                    .restore_activity_sequence(activity.activity_id.clone(), activity.sequence)
                    .map_err(|_| DashboardServiceError::AuditUnavailable)?;
                service
                    .activities
                    .insert(activity.activity_id.clone(), activity);
            }
            service.reconcile_after_restart(now_ms())?;
        }
        Ok(service)
    }

    pub fn local_host_id(&self) -> &HostId {
        &self.local_host_id
    }

    pub fn remote_access_paused(&self) -> bool {
        self.paused
    }

    pub fn snapshot(&self, scope: DashboardScope, now_ms: u64) -> DashboardSnapshot {
        let mut snapshot = self.topology.snapshot(now_ms);
        if scope == DashboardScope::Local {
            snapshot.scope = DashboardScope::Local;
            snapshot.hosts.retain(|host| host.id == self.local_host_id);
        }
        snapshot.activities = self.activities.values().map(Into::into).collect();
        snapshot.pending_approvals = self.pending_approvals(now_ms);
        snapshot
    }

    pub fn events(&self, cursor: EventCursor, limit: usize) -> EventRead {
        self.events.expire_idle(now_ms());
        self.events.read(
            cursor,
            ReadLimit {
                max_events: limit,
                ..ReadLimit::default()
            },
        )
    }

    pub fn acknowledge(
        &self,
        subscriber_id: SubscriberId,
        cursor: EventCursor,
        now_ms: u64,
    ) -> Result<(), DashboardServiceError> {
        self.events.expire_idle(now_ms);
        match self.events.subscribe(subscriber_id.clone(), now_ms) {
            Ok(()) | Err(super::event_log::SubscribeError::AlreadyExists) => {}
            Err(super::event_log::SubscribeError::LimitExceeded) => {
                return Err(DashboardServiceError::LimitExceeded);
            }
        }
        self.events
            .acknowledge(&subscriber_id, cursor, now_ms)
            .map_err(|error| match error {
                AcknowledgeError::CursorAhead => DashboardServiceError::CursorAhead,
                AcknowledgeError::ResyncRequired { .. } | AcknowledgeError::WrongEpoch => {
                    DashboardServiceError::ResyncRequired
                }
                AcknowledgeError::UnknownSubscriber => DashboardServiceError::InvalidRequest,
            })
    }

    pub fn pending_approvals(&self, now_ms: u64) -> Vec<ApprovalRequest> {
        self.pending
            .values()
            .filter(|pending| pending.request.expires_at_ms > now_ms)
            .map(|pending| pending.request.clone())
            .collect()
    }

    pub fn request_approval(
        &mut self,
        access: AccessRequest,
        lifetime_ms: u64,
        now_ms: u64,
    ) -> Result<(String, u64), DashboardServiceError> {
        if self.paused || access.target_host_id != self.local_host_id {
            return Err(DashboardServiceError::PermissionDenied);
        }
        match self
            .policy
            .evaluate(&access, now_ms)
            .map_err(|_| DashboardServiceError::InvalidRequest)?
        {
            PolicyDecision::Denied { .. } => {
                self.audit_access(&access, PolicyEffect::Deny, AuditResult::Denied, now_ms)?;
                return Err(DashboardServiceError::PermissionDenied);
            }
            PolicyDecision::Allowed { .. } | PolicyDecision::ApprovalRequired { .. } => {}
        }
        self.audit_access(&access, PolicyEffect::Allow, AuditResult::Attempted, now_ms)?;
        let mut next_policy = self.policy.clone();
        let challenge = match next_policy.create_approval(&access, now_ms, lifetime_ms) {
            Ok(challenge) => challenge,
            Err(error) => {
                self.audit_access(&access, PolicyEffect::Allow, AuditResult::Failed, now_ms)?;
                return Err(map_approval_error(error));
            }
        };
        let id = ApprovalId::parse(format!("approval-{}", &challenge.nonce[..16]))
            .map_err(|_| DashboardServiceError::InvalidRequest)?;
        let pending = Pending {
            nonce: challenge.nonce.clone(),
            request: ApprovalRequest {
                id: id.clone(),
                activity_id: access.activity_id.clone(),
                principal_id: access.principal_id.clone(),
                source_host_id: access.source_host_id.clone(),
                target_host_id: access.target_host_id.clone(),
                device_id: access.device_id.clone(),
                operation: access.operation.clone(),
                resources: access.resources.clone(),
                requested_at_ms: now_ms,
                expires_at_ms: challenge.expires_at_ms,
                risk: super::SafeCode::parse("target_confirmation").expect("constant safe code"),
            },
            access: access.clone(),
        };
        let sequence = self
            .activities
            .get(&access.activity_id)
            .map_or(1, |event| event.sequence.saturating_add(1));
        if let Err(error) = self.record_activity(
            ActivityEvent {
                activity_id: access.activity_id.clone(),
                sequence,
                occurred_at_ms: now_ms,
                principal_id: access.principal_id.clone(),
                source_host_id: access.source_host_id.clone(),
                target_host_id: access.target_host_id.clone(),
                device_id: access.device_id.clone(),
                operation: access.operation.clone(),
                resources: access.resources.clone(),
                authorization: Authorization {
                    effect: PolicyEffect::Allow,
                    rule_id: None,
                    approval_id: Some(id.clone()),
                },
                state: ActivityState::AwaitingApproval,
                message: None,
                metrics: unavailable_metrics(),
                started_at_ms: None,
                finished_at_ms: None,
            },
            &format!("approval-request:{}", challenge.nonce),
        ) {
            self.audit_access(&access, PolicyEffect::Allow, AuditResult::Failed, now_ms)?;
            return Err(error);
        }
        self.policy = next_policy;
        self.pending.insert(id, pending);
        Ok((challenge.nonce, challenge.expires_at_ms))
    }

    pub fn decide_approval(
        &mut self,
        nonce: &str,
        session: &crate::local_ipc::AuthenticatedTargetSession,
        access: &AccessRequest,
        decision: ApprovalDecision,
        now_ms: u64,
    ) -> Result<Option<PolicyRule>, DashboardServiceError> {
        if self.paused {
            return Err(DashboardServiceError::PermissionDenied);
        }
        if matches!(
            self.policy.evaluate(access, now_ms),
            Ok(PolicyDecision::Denied { .. })
        ) {
            self.audit_access(access, PolicyEffect::Deny, AuditResult::Denied, now_ms)?;
            return Err(DashboardServiceError::PermissionDenied);
        }
        let pending_id = self.pending.iter().find_map(|(id, pending)| {
            (pending.nonce == nonce && &pending.access == access).then(|| id.clone())
        });
        let effect = if matches!(
            decision,
            ApprovalDecision::DenyOnce | ApprovalDecision::DenyAndBlock
        ) {
            PolicyEffect::Deny
        } else {
            PolicyEffect::Allow
        };
        self.audit_access(access, effect, AuditResult::Attempted, now_ms)?;
        let mut next_policy = self.policy.clone();
        let outcome = match next_policy.decide(nonce, session, access, decision, now_ms) {
            Ok(outcome) => outcome,
            Err(error) => {
                self.audit_access(access, effect, AuditResult::Failed, now_ms)?;
                return Err(map_approval_error(error));
            }
        };
        let approval_id = pending_id.clone();
        let state = if effect == PolicyEffect::Deny {
            ActivityState::Denied
        } else {
            ActivityState::Queued
        };
        let sequence = self
            .activities
            .get(&access.activity_id)
            .map_or(1, |event| event.sequence.saturating_add(1));
        let terminal = (state == ActivityState::Denied).then_some(now_ms);
        self.record_activity(
            ActivityEvent {
                activity_id: access.activity_id.clone(),
                sequence,
                occurred_at_ms: now_ms,
                principal_id: access.principal_id.clone(),
                source_host_id: access.source_host_id.clone(),
                target_host_id: access.target_host_id.clone(),
                device_id: access.device_id.clone(),
                operation: access.operation.clone(),
                resources: access.resources.clone(),
                authorization: Authorization {
                    effect,
                    rule_id: outcome.created_rule.as_ref().map(|rule| rule.id.clone()),
                    approval_id,
                },
                state,
                message: None,
                metrics: unavailable_metrics(),
                started_at_ms: None,
                finished_at_ms: terminal,
            },
            &format!("approval-decision:{nonce}"),
        )?;
        self.policy = next_policy;
        if let Some(id) = pending_id {
            self.pending.remove(&id);
        }
        Ok(outcome.created_rule)
    }

    pub fn policy_rules(&self) -> Vec<PolicyRule> {
        self.policy.rules().to_vec()
    }

    pub fn put_policy_rule(
        &mut self,
        rule: PolicyRule,
        now_ms: u64,
    ) -> Result<(), DashboardServiceError> {
        self.authorize_admin(
            "devicelane.policy.put",
            ResourceClass::DeviceLanePolicy,
            now_ms,
        )?;
        self.audit_local("policy-put", AuditResult::Attempted, now_ms)?;
        let mut next_policy = self.policy.clone();
        if next_policy.put_user_rule(rule).is_err() {
            self.audit_local("policy-put", AuditResult::Failed, now_ms)?;
            return Err(DashboardServiceError::PermissionDenied);
        }
        self.append_local_event("policy-put", now_ms)?;
        self.policy = next_policy;
        Ok(())
    }

    pub fn delete_policy_rule(
        &mut self,
        id: &RuleId,
        now_ms: u64,
    ) -> Result<bool, DashboardServiceError> {
        self.authorize_admin(
            "devicelane.policy.delete",
            ResourceClass::DeviceLanePolicy,
            now_ms,
        )?;
        self.audit_local("policy-delete", AuditResult::Attempted, now_ms)?;
        let mut next_policy = self.policy.clone();
        let deleted = match next_policy.delete_user_rule(id) {
            Ok(deleted) => deleted,
            Err(_) => {
                self.audit_local("policy-delete", AuditResult::Failed, now_ms)?;
                return Err(DashboardServiceError::PermissionDenied);
            }
        };
        self.append_local_event("policy-delete", now_ms)?;
        self.policy = next_policy;
        Ok(deleted)
    }

    pub fn audit_query(
        &self,
        filter: AuditFilter,
        cursor: Option<EventCursor>,
        limit: usize,
    ) -> Result<CursorPage<super::AuditRecord>, DashboardServiceError> {
        self.audit
            .lock()
            .map_err(|_| DashboardServiceError::AuditUnavailable)?
            .query(filter, cursor, limit)
            .map_err(map_audit_error)
    }

    pub fn audit_export(
        &self,
        filter: AuditFilter,
        signer: Option<&dyn AuditSigner>,
    ) -> Result<AuditExport, DashboardServiceError> {
        self.audit
            .lock()
            .map_err(|_| DashboardServiceError::AuditUnavailable)?
            .export(filter, signer)
            .map_err(map_audit_error)
    }

    pub fn record_activity(
        &mut self,
        event: ActivityEvent,
        idempotency_key: &str,
    ) -> Result<(), DashboardServiceError> {
        self.events
            .preflight_append(idempotency_key, &event)
            .map_err(|_| DashboardServiceError::LimitExceeded)?;
        let mut next = self.activities.clone();
        next.insert(event.activity_id.clone(), event.clone());
        self.persist_activities(&next)?;
        if self.events.append(idempotency_key, event.clone()).is_err() {
            self.persist_activities(&self.activities)?;
            return Err(DashboardServiceError::LimitExceeded);
        }
        self.activities = next;
        Ok(())
    }

    pub fn cancel_activity(
        &mut self,
        id: &ActivityId,
        now_ms: u64,
    ) -> Result<bool, DashboardServiceError> {
        self.authorize_admin(
            "devicelane.activity.cancel",
            ResourceClass::DeviceLaneService,
            now_ms,
        )?;
        let Some(current) = self.activities.get(id).cloned() else {
            return Ok(false);
        };
        if matches!(
            current.state,
            ActivityState::Cancelled
                | ActivityState::Succeeded
                | ActivityState::Failed
                | ActivityState::Denied
        ) {
            return Ok(false);
        }
        self.audit_access_from_event(&current, AuditResult::Cancelled, now_ms)?;
        let mut cancelled = current;
        cancelled.sequence = cancelled.sequence.saturating_add(1);
        cancelled.occurred_at_ms = now_ms;
        cancelled.state = ActivityState::Cancelled;
        cancelled.finished_at_ms = Some(now_ms);
        self.record_activity(cancelled, &format!("cancel:{}", id.as_str()))?;
        Ok(true)
    }

    pub fn reconcile_after_restart(&mut self, now_ms: u64) -> Result<usize, DashboardServiceError> {
        let active: Vec<_> = self
            .activities
            .values()
            .filter(|event| {
                matches!(
                    event.state,
                    ActivityState::AwaitingApproval
                        | ActivityState::Queued
                        | ActivityState::Running
                )
            })
            .cloned()
            .collect();
        for mut event in active.iter().cloned() {
            event.sequence = event.sequence.saturating_add(1);
            event.occurred_at_ms = now_ms;
            event.state = ActivityState::Reconnecting;
            event.started_at_ms.get_or_insert(now_ms);
            event.finished_at_ms = None;
            let key = format!("restart:{}:{}", event.activity_id.as_str(), event.sequence);
            self.record_activity(event, &key)?;
        }
        Ok(active.len())
    }

    pub fn pause(
        &mut self,
        existing: ExistingJobs,
        now_ms: u64,
    ) -> Result<(), DashboardServiceError> {
        self.authorize_admin(
            "devicelane.service.pause",
            ResourceClass::DeviceLaneService,
            now_ms,
        )?;
        self.audit_local("remote-access-pause", AuditResult::Attempted, now_ms)?;
        self.paused = true;
        if existing == ExistingJobs::Cancel {
            let ids: Vec<_> = self.activities.keys().cloned().collect();
            for id in ids {
                if let Err(error) = self.cancel_activity(&id, now_ms) {
                    self.paused = false;
                    self.audit_local("remote-access-pause", AuditResult::Failed, now_ms)?;
                    return Err(error);
                }
            }
        }
        if let Err(error) = self.append_local_event("remote-access-pause", now_ms) {
            self.paused = false;
            self.audit_local("remote-access-pause", AuditResult::Failed, now_ms)?;
            return Err(error);
        }
        Ok(())
    }

    pub fn resume(&mut self, now_ms: u64) -> Result<(), DashboardServiceError> {
        self.authorize_admin(
            "devicelane.service.resume",
            ResourceClass::DeviceLaneService,
            now_ms,
        )?;
        self.audit_local("remote-access-resume", AuditResult::Attempted, now_ms)?;
        self.paused = false;
        if let Err(error) = self.append_local_event("remote-access-resume", now_ms) {
            self.paused = true;
            self.audit_local("remote-access-resume", AuditResult::Failed, now_ms)?;
            return Err(error);
        }
        Ok(())
    }

    fn audit_access(
        &mut self,
        access: &AccessRequest,
        effect: PolicyEffect,
        result: AuditResult,
        now_ms: u64,
    ) -> Result<(), DashboardServiceError> {
        self.append_audit(RawAuditRecord {
            sequence: self.next_audit_sequence,
            occurred_at_ms: now_ms,
            activity_id: Some(access.activity_id.clone()),
            principal_id: access.principal_id.clone(),
            source_host_id: access.source_host_id.clone(),
            target_host_id: access.target_host_id.clone(),
            device_id: access.device_id.clone(),
            operation: access.operation.clone(),
            resources: access.resources.clone(),
            decision: effect,
            result,
            message: None,
            arguments: vec![],
            environment: vec![],
            stdout: None,
            stderr: None,
            workspace_path: None,
            artifact_metadata: vec![],
        })
    }

    fn authorize_admin(
        &mut self,
        operation: &str,
        resource: ResourceClass,
        now_ms: u64,
    ) -> Result<(), DashboardServiceError> {
        let request = AccessRequest {
            activity_id: ActivityId::parse(format!("admin-auth-{}", self.next_audit_sequence))
                .map_err(|_| DashboardServiceError::InvalidRequest)?,
            principal_id: PrincipalId::parse("local-user").expect("constant id"),
            source_host_id: self.local_host_id.clone(),
            target_host_id: self.local_host_id.clone(),
            device_id: None,
            operation: OperationId::parse(operation)
                .map_err(|_| DashboardServiceError::InvalidRequest)?,
            resources: vec![resource],
            physical_device: false,
            user_present: true,
        };
        match self
            .policy
            .evaluate(&request, now_ms)
            .map_err(|_| DashboardServiceError::InvalidRequest)?
        {
            PolicyDecision::Denied { .. } => {
                self.audit_access(&request, PolicyEffect::Deny, AuditResult::Denied, now_ms)?;
                Err(DashboardServiceError::PermissionDenied)
            }
            PolicyDecision::Allowed { .. } | PolicyDecision::ApprovalRequired { .. } => Ok(()),
        }
    }

    fn audit_access_from_event(
        &mut self,
        event: &ActivityEvent,
        result: AuditResult,
        now_ms: u64,
    ) -> Result<(), DashboardServiceError> {
        self.audit_access(
            &AccessRequest {
                activity_id: event.activity_id.clone(),
                principal_id: event.principal_id.clone(),
                source_host_id: event.source_host_id.clone(),
                target_host_id: event.target_host_id.clone(),
                device_id: event.device_id.clone(),
                operation: event.operation.clone(),
                resources: event.resources.clone(),
                physical_device: false,
                user_present: true,
            },
            event.authorization.effect,
            result,
            now_ms,
        )
    }

    fn audit_local(
        &mut self,
        operation: &str,
        result: AuditResult,
        now_ms: u64,
    ) -> Result<(), DashboardServiceError> {
        let principal = PrincipalId::parse("local-user").expect("constant id");
        let host = self.local_host_id.clone();
        self.append_audit(RawAuditRecord {
            sequence: self.next_audit_sequence,
            occurred_at_ms: now_ms,
            activity_id: None,
            principal_id: principal,
            source_host_id: host.clone(),
            target_host_id: host,
            device_id: None,
            operation: OperationId::parse(operation).expect("constant id"),
            resources: vec![],
            decision: PolicyEffect::Allow,
            result,
            message: None,
            arguments: vec![],
            environment: vec![],
            stdout: None,
            stderr: None,
            workspace_path: None,
            artifact_metadata: vec![],
        })
    }

    fn append_audit(&mut self, record: RawAuditRecord) -> Result<(), DashboardServiceError> {
        self.audit
            .lock()
            .map_err(|_| DashboardServiceError::AuditUnavailable)?
            .append(record)
            .map_err(map_audit_error)?;
        self.next_audit_sequence = self
            .next_audit_sequence
            .checked_add(1)
            .ok_or(DashboardServiceError::AuditUnavailable)?;
        Ok(())
    }

    fn persist_activities(
        &self,
        activities: &HashMap<ActivityId, ActivityEvent>,
    ) -> Result<(), DashboardServiceError> {
        let Some(path) = &self.checkpoint_path else {
            return Ok(());
        };
        let mut values: Vec<_> = activities.values().cloned().collect();
        values.sort_by(|left, right| left.activity_id.cmp(&right.activity_id));
        if values.len() > 1_000 {
            return Err(DashboardServiceError::LimitExceeded);
        }
        let audit_sequence = self.next_audit_sequence.saturating_sub(1);
        let checkpoint = ActivityCheckpoint {
            version: 1,
            audit_sequence,
            digest: checkpoint_digest(audit_sequence, &values)?,
            activities: values,
        };
        let bytes =
            serde_json::to_vec(&checkpoint).map_err(|_| DashboardServiceError::AuditUnavailable)?;
        write_activity_checkpoint(path, &bytes).map_err(|_| DashboardServiceError::AuditUnavailable)
    }

    fn append_local_event(
        &mut self,
        operation: &str,
        now_ms: u64,
    ) -> Result<(), DashboardServiceError> {
        let activity_id = ActivityId::parse(format!(
            "admin-{}-{operation}",
            self.next_audit_sequence.saturating_sub(1)
        ))
        .map_err(|_| DashboardServiceError::InvalidRequest)?;
        let host = self.local_host_id.clone();
        self.record_activity(
            ActivityEvent {
                activity_id: activity_id.clone(),
                sequence: 1,
                occurred_at_ms: now_ms,
                principal_id: PrincipalId::parse("local-user").expect("constant id"),
                source_host_id: host.clone(),
                target_host_id: host,
                device_id: None,
                operation: OperationId::parse(operation).expect("constant id"),
                resources: Vec::new(),
                authorization: Authorization {
                    effect: PolicyEffect::Allow,
                    rule_id: None,
                    approval_id: None,
                },
                state: ActivityState::Succeeded,
                message: None,
                metrics: unavailable_metrics(),
                started_at_ms: Some(now_ms),
                finished_at_ms: Some(now_ms),
            },
            &format!("local-mutation:{}:{operation}", activity_id.as_str()),
        )
    }
}

fn checkpoint_digest(
    audit_sequence: u64,
    activities: &[ActivityEvent],
) -> Result<String, DashboardServiceError> {
    let payload = serde_json::to_vec(&ActivityCheckpointPayload {
        version: 1,
        audit_sequence,
        activities,
    })
    .map_err(|_| DashboardServiceError::AuditUnavailable)?;
    Ok(Sha256::digest(payload)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn map_approval_error(error: ApprovalError) -> DashboardServiceError {
    match error {
        ApprovalError::Expired => DashboardServiceError::ApprovalExpired,
        ApprovalError::RuleLimitExceeded | ApprovalError::ApprovalLimitExceeded => {
            DashboardServiceError::LimitExceeded
        }
        _ => DashboardServiceError::PermissionDenied,
    }
}
fn map_audit_error(error: AuditError) -> DashboardServiceError {
    match error {
        AuditError::CursorAhead => DashboardServiceError::CursorAhead,
        AuditError::LimitExceeded | AuditError::FrameTooLarge => {
            DashboardServiceError::LimitExceeded
        }
        _ => DashboardServiceError::AuditUnavailable,
    }
}
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |value| value.as_millis() as u64)
}

fn unavailable_metrics() -> MetricSnapshot {
    let value = || MetricValue::Unavailable {
        reason: SafeCode::parse("observer_unavailable").expect("constant safe code"),
    };
    MetricSnapshot {
        current_memory_bytes: value(),
        peak_memory_bytes: value(),
        cpu_time_ms: value(),
        process_count: value(),
    }
}
