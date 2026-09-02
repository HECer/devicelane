use crate::dashboard::{ActivityEvent, ActivityId, EventCursor, SubscriberId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};

pub const MAX_EVENTS: usize = 1_000;
pub const MAX_EVENT_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_PAGE_EVENTS: usize = 256;
pub const MAX_PAGE_BYTES: usize = 256 * 1024;
pub const MAX_SUBSCRIBERS: usize = 32;
pub const SUBSCRIBER_IDLE_MS: u64 = 15_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadLimit {
    pub max_events: usize,
    pub max_bytes: usize,
}

impl Default for ReadLimit {
    fn default() -> Self {
        Self {
            max_events: MAX_PAGE_EVENTS,
            max_bytes: MAX_PAGE_BYTES,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "result", deny_unknown_fields)]
pub enum EventRead {
    Events {
        events: Vec<ActivityEvent>,
        next_cursor: EventCursor,
    },
    CursorAhead {
        newest_available: EventCursor,
    },
    ResyncRequired {
        oldest_available: EventCursor,
        snapshot_revision: u64,
    },
    LimitExceeded,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AppendOutcome {
    Appended,
    DuplicateCollapsed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AppendError {
    InvalidEvent(String),
    EmptyIdempotencyKey,
    IdempotencyKeyTooLong,
    IdempotencyConflict,
    NonMonotonicSequence {
        expected: u64,
    },
    SequenceOverflow,
    EpochOverflow,
    LimitExceeded {
        serialized_bytes: usize,
        maximum_bytes: usize,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AppendTransactionError<E> {
    Append(AppendError),
    Precommit(E),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SubscribeError {
    AlreadyExists,
    LimitExceeded,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AcknowledgeError {
    UnknownSubscriber,
    CursorAhead,
    WrongEpoch,
    ResyncRequired {
        oldest_available: EventCursor,
        snapshot_revision: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RotateError {
    EpochNotIncreasing,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JournalStats {
    pub epoch: u64,
    pub events: usize,
    pub serialized_bytes: usize,
    pub oldest_sequence: Option<u64>,
    pub newest_sequence: u64,
    pub subscribers: usize,
    pub idempotency_entries: usize,
    pub activity_entries: usize,
}

#[derive(Clone)]
pub struct EventJournal {
    inner: Arc<Mutex<Inner>>,
}

struct Inner {
    epoch: u64,
    snapshot_revision: u64,
    next_cursor_sequence: u64,
    events: VecDeque<StoredEvent>,
    serialized_bytes: usize,
    idempotency: HashMap<String, IdempotencyRecord>,
    activity_sequences: HashMap<ActivityId, u64>,
    subscribers: HashMap<SubscriberId, Subscriber>,
    max_events: usize,
    max_bytes: usize,
}

struct StoredEvent {
    cursor_sequence: u64,
    event: ActivityEvent,
    serialized_bytes: usize,
    idempotency_key: String,
}

struct IdempotencyRecord {
    event_digest: [u8; 32],
}
struct Subscriber {
    acknowledged: EventCursor,
    last_active_ms: u64,
}

impl EventJournal {
    pub fn new(epoch: u64, snapshot_revision: u64) -> Self {
        Self::with_bounds(epoch, snapshot_revision, MAX_EVENTS, MAX_EVENT_BYTES)
    }

    pub fn with_bounds(
        epoch: u64,
        snapshot_revision: u64,
        max_events: usize,
        max_bytes: usize,
    ) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                epoch,
                snapshot_revision,
                next_cursor_sequence: 1,
                events: VecDeque::new(),
                serialized_bytes: 0,
                idempotency: HashMap::new(),
                activity_sequences: HashMap::new(),
                subscribers: HashMap::new(),
                max_events: max_events.min(MAX_EVENTS),
                max_bytes: max_bytes.min(MAX_EVENT_BYTES),
            })),
        }
    }

    pub fn append(
        &self,
        idempotency_key: impl Into<String>,
        event: ActivityEvent,
    ) -> Result<AppendOutcome, AppendError> {
        self.append_with_precommit(idempotency_key, event, || {
            Ok::<_, std::convert::Infallible>(())
        })
        .map_err(|error| match error {
            AppendTransactionError::Append(error) => error,
            AppendTransactionError::Precommit(never) => match never {},
        })
    }

    /// Atomically reserves the journal position, runs durable precommit work, and only then
    /// publishes the event. Other `EventJournal` clones cannot interleave an append.
    pub fn append_with_precommit<E>(
        &self,
        idempotency_key: impl Into<String>,
        event: ActivityEvent,
        precommit: impl FnOnce() -> Result<(), E>,
    ) -> Result<AppendOutcome, AppendTransactionError<E>> {
        event.validate().map_err(|error| {
            AppendTransactionError::Append(AppendError::InvalidEvent(error.code().to_owned()))
        })?;
        let key = idempotency_key.into();
        if key.trim().is_empty() {
            return Err(AppendTransactionError::Append(
                AppendError::EmptyIdempotencyKey,
            ));
        }
        if key.len() > 256 {
            return Err(AppendTransactionError::Append(
                AppendError::IdempotencyKeyTooLong,
            ));
        }
        let event_json = serde_json::to_vec(&event).map_err(|error| {
            AppendTransactionError::Append(AppendError::InvalidEvent(error.to_string()))
        })?;
        let event_digest: [u8; 32] = Sha256::digest(&event_json).into();
        let mut inner = self.lock();
        if let Some(existing) = inner.idempotency.get(&key) {
            return if existing.event_digest == event_digest {
                Ok(AppendOutcome::DuplicateCollapsed)
            } else {
                Err(AppendTransactionError::Append(
                    AppendError::IdempotencyConflict,
                ))
            };
        }
        if event.sequence == u64::MAX {
            return Err(AppendTransactionError::Append(
                AppendError::SequenceOverflow,
            ));
        }
        if inner.max_events == 0 || event_json.len() > inner.max_bytes {
            return Err(AppendTransactionError::Append(AppendError::LimitExceeded {
                serialized_bytes: event_json.len(),
                maximum_bytes: inner.max_bytes,
            }));
        }
        let previous_activity_sequence = inner.activity_sequences.get(&event.activity_id).copied();
        let expected = previous_activity_sequence
            .map_or(Some(1), |value| value.checked_add(1))
            .ok_or(AppendTransactionError::Append(
                AppendError::SequenceOverflow,
            ))?;
        if event.sequence != expected {
            return Err(AppendTransactionError::Append(
                AppendError::NonMonotonicSequence { expected },
            ));
        }
        let needs_rotation =
            previous_activity_sequence.is_none() && inner.activity_sequences.len() >= MAX_EVENTS;
        if needs_rotation {
            let next_epoch = inner
                .epoch
                .checked_add(1)
                .ok_or(AppendTransactionError::Append(AppendError::EpochOverflow))?;
            let snapshot_revision = inner.snapshot_revision;
            rotate_locked(&mut inner, next_epoch, snapshot_revision);
            if let Some(previous) = previous_activity_sequence {
                inner
                    .activity_sequences
                    .insert(event.activity_id.clone(), previous);
            }
        }
        let next_cursor_sequence =
            inner
                .next_cursor_sequence
                .checked_add(1)
                .ok_or(AppendTransactionError::Append(
                    AppendError::SequenceOverflow,
                ))?;
        precommit().map_err(AppendTransactionError::Precommit)?;
        while inner.events.len() >= inner.max_events
            || inner.serialized_bytes > inner.max_bytes - event_json.len()
        {
            let removed = inner
                .events
                .pop_front()
                .expect("non-empty journal while over capacity");
            inner.serialized_bytes -= removed.serialized_bytes;
            inner.idempotency.remove(&removed.idempotency_key);
        }
        let cursor_sequence = inner.next_cursor_sequence;
        inner.next_cursor_sequence = next_cursor_sequence;
        let serialized_bytes = event_json.len();
        inner.serialized_bytes += serialized_bytes;
        inner
            .activity_sequences
            .insert(event.activity_id.clone(), event.sequence);
        inner
            .idempotency
            .insert(key.clone(), IdempotencyRecord { event_digest });
        inner.events.push_back(StoredEvent {
            cursor_sequence,
            event,
            serialized_bytes,
            idempotency_key: key,
        });
        Ok(AppendOutcome::Appended)
    }

    pub fn preflight_append(
        &self,
        idempotency_key: &str,
        event: &ActivityEvent,
    ) -> Result<(), AppendError> {
        event
            .validate()
            .map_err(|error| AppendError::InvalidEvent(error.code().to_owned()))?;
        if idempotency_key.trim().is_empty() {
            return Err(AppendError::EmptyIdempotencyKey);
        }
        if idempotency_key.len() > 256 {
            return Err(AppendError::IdempotencyKeyTooLong);
        }
        let event_json = serde_json::to_vec(event)
            .map_err(|error| AppendError::InvalidEvent(error.to_string()))?;
        if event.sequence == u64::MAX {
            return Err(AppendError::SequenceOverflow);
        }
        let inner = self.lock();
        if inner.max_events == 0 || event_json.len() > inner.max_bytes {
            return Err(AppendError::LimitExceeded {
                serialized_bytes: event_json.len(),
                maximum_bytes: inner.max_bytes,
            });
        }
        if let Some(existing) = inner.idempotency.get(idempotency_key) {
            let digest: [u8; 32] = Sha256::digest(&event_json).into();
            return if existing.event_digest == digest {
                Ok(())
            } else {
                Err(AppendError::IdempotencyConflict)
            };
        }
        let expected = inner
            .activity_sequences
            .get(&event.activity_id)
            .map_or(Some(1), |value| value.checked_add(1))
            .ok_or(AppendError::SequenceOverflow)?;
        if event.sequence != expected {
            return Err(AppendError::NonMonotonicSequence { expected });
        }
        Ok(())
    }

    pub fn read(&self, cursor: EventCursor, limit: ReadLimit) -> EventRead {
        self.read_filtered(cursor, limit, |_| true)
    }

    pub fn read_filtered<F>(&self, cursor: EventCursor, limit: ReadLimit, include: F) -> EventRead
    where
        F: Fn(&ActivityEvent) -> bool,
    {
        let inner = self.lock();
        let oldest_event = inner.events.front().map(|entry| entry.cursor_sequence);
        let newest = inner.next_cursor_sequence - 1;
        if cursor.epoch != inner.epoch {
            return EventRead::ResyncRequired {
                oldest_available: EventCursor {
                    epoch: inner.epoch,
                    sequence: oldest_event.map_or(newest, |value| value - 1),
                },
                snapshot_revision: inner.snapshot_revision,
            };
        }
        if cursor.sequence > newest {
            return EventRead::CursorAhead {
                newest_available: EventCursor {
                    epoch: inner.epoch,
                    sequence: newest,
                },
            };
        }
        if oldest_event.is_some_and(|oldest| cursor.sequence < oldest - 1) {
            return EventRead::ResyncRequired {
                oldest_available: EventCursor {
                    epoch: inner.epoch,
                    sequence: oldest_event.unwrap() - 1,
                },
                snapshot_revision: inner.snapshot_revision,
            };
        }
        let event_limit = limit.max_events.min(MAX_PAGE_EVENTS);
        let byte_limit = limit.max_bytes.min(MAX_PAGE_BYTES);
        if event_limit == 0 || byte_limit == 0 {
            return EventRead::LimitExceeded;
        }
        let mut events = Vec::new();
        let mut next = cursor.sequence;
        let mut page_bytes = 2usize;
        for entry in inner
            .events
            .iter()
            .filter(|entry| entry.cursor_sequence > cursor.sequence)
        {
            if events.len() == event_limit {
                break;
            }
            if !include(&entry.event) {
                next = entry.cursor_sequence;
                continue;
            }
            let separator = usize::from(!events.is_empty());
            if page_bytes
                .saturating_add(separator)
                .saturating_add(entry.serialized_bytes)
                > byte_limit
            {
                if events.is_empty() {
                    return EventRead::LimitExceeded;
                }
                break;
            }
            page_bytes += separator + entry.serialized_bytes;
            events.push(entry.event.clone());
            next = entry.cursor_sequence;
        }
        EventRead::Events {
            events,
            next_cursor: EventCursor {
                epoch: inner.epoch,
                sequence: next,
            },
        }
    }

    pub fn subscribe(&self, id: SubscriberId, now_ms: u64) -> Result<(), SubscribeError> {
        let mut inner = self.lock();
        if inner.subscribers.contains_key(&id) {
            return Err(SubscribeError::AlreadyExists);
        }
        if inner.subscribers.len() >= MAX_SUBSCRIBERS {
            return Err(SubscribeError::LimitExceeded);
        }
        let epoch = inner.epoch;
        inner.subscribers.insert(
            id,
            Subscriber {
                acknowledged: EventCursor { epoch, sequence: 0 },
                last_active_ms: now_ms,
            },
        );
        Ok(())
    }

    pub fn restore_activity_sequence(
        &self,
        activity_id: ActivityId,
        sequence: u64,
    ) -> Result<(), AppendError> {
        if sequence == 0 || sequence == u64::MAX {
            return Err(AppendError::SequenceOverflow);
        }
        let mut inner = self.lock();
        if inner.activity_sequences.len() >= MAX_EVENTS
            && !inner.activity_sequences.contains_key(&activity_id)
        {
            return Err(AppendError::LimitExceeded {
                serialized_bytes: 0,
                maximum_bytes: MAX_EVENTS,
            });
        }
        match inner.activity_sequences.get(&activity_id) {
            Some(existing) if *existing != sequence => Err(AppendError::IdempotencyConflict),
            _ => {
                inner.activity_sequences.insert(activity_id, sequence);
                Ok(())
            }
        }
    }

    pub fn acknowledge(
        &self,
        id: &SubscriberId,
        cursor: EventCursor,
        now_ms: u64,
    ) -> Result<(), AcknowledgeError> {
        let mut inner = self.lock();
        if cursor.epoch != inner.epoch {
            return Err(AcknowledgeError::WrongEpoch);
        }
        if cursor.sequence >= inner.next_cursor_sequence {
            return Err(AcknowledgeError::CursorAhead);
        }
        if let Some(oldest) = inner.events.front().map(|event| event.cursor_sequence) {
            if cursor.sequence < oldest - 1 {
                return Err(AcknowledgeError::ResyncRequired {
                    oldest_available: EventCursor {
                        epoch: inner.epoch,
                        sequence: oldest - 1,
                    },
                    snapshot_revision: inner.snapshot_revision,
                });
            }
        }
        let subscriber = inner
            .subscribers
            .get_mut(id)
            .ok_or(AcknowledgeError::UnknownSubscriber)?;
        if cursor.sequence >= subscriber.acknowledged.sequence {
            subscriber.acknowledged = cursor;
        }
        subscriber.last_active_ms = now_ms;
        Ok(())
    }

    pub fn expire_idle(&self, now_ms: u64) -> usize {
        let mut inner = self.lock();
        let before = inner.subscribers.len();
        inner.subscribers.retain(|_, subscriber| {
            now_ms.saturating_sub(subscriber.last_active_ms) <= SUBSCRIBER_IDLE_MS
        });
        before - inner.subscribers.len()
    }

    pub fn rotate_epoch(&self, epoch: u64, snapshot_revision: u64) -> Result<(), RotateError> {
        let mut inner = self.lock();
        if epoch <= inner.epoch {
            return Err(RotateError::EpochNotIncreasing);
        }
        rotate_locked(&mut inner, epoch, snapshot_revision);
        Ok(())
    }

    pub fn stats(&self) -> JournalStats {
        let inner = self.lock();
        JournalStats {
            epoch: inner.epoch,
            events: inner.events.len(),
            serialized_bytes: inner.serialized_bytes,
            oldest_sequence: inner.events.front().map(|event| event.cursor_sequence),
            newest_sequence: inner.next_cursor_sequence - 1,
            subscribers: inner.subscribers.len(),
            idempotency_entries: inner.idempotency.len(),
            activity_entries: inner.activity_sequences.len(),
        }
    }

    /// Returns the last cursor durably observed by a live subscriber.
    /// Intended for diagnostics and black-box delivery verification.
    pub fn subscriber_cursor(&self, id: &SubscriberId) -> Option<EventCursor> {
        self.lock()
            .subscribers
            .get(id)
            .map(|value| value.acknowledged)
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

fn rotate_locked(inner: &mut Inner, epoch: u64, snapshot_revision: u64) {
    inner.epoch = epoch;
    inner.snapshot_revision = snapshot_revision;
    inner.next_cursor_sequence = 1;
    inner.events.clear();
    inner.serialized_bytes = 0;
    inner.idempotency.clear();
    inner.activity_sequences.clear();
    inner.subscribers.clear();
}
