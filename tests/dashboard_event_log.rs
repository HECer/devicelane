use device_development_mesh::dashboard::event_log::{
    AcknowledgeError, AppendError, AppendOutcome, EventJournal, EventRead, MAX_EVENT_BYTES,
    MAX_EVENTS, MAX_PAGE_BYTES, MAX_PAGE_EVENTS, MAX_SUBSCRIBERS, ReadLimit, SUBSCRIBER_IDLE_MS,
    SubscribeError,
};
use device_development_mesh::dashboard::{
    ActivityEvent, ActivityId, ActivityState, Authorization, EventCursor, HostId, MetricSnapshot,
    MetricValue, OperationId, PolicyEffect, PrincipalId, ResourceClass, SafeCode, SubscriberId,
};
use std::time::{Duration, Instant};

fn id<T, E: std::fmt::Debug>(value: &str, parse: impl FnOnce(String) -> Result<T, E>) -> T {
    parse(value.to_owned()).unwrap()
}

fn event(activity: &str, sequence: u64) -> ActivityEvent {
    ActivityEvent {
        activity_id: id(activity, ActivityId::parse),
        sequence,
        occurred_at_ms: sequence,
        principal_id: id("principal", PrincipalId::parse),
        source_host_id: id("source", HostId::parse),
        target_host_id: id("target", HostId::parse),
        device_id: None,
        operation: id("build", OperationId::parse),
        resources: vec![ResourceClass::WorkspaceRead],
        authorization: Authorization {
            effect: PolicyEffect::Allow,
            rule_id: None,
            approval_id: None,
        },
        state: ActivityState::Queued,
        message: None,
        metrics: MetricSnapshot {
            current_memory_bytes: MetricValue::Unavailable {
                reason: SafeCode::parse("unavailable").unwrap(),
            },
            peak_memory_bytes: MetricValue::Unavailable {
                reason: SafeCode::parse("unavailable").unwrap(),
            },
            cpu_time_ms: MetricValue::Unavailable {
                reason: SafeCode::parse("unavailable").unwrap(),
            },
            process_count: MetricValue::Unavailable {
                reason: SafeCode::parse("unavailable").unwrap(),
            },
        },
        started_at_ms: None,
        finished_at_ms: None,
    }
}

#[test]
fn append_is_ordered_and_idempotent_but_conflicts_are_rejected() {
    let journal = EventJournal::new(7, 1);
    assert_eq!(
        journal.append("key-1", event("a", 1)).unwrap(),
        AppendOutcome::Appended
    );
    assert_eq!(
        journal.append("key-1", event("a", 1)).unwrap(),
        AppendOutcome::DuplicateCollapsed
    );

    let mut conflict = event("a", 1);
    conflict.operation = id("test", OperationId::parse);
    assert_eq!(
        journal.append("key-1", conflict),
        Err(AppendError::IdempotencyConflict)
    );
    assert_eq!(
        journal.append("key-2", event("a", 3)),
        Err(AppendError::NonMonotonicSequence { expected: 2 })
    );
    assert_eq!(
        journal.append("key-2", event("a", 2)).unwrap(),
        AppendOutcome::Appended
    );
}

#[test]
fn journal_and_pages_enforce_exact_event_and_byte_bounds() {
    let journal = EventJournal::new(7, 11);
    for sequence in 1..=(MAX_EVENTS as u64 + 10) {
        journal
            .append(format!("key-{sequence}"), event("a", sequence))
            .unwrap();
    }
    let stats = journal.stats();
    assert_eq!(stats.events, MAX_EVENTS);
    assert!(stats.serialized_bytes <= MAX_EVENT_BYTES);
    assert_eq!(stats.oldest_sequence, Some(11));

    assert!(matches!(
        journal.read(
            EventCursor {
                epoch: 7,
                sequence: 0
            },
            ReadLimit::default()
        ),
        EventRead::ResyncRequired {
            oldest_available: EventCursor { sequence: 10, .. },
            snapshot_revision: 11
        }
    ));
    let EventRead::Events {
        events,
        next_cursor,
    } = journal.read(
        EventCursor {
            epoch: 7,
            sequence: 10,
        },
        ReadLimit {
            max_events: usize::MAX,
            max_bytes: usize::MAX,
        },
    )
    else {
        panic!("expected events")
    };
    assert!(events.len() <= MAX_PAGE_EVENTS);
    assert!(serde_json::to_vec(&events).unwrap().len() <= MAX_PAGE_BYTES);
    assert_eq!(next_cursor.sequence, 10 + events.len() as u64);
}

#[test]
fn one_logical_event_is_never_silently_truncated() {
    let journal = EventJournal::with_bounds(1, 1, 1000, 64);
    assert!(matches!(
        journal.append("large", event("a", 1)),
        Err(AppendError::LimitExceeded { .. })
    ));
    assert_eq!(journal.stats().events, 0);
}

#[test]
fn auxiliary_indexes_remain_bounded_with_many_distinct_activities() {
    let journal = EventJournal::new(1, 1);
    for sequence in 1..=2_000 {
        journal
            .append(
                format!("key-{sequence}"),
                event(&format!("activity-{sequence}"), 1),
            )
            .unwrap();
    }
    let stats = journal.stats();
    assert!(stats.idempotency_entries <= MAX_EVENTS);
    assert!(stats.activity_entries <= MAX_EVENTS);
}

#[test]
fn subscribers_acknowledge_expire_and_are_strictly_bounded() {
    let journal = EventJournal::new(1, 1);
    for index in 0..MAX_SUBSCRIBERS {
        journal
            .subscribe(id(&format!("s-{index}"), SubscriberId::parse), 100)
            .unwrap();
    }
    assert_eq!(
        journal.subscribe(id("extra", SubscriberId::parse), 100),
        Err(SubscribeError::LimitExceeded)
    );

    let subscriber = id("s-0", SubscriberId::parse);
    journal
        .acknowledge(
            &subscriber,
            EventCursor {
                epoch: 1,
                sequence: 0,
            },
            101,
        )
        .unwrap();
    assert_eq!(
        journal.expire_idle(101 + SUBSCRIBER_IDLE_MS),
        MAX_SUBSCRIBERS - 1
    );
    assert_eq!(journal.expire_idle(102 + SUBSCRIBER_IDLE_MS), 1);
}

#[test]
fn acknowledgement_of_an_evicted_gap_requires_resync() {
    let journal = EventJournal::with_bounds(1, 77, 2, MAX_EVENT_BYTES);
    let subscriber = id("slow", SubscriberId::parse);
    journal.subscribe(subscriber.clone(), 0).unwrap();
    for sequence in 1..=3 {
        journal
            .append(format!("key-{sequence}"), event("a", sequence))
            .unwrap();
    }
    assert_eq!(
        journal.acknowledge(
            &subscriber,
            EventCursor {
                epoch: 1,
                sequence: 0
            },
            1
        ),
        Err(AcknowledgeError::ResyncRequired {
            oldest_available: EventCursor {
                epoch: 1,
                sequence: 1
            },
            snapshot_revision: 77,
        })
    );
}

#[test]
fn epoch_rotation_and_cursor_ahead_require_explicit_recovery() {
    let journal = EventJournal::new(7, 1);
    journal.append("one", event("a", 1)).unwrap();
    assert!(matches!(
        journal.read(
            EventCursor {
                epoch: 7,
                sequence: 2
            },
            ReadLimit::default()
        ),
        EventRead::CursorAhead {
            newest_available: EventCursor { sequence: 1, .. }
        }
    ));
    journal.rotate_epoch(8, 42);
    assert!(matches!(
        journal.read(
            EventCursor {
                epoch: 7,
                sequence: 1
            },
            ReadLimit::default()
        ),
        EventRead::ResyncRequired {
            snapshot_revision: 42,
            ..
        }
    ));
    assert_eq!(journal.stats().events, 0);
}

#[test]
fn ten_thousand_events_and_a_slow_consumer_finish_under_five_seconds() {
    let journal = EventJournal::new(3, 1);
    let slow = journal.clone();
    let reader = std::thread::spawn(move || {
        for _ in 0..20 {
            let _ = slow.read(
                EventCursor {
                    epoch: 3,
                    sequence: 0,
                },
                ReadLimit::default(),
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    });
    let started = Instant::now();
    for sequence in 1..=10_000 {
        journal
            .append(format!("load-{sequence}"), event("load", sequence))
            .unwrap();
    }
    reader.join().unwrap();
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(journal.stats().events, MAX_EVENTS);
}
