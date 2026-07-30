use device_development_mesh::sessions::{Client, JobJournal, RequestResult, ResumeError};
use std::cell::Cell;

#[test]
fn reconnect_resumes_the_same_job_after_the_last_acknowledged_event() {
    let mut journal = JobJournal::new();
    for payload in ["start", "one"] {
        journal.append("job-1", "output", payload.as_bytes().to_vec());
    }
    let mut client = Client::new("job-1");
    let mut connection = client.connect(&journal).unwrap();
    assert_eq!(connection.next().unwrap().payload, b"start");
    client.acknowledge(connection.next().unwrap().sequence);
    connection.disconnect();

    for payload in ["two", "exit"] {
        journal.append("job-1", "output", payload.as_bytes().to_vec());
    }

    let after_reconnect = client.connect(&journal).unwrap().collect::<Vec<_>>();
    assert_eq!(
        after_reconnect
            .iter()
            .map(|event| event.sequence)
            .collect::<Vec<_>>(),
        [3, 4]
    );
    assert_eq!(
        after_reconnect
            .iter()
            .map(|event| event.payload.as_slice())
            .collect::<Vec<_>>(),
        [b"two".as_slice(), b"exit".as_slice()]
    );
}

#[test]
fn reconnect_rejects_a_cursor_beyond_the_job_tail() {
    let journal = JobJournal::new();
    let mut client = Client::new("job-1");
    client.acknowledge(1);

    assert_eq!(
        client.connect(&journal).unwrap_err(),
        ResumeError::CursorAhead
    );
}

#[test]
fn duplicate_non_idempotent_request_returns_the_first_result_without_executing_again() {
    let mut journal = JobJournal::new();
    let executions = Cell::new(0);

    let first = journal.execute_once("request-1", || {
        executions.set(executions.get() + 1);
        RequestResult::new("job-1")
    });
    let duplicate = journal.execute_once("request-1", || {
        executions.set(executions.get() + 1);
        RequestResult::new("job-2")
    });

    assert_eq!(executions.get(), 1);
    assert_eq!(duplicate, first);
    assert_eq!(duplicate.job_id(), "job-1");
}

#[test]
fn reconnect_delivers_ten_thousand_buffered_events() {
    let mut journal = JobJournal::new();
    for number in 1_u64..=10_000 {
        journal.append("job-1", "output", number.to_le_bytes().to_vec());
    }

    let events = journal.resume("job-1", 0).unwrap();

    assert_eq!(events.len(), 10_000);
    for (index, event) in events.iter().enumerate() {
        let expected = index as u64 + 1;
        assert_eq!(event.sequence, expected);
        assert_eq!(event.payload, expected.to_le_bytes());
    }
}
