use device_development_mesh::protocol::{
    Artifact, Capability, Device, Error, Event, Host, Job, ProtocolVersion, RepairAction,
    RetryClass,
};
use prost::Message;

fn assert_round_trip<T>(value: T)
where
    T: Message + Default + PartialEq + std::fmt::Debug,
{
    let bytes = value.encode_to_vec();
    assert_eq!(T::decode(bytes.as_slice()).unwrap(), value);
}

#[test]
fn contract_types_round_trip_without_information_loss() {
    let version = Some(ProtocolVersion { major: 1, minor: 0 });

    assert_round_trip(Host {
        version,
        id: "host-1".into(),
        operating_system: "macos".into(),
        architecture: "aarch64".into(),
    });
    assert_round_trip(Device {
        version,
        id: "device-1".into(),
        host_id: "host-1".into(),
        platform: "ios".into(),
        state: "connected".into(),
    });
    assert_round_trip(Capability {
        version,
        name: "apple.device.install".into(),
        revision: 1,
    });
    assert_round_trip(Job {
        version,
        id: "job-1".into(),
        capability: "apple.device.install@1".into(),
        state: "running".into(),
    });
    assert_round_trip(Event {
        version,
        job_id: "job-1".into(),
        sequence: 42,
        kind: "progress".into(),
        payload: b"halfway".to_vec(),
    });
    assert_round_trip(Artifact {
        version,
        id: "artifact-1".into(),
        job_id: "job-1".into(),
        sha256: "abc123".into(),
        size_bytes: 4096,
        media_type: "application/octet-stream".into(),
    });
}

#[test]
fn previous_minor_version_ignores_an_unknown_optional_property() {
    let host = Host {
        version: Some(ProtocolVersion { major: 1, minor: 1 }),
        id: "host-1".into(),
        operating_system: "linux".into(),
        architecture: "x86_64".into(),
    };
    let mut newer_minor_bytes = host.encode_to_vec();
    newer_minor_bytes.extend_from_slice(&[0x2a, 0x03, b'n', b'e', b'w']);

    assert_eq!(Host::decode(newer_minor_bytes.as_slice()).unwrap(), host);
}

#[test]
fn error_has_stable_code_message_retry_class_and_optional_repair_action() {
    let error = Error::new(
        "device_not_trusted",
        "The device has not trusted this host",
        RetryClass::AfterRepair,
        Some(RepairAction {
            description: "Trust the host on the device".into(),
            command: None,
        }),
    )
    .unwrap();

    let decoded = Error::decode(error.encode_to_vec().as_slice()).unwrap();
    assert_eq!(decoded, error);
    assert_eq!(error.code(), "device_not_trusted");
    assert_eq!(error.message(), "The device has not trusted this host");
    assert_eq!(error.retry_class(), RetryClass::AfterRepair);
    assert_eq!(
        error.repair_action().unwrap().description,
        "Trust the host on the device"
    );
}

#[test]
fn error_rejects_missing_required_properties() {
    assert!(Error::new("", "message", RetryClass::Never, None).is_err());
    assert!(Error::new("code", "", RetryClass::Never, None).is_err());
    assert!(Error::decode(&[][..]).is_err());
}
