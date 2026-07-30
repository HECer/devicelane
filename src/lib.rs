pub mod protocol {
    use prost::{Enumeration, Message};

    #[derive(Clone, Copy, PartialEq, Eq, Message)]
    pub struct ProtocolVersion {
        #[prost(uint32, tag = "1")]
        pub major: u32,
        #[prost(uint32, tag = "2")]
        pub minor: u32,
    }

    #[derive(Clone, PartialEq, Message)]
    pub struct Host {
        #[prost(message, optional, tag = "1")]
        pub version: Option<ProtocolVersion>,
        #[prost(string, tag = "2")]
        pub id: String,
        #[prost(string, tag = "3")]
        pub operating_system: String,
        #[prost(string, tag = "4")]
        pub architecture: String,
    }

    #[derive(Clone, PartialEq, Message)]
    pub struct Device {
        #[prost(message, optional, tag = "1")]
        pub version: Option<ProtocolVersion>,
        #[prost(string, tag = "2")]
        pub id: String,
        #[prost(string, tag = "3")]
        pub host_id: String,
        #[prost(string, tag = "4")]
        pub platform: String,
        #[prost(string, tag = "5")]
        pub state: String,
    }

    #[derive(Clone, PartialEq, Message)]
    pub struct Capability {
        #[prost(message, optional, tag = "1")]
        pub version: Option<ProtocolVersion>,
        #[prost(string, tag = "2")]
        pub name: String,
        #[prost(uint32, tag = "3")]
        pub revision: u32,
    }

    #[derive(Clone, PartialEq, Message)]
    pub struct Job {
        #[prost(message, optional, tag = "1")]
        pub version: Option<ProtocolVersion>,
        #[prost(string, tag = "2")]
        pub id: String,
        #[prost(string, tag = "3")]
        pub capability: String,
        #[prost(string, tag = "4")]
        pub state: String,
    }

    #[derive(Clone, PartialEq, Message)]
    pub struct Event {
        #[prost(message, optional, tag = "1")]
        pub version: Option<ProtocolVersion>,
        #[prost(string, tag = "2")]
        pub job_id: String,
        #[prost(uint64, tag = "3")]
        pub sequence: u64,
        #[prost(string, tag = "4")]
        pub kind: String,
        #[prost(bytes = "vec", tag = "5")]
        pub payload: Vec<u8>,
    }

    #[derive(Clone, PartialEq, Message)]
    pub struct Artifact {
        #[prost(message, optional, tag = "1")]
        pub version: Option<ProtocolVersion>,
        #[prost(string, tag = "2")]
        pub id: String,
        #[prost(string, tag = "3")]
        pub job_id: String,
        #[prost(string, tag = "4")]
        pub sha256: String,
        #[prost(uint64, tag = "5")]
        pub size_bytes: u64,
        #[prost(string, tag = "6")]
        pub media_type: String,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Enumeration)]
    pub enum RetryClass {
        Never = 0,
        Immediate = 1,
        Backoff = 2,
        AfterRepair = 3,
    }

    #[derive(Clone, PartialEq, Message)]
    pub struct RepairAction {
        #[prost(string, tag = "1")]
        pub description: String,
        #[prost(string, optional, tag = "2")]
        pub command: Option<String>,
    }

    #[derive(Clone, PartialEq, Message)]
    struct WireError {
        #[prost(string, tag = "1")]
        code: String,
        #[prost(string, tag = "2")]
        message: String,
        #[prost(enumeration = "RetryClass", tag = "3")]
        retry_class: i32,
        #[prost(message, optional, tag = "4")]
        repair_action: Option<RepairAction>,
    }

    #[derive(Clone, Debug, PartialEq)]
    pub struct Error {
        code: String,
        message: String,
        retry_class: RetryClass,
        repair_action: Option<RepairAction>,
    }

    impl Error {
        pub fn new(
            code: impl Into<String>,
            message: impl Into<String>,
            retry_class: RetryClass,
            repair_action: Option<RepairAction>,
        ) -> Result<Self, &'static str> {
            let code = code.into();
            let message = message.into();
            if code.is_empty() {
                return Err("error code must not be empty");
            }
            if message.is_empty() {
                return Err("error message must not be empty");
            }
            Ok(Self {
                code,
                message,
                retry_class,
                repair_action,
            })
        }

        pub fn encode_to_vec(&self) -> Vec<u8> {
            WireError {
                code: self.code.clone(),
                message: self.message.clone(),
                retry_class: self.retry_class.into(),
                repair_action: self.repair_action.clone(),
            }
            .encode_to_vec()
        }

        pub fn decode(bytes: &[u8]) -> Result<Self, &'static str> {
            let wire = WireError::decode(bytes).map_err(|_| "invalid error encoding")?;
            let retry_class =
                RetryClass::try_from(wire.retry_class).map_err(|_| "unknown retry class")?;
            Self::new(wire.code, wire.message, retry_class, wire.repair_action)
        }

        pub fn code(&self) -> &str {
            &self.code
        }

        pub fn message(&self) -> &str {
            &self.message
        }

        pub fn retry_class(&self) -> RetryClass {
            self.retry_class
        }

        pub fn repair_action(&self) -> Option<&RepairAction> {
            self.repair_action.as_ref()
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn workspace_package_is_available() {
        assert_eq!(env!("CARGO_PKG_NAME"), "device-development-mesh");
    }
}
