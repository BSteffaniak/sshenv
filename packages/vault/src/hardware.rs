use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HardwareRecipientKind {
    AgePlugin,
    YubiKeyPiv,
    FidoSecurityKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HardwareRecipientDescriptor {
    pub id: String,
    pub label: Option<String>,
    pub kind: HardwareRecipientKind,
    pub public_descriptor: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HardwareRecipientError {
    #[error("hardware recipient provider is unavailable: {0}")]
    Unavailable(String),
    #[error("hardware recipient was not found: {0}")]
    NotFound(String),
    #[error("hardware recipient descriptor is invalid: {0}")]
    InvalidDescriptor(String),
}

pub trait HardwareRecipientProvider {
    fn provider_name(&self) -> &'static str;

    fn list_recipients(&self) -> Result<Vec<HardwareRecipientDescriptor>, HardwareRecipientError>;

    fn recipient_by_id(
        &self,
        id: &str,
    ) -> Result<HardwareRecipientDescriptor, HardwareRecipientError> {
        self.list_recipients()?
            .into_iter()
            .find(|recipient| recipient.id == id)
            .ok_or_else(|| HardwareRecipientError::NotFound(id.to_string()))
    }
}

pub fn validate_hardware_recipient_descriptor(
    descriptor: &HardwareRecipientDescriptor,
) -> Result<(), HardwareRecipientError> {
    if descriptor.id.trim().is_empty() {
        return Err(HardwareRecipientError::InvalidDescriptor(
            "id is empty".to_string(),
        ));
    }
    if descriptor.public_descriptor.trim().is_empty() {
        return Err(HardwareRecipientError::InvalidDescriptor(
            "public descriptor is empty".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        HardwareRecipientDescriptor, HardwareRecipientError, HardwareRecipientKind,
        HardwareRecipientProvider, validate_hardware_recipient_descriptor,
    };

    struct FakeProvider;

    impl HardwareRecipientProvider for FakeProvider {
        fn provider_name(&self) -> &'static str {
            "fake"
        }

        fn list_recipients(
            &self,
        ) -> Result<Vec<HardwareRecipientDescriptor>, HardwareRecipientError> {
            Ok(vec![HardwareRecipientDescriptor {
                id: "slot-9c".to_string(),
                label: Some("test key".to_string()),
                kind: HardwareRecipientKind::YubiKeyPiv,
                public_descriptor: "age-plugin-yubikey-1example".to_string(),
            }])
        }
    }

    #[test]
    fn provider_can_resolve_recipient_by_id() {
        let recipient = FakeProvider.recipient_by_id("slot-9c").unwrap();
        assert_eq!(recipient.kind, HardwareRecipientKind::YubiKeyPiv);
        validate_hardware_recipient_descriptor(&recipient).unwrap();
    }

    #[test]
    fn rejects_empty_public_descriptor() {
        let descriptor = HardwareRecipientDescriptor {
            id: "id".to_string(),
            label: None,
            kind: HardwareRecipientKind::AgePlugin,
            public_descriptor: String::new(),
        };
        assert_eq!(
            validate_hardware_recipient_descriptor(&descriptor),
            Err(HardwareRecipientError::InvalidDescriptor(
                "public descriptor is empty".to_string()
            ))
        );
    }
}
