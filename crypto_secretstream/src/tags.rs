//! `crypto_secretstream` tags.

use crate::errors;

/// Tag is attached to each message, which can change the state of the stream.
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Tag {
    /// Most common tag, doesn't add any information about the nature of the message.
    Message,
    /// Marks the end of a set of messages, but not the end of the stream.
    Push,
    /// Generate a new key for the stream.
    Rekey,
    /// Marks the end of the stream.
    Final,
}

impl TryFrom<u8> for Tag {
    type Error = errors::InvalidRange<u8>;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Message),
            1 => Ok(Self::Push),
            2 => Ok(Self::Rekey),
            3 => Ok(Self::Final),
            _ => Err(errors::InvalidRange::new(0..3, value)),
        }
    }
}
