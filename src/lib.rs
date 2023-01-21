pub mod aes;
pub mod base64;
pub mod hex;
pub mod xor;

pub use crate::base64::Base64;
pub use hex::{from_hex, ToHex};

#[cfg(test)]
mod tests;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Invalid base64")]
    Base64Error(#[from] ::base64::DecodeError),
    #[error("IO error")]
    IoError(#[from] std::io::Error),
}
