use base64::Engine;

pub trait Base64 {
    fn to_base64(&self) -> String;
    fn from_base64(&self) -> Result<Vec<u8>, base64::DecodeError>;
}

impl<T: AsRef<[u8]>> Base64 for T {
    fn to_base64(&self) -> String {
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(self.as_ref())
    }

    fn from_base64(&self) -> Result<Vec<u8>, base64::DecodeError> {
        base64::engine::general_purpose::STANDARD_NO_PAD.decode(self.as_ref())
    }
}

pub fn from_base64(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    let input = input.as_bytes();
    input.from_base64()
}
