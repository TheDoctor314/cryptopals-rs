const HEX_TABLE: &[u8; 16] = b"0123456789abcdef";

pub trait ToHex {
    fn to_hex(&self) -> String;
}

impl<T: AsRef<[u8]>> ToHex for T {
    fn to_hex(&self) -> String {
        self::to_hex(self.as_ref())
    }
}

fn to_hex(input: &[u8]) -> String {
    let mut buf = vec![0; input.len() * 2];

    for (byte, pair) in input.iter().zip(&mut buf.chunks_exact_mut(2)) {
        pair[0] = HEX_TABLE[(byte >> 4) as usize];
        pair[1] = HEX_TABLE[(byte & 0xf) as usize];
    }

    String::from_utf8(buf).expect("Invalid utf-8")
}

pub fn from_hex(input: &str) -> Result<Vec<u8>, FromHexError> {
    let input = input.as_bytes();

    if input.len() % 2 != 0 {
        return Err(FromHexError::OddLength);
    }

    input
        .chunks_exact(2)
        .enumerate()
        .map(|(i, pair)| Ok((hex_to_byte(pair[0], 2 * i)? << 4) | hex_to_byte(pair[1], 2 * i + 1)?))
        .collect()
}

fn hex_to_byte(ch: u8, at: usize) -> Result<u8, FromHexError> {
    match ch {
        b'0'..=b'9' => Ok(ch - b'0'),
        b'A'..=b'F' => Ok(ch - b'A' + 10),
        b'a'..=b'f' => Ok(ch - b'a' + 10),
        _ => Err(FromHexError::InvalidHexChar { ch, at }),
    }
}

#[derive(Debug, Clone, Copy)]
pub enum FromHexError {
    OddLength,
    InvalidHexChar { ch: u8, at: usize },
}

impl std::error::Error for FromHexError {}

impl std::fmt::Display for FromHexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FromHexError::OddLength => "Hex string length cannot be odd".fmt(f),
            FromHexError::InvalidHexChar { ch, at } => {
                write!(f, "Invalid character {ch:#x} at idx: {at}")
            }
        }
    }
}
