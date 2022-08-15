/// Returns the bytewise xor of the two buffers.
///
/// If `b.len() < a.len()` then `b` is repeated to compute the xor.
pub fn repeating_xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut res = a.to_vec();

    repeating_xor_inplace(&mut res, b);

    res
}

/// Computes the bytewise xor of the two buffers inplace.
///
/// If `b.len() < a.len()` then `b` is repeated to compute the xor.
pub fn repeating_xor_inplace(a: &mut [u8], b: &[u8]) {
    for block in a.chunks_mut(b.len()) {
        let len = block.len();
        xor_in_place(block, &b[..len]);
    }
}

/// Returns the bytewise xor of the buffers.
///
/// # Panics
/// The function panics if the length of the buffers is not equal.
pub fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    assert_eq!(a.len(), b.len());

    let mut res = a.to_vec();
    xor_in_place(&mut res, b);

    res
}

/// Computes the bytewise xor of the two buffers inplace.
///
/// # Panics
/// The function panics if the length of the buffers is not equal.
pub fn xor_in_place(a: &mut [u8], b: &[u8]) {
    // TODO: Make it faster by working on a u64 at a time
    // instead of a byte.

    assert_eq!(a.len(), b.len());

    for (a, b) in a.iter_mut().zip(b.iter()) {
        *a ^= *b;
    }
}

// source: https://www.cl.cam.ac.uk/~mgk25/lee-essays.pdf pg. 181
const CHAR_FREQ: [(u8, u32); 28] = [
    (b'a', 609),
    (b'b', 105),
    (b'c', 284),
    (b'd', 292),
    (b'e', 1136),
    (b'f', 179),
    (b'g', 138),
    (b'h', 341),
    (b'i', 544),
    (b'j', 24),
    (b'k', 41),
    (b'l', 292),
    (b'm', 276),
    (b'n', 544),
    (b'o', 600),
    (b'p', 195),
    (b'q', 24),
    (b'r', 495),
    (b's', 568),
    (b't', 803),
    (b'u', 243),
    (b'v', 97),
    (b'w', 138),
    (b'x', 24),
    (b'y', 130),
    (b'z', 3),
    (b' ', 1217), // whitespace
    (b'.', 657),  // others
];

pub mod metrics {
    use std::collections::HashMap;

    pub fn score_by_character_freq(input: &[u8]) -> u64 {
        if !input.is_ascii() {
            return u64::MAX;
        }

        if input.iter().any(|&b| b.is_ascii_control() && b != b'\n') {
            return u64::MAX;
        }

        let freq: HashMap<u8, u32> = {
            let mut map = HashMap::new();

            for &b in input {
                if b.is_ascii_control() {
                    continue;
                }

                let ch = if b.is_ascii_alphabetic() {
                    b.to_ascii_lowercase()
                } else if b.is_ascii_whitespace() {
                    b' '
                } else {
                    b'.'
                };

                *map.entry(ch).or_default() += 1;
            }

            map
        };

        let len = input.len();

        super::CHAR_FREQ.iter().fold(0, |acc, &(b, score)| {
            let expected = score as u64 * len as u64;
            let actual = freq.get(&b).copied().unwrap_or_default();

            acc + (expected - actual as u64).pow(2)
        })
    }

    pub fn count_spaces(input: &[u8]) -> u64 {
        input.iter().filter(|&b| *b == b' ').count() as u64
    }
}

pub fn break_single_byte_xor<F>(input: &[u8], score_by: F) -> (u8, Vec<u8>)
where
    F: Fn(&[u8]) -> u64,
{
    (0..u8::MAX)
        .map(|key| (key, repeating_xor(input, &[key])))
        .min_by_key(|(_, buf)| score_by(buf))
        .expect("Cannot be empty")
}
