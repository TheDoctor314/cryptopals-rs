pub fn hamming_distance(a: &[u8], b: &[u8]) -> u32 {
    xor(a, b).into_iter().map(|b| b.count_ones()).sum()
}

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
const CHAR_FREQ: [(u8, f64); 28] = [
    (b'a', 6.09),
    (b'b', 1.05),
    (b'c', 2.84),
    (b'd', 2.92),
    (b'e', 11.36),
    (b'f', 1.79),
    (b'g', 1.38),
    (b'h', 3.41),
    (b'i', 5.44),
    (b'j', 0.24),
    (b'k', 0.41),
    (b'l', 2.92),
    (b'm', 2.76),
    (b'n', 5.44),
    (b'o', 6.00),
    (b'p', 1.95),
    (b'q', 0.24),
    (b'r', 4.95),
    (b's', 5.68),
    (b't', 8.03),
    (b'u', 2.43),
    (b'v', 0.97),
    (b'w', 1.38),
    (b'x', 0.24),
    (b'y', 1.30),
    (b'z', 0.03),
    (b' ', 12.17), // whitespace
    (b'\n', 6.57), // others
];

pub mod metrics {
    use std::collections::HashMap;

    pub fn score_by_character_freq(input: &[u8]) -> u64 {
        if input
            .iter()
            .any(|&b| !b.is_ascii() || (b.is_ascii_control() && b != b'\n'))
        {
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
                    b'\0'
                };

                *map.entry(ch).or_default() += 1;
            }

            map
        };

        let len = input.len() as f64;

        super::CHAR_FREQ.iter().fold(0f64, |acc, &(b, score)| {
            let expected_count = score / 100f64 * len;
            let actual_count = freq.get(&b).copied().unwrap_or_default() as f64;
            acc + (expected_count - actual_count).powi(2)
        }) as u64
    }

    pub fn count_spaces(input: &[u8]) -> u64 {
        input.iter().filter(|&b| *b == b' ').count() as u64
    }
}

pub struct DecodeSingleByteXorResult {
    pub key: u8,
    pub plaintext: Vec<u8>,
}

pub fn break_single_byte_xor<F>(input: &[u8], score_by: F) -> DecodeSingleByteXorResult
where
    F: Fn(&[u8]) -> u64,
{
    let (key, plaintext) = (0..u8::MAX)
        .map(|key| (key, repeating_xor(input, &[key])))
        .min_by_key(|(_, buf)| score_by(buf))
        .expect("Cannot be empty");

    DecodeSingleByteXorResult { key, plaintext }
}

#[derive(Debug)]
pub struct DecodeRepeatingKeyXorResult {
    pub key: Vec<u8>,
    pub plaintext: Vec<u8>,
}

pub fn break_repeating_key_xor(input: &[u8]) -> DecodeRepeatingKeyXorResult {
    let key = get_possible_keysizes(input)
        .into_iter()
        .map(|keysize| break_repeating_key_xor_for_keysize(input, keysize))
        .min_by_key(|key| metrics::score_by_character_freq(&repeating_xor(input, key)))
        .expect("Should have found a key");

    let plaintext = repeating_xor(input, &key);

    DecodeRepeatingKeyXorResult { key, plaintext }
}

/// Returns the possible key for the given key length.
fn break_repeating_key_xor_for_keysize(input: &[u8], key_len: usize) -> Vec<u8> {
    get_group_by_keylen(input, key_len)
        .into_iter()
        .map(|block| break_single_byte_xor(&block, metrics::score_by_character_freq).key)
        .collect()
}

/// Returns the top 5 keysizes
fn get_possible_keysizes(input: &[u8]) -> Vec<usize> {
    let count = 5;
    let mut candidates: Vec<(usize, u32)> = (2..=40)
        .map(|keysize| {
            let mut distance = 0f32;

            let chunks = input.chunks_exact(keysize);
            let mut chunks_next = chunks.clone();
            chunks_next.next();

            for (a, b) in chunks.zip(chunks_next).take(4) {
                distance += hamming_distance(a, b) as f32;
            }

            let distance = (distance / keysize as f32) as u32;
            (keysize, distance)
        })
        .collect();

    candidates.sort_by_key(|&(_, x)| x);

    candidates
        .into_iter()
        .take(count)
        .map(|(keysize, _)| keysize)
        .collect()
}

fn get_group_by_keylen(input: &[u8], key_len: usize) -> Vec<Vec<u8>> {
    let mut chunks = vec![Vec::new(); key_len];

    let mut i = 0;
    for &byte in input {
        if i == key_len {
            i = 0;
        }

        chunks[i].push(byte);
        i += 1;
    }

    chunks
}
