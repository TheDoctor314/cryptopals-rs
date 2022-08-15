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
