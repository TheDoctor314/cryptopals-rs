pub struct Aes128 {
    round_keys: [u32; NB * (NR + 1)],
}

impl Aes128 {
    pub fn new(key: &[u8]) -> Self {
        let round_keys = create_round_keys(key);
        Self { round_keys }
    }

    pub fn decrypt(&self, input: &[u8], output: &mut [u8]) {
        assert_eq!(
            input.len(),
            output.len(),
            "input and output buffers must have the same length"
        );
        assert_eq!(
            input.len() % (NB * NK),
            0,
            "buffer length must be a multiple of sixteen bytes"
        );

        let mut state = [0u8; 16];

        for (in_block, out_block) in input
            .chunks_exact(NB * NK)
            .zip(output.chunks_exact_mut(NB * NK))
        {
            self.decrypt_block(in_block, out_block, &mut state);
        }
    }

    fn decrypt_block(&self, input: &[u8], output: &mut [u8], state: &mut [u8; 16]) {
        state.copy_from_slice(input);

        add_round_key(state, self.round_keys[NR * NB..].try_into().unwrap());

        for round_key in self
            .round_keys
            .rchunks_exact(NB)
            .skip(1) // already added one rk
            .take(9) // add rk at end
            .map(|rk| TryInto::<&[u32; NB]>::try_into(rk).unwrap())
        {
            inv_shift_rows(state);
            inv_sub_bytes(state);
            add_round_key(state, round_key);
            inv_mix_cols(state);
        }

        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, self.round_keys[0..NB].try_into().unwrap());

        output.copy_from_slice(state)
    }
}

fn add_round_key(state: &mut [u8; 16], round_key: &[u32; NB]) {
    for (i, col) in state.chunks_exact_mut(NB).enumerate() {
        let word = u32::from_le_bytes(col.try_into().unwrap());
        col.copy_from_slice(&(word ^ round_key[i]).to_le_bytes());
    }
}

fn inv_mix_cols(state: &mut [u8; 16]) {
    for chunk in state.chunks_exact_mut(4) {
        let word = u32::from_le_bytes(chunk.try_into().unwrap());
        let word = inv_mix_word(word);
        chunk.copy_from_slice(&word.to_le_bytes());
    }
}

fn inv_shift_rows(state: &mut [u8; 16]) {
    for r in 0..4 {
        let mut temp = [0; 4];
        for c in 0..4 {
            temp[c] = state[4 * c + r];
        }

        for c in 0..4 {
            state[4 * c + r] = temp[(4 + c - r) % 4];
        }
    }
}

fn inv_sub_bytes(state: &mut [u8; 16]) {
    for b in state {
        *b = INV_SBOX[*b as usize];
    }
}

const NB: usize = 4;
const NR: usize = 10;
const NK: usize = 4;

pub(crate) const RCON: [u32; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

// We create the same key schedule for both decryption and encryption, instead
// using different sequence of transformations for the actual cipher.
pub(crate) fn create_round_keys(key: &[u8]) -> [u32; NB * (NR + 1)] {
    debug_assert_eq!(key.len(), 4 * NK);

    let mut i = 0;
    let mut round_keys = [0u32; NB * (NR + 1)];

    // TODO: Make sure this compiles to a `memcpy()`
    while i < NK {
        round_keys[i] = u32::from_le_bytes(key[4 * i..4 * (i + 1)].try_into().unwrap());
        i += 1;
    }

    while i < NB * (NR + 1) {
        let mut temp = round_keys[i - 1];
        if (i % NK) == 0 {
            temp = sub_word(rot_word(temp)) ^ RCON[(i / NK) - 1];
        }

        round_keys[i] = round_keys[i - NK] ^ temp;
        i += 1;
    }

    round_keys
}

pub(crate) fn sub_word(w: u32) -> u32 {
    u32::from_le_bytes(w.to_le_bytes().map(|b| SBOX[b as usize]))
}

pub(crate) fn inv_mix_word(w: u32) -> u32 {
    let f2 = xtime(w);
    let f4 = xtime(f2);
    let f8 = xtime(f4);
    let f9 = w ^ f8;

    let f0e = f2 ^ f4 ^ f8;
    let f0b = f2 ^ f9;
    let f0d = f4 ^ f9;

    f0e ^ f0b.rotate_right(8) ^ f0d.rotate_right(16) ^ f9.rotate_right(24)
}

pub(crate) const fn rot_word(w: u32) -> u32 {
    w.rotate_right(8)
}

pub(crate) const fn xtime(w: u32) -> u32 {
    let high_bit_mask = 0x80808080;
    // low 7 bits of each byte
    let rest_mask = !high_bit_mask;
    let modulo = 0x1b;

    (((w & high_bit_mask) >> 7) * modulo) ^ ((w & rest_mask) << 1)
}

const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

const INV_SBOX: [u8; 256] = {
    let mut table = [0u8; 256];

    let mut i = 0;
    while i < table.len() {
        let b = SBOX[i];
        table[b as usize] = i as u8;
        i += 1;
    }

    table
};
