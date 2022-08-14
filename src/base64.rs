const BASE64_TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub trait ToBase64 {
    fn to_base64(&self) -> String;
}

impl<T: AsRef<[u8]>> ToBase64 for T {
    fn to_base64(&self) -> String {
        self::to_base64(self.as_ref())
    }
}

pub(crate) fn to_base64(input: &[u8]) -> String {
    let size = encoded_size(input.len());
    let mut buf = vec![0; size];

    encode_with_padding(input, size, &mut buf);

    String::from_utf8(buf).expect("Invalid utf-8")
}

pub(crate) const fn encoded_size(len: usize) -> usize {
    ((len + 2) / 3) * 4
}

fn encode_with_padding(input: &[u8], encoded_size: usize, output: &mut [u8]) {
    debug_assert_eq!(encoded_size, output.len());

    let b64_bytes = encode_to_slice(input, output);
    let padding = add_padding(input.len(), &mut output[b64_bytes..]);

    debug_assert_eq!(encoded_size, b64_bytes + padding);
}

fn encode_to_slice(input: &[u8], output: &mut [u8]) -> usize {
    use self::BASE64_TABLE as table;
    const LOW_SIX_BITS: u8 = 0x3f;

    let rem = input.len() % 3;
    let start_of_rem = input.len() - rem;

    let mut input_idx = 0;
    let mut output_idx = 0;

    while input_idx < start_of_rem {
        let input_chunk = &input[input_idx..(input_idx + 3)];
        let output_chunk = &mut output[output_idx..(output_idx + 4)];

        dbg!(input_chunk);

        output_chunk[0] = table[(input_chunk[0] >> 2) as usize];
        output_chunk[1] =
            table[((input_chunk[0] << 4 | input_chunk[1] >> 4) & LOW_SIX_BITS) as usize];
        output_chunk[2] =
            table[((input_chunk[1] << 2 | input_chunk[2] >> 6) & LOW_SIX_BITS) as usize];
        output_chunk[3] = table[(input_chunk[2] & LOW_SIX_BITS) as usize];

        input_idx += 3;
        output_idx += 4;
    }

    if rem == 2 {
        output[output_idx] = table[(input[start_of_rem] >> 2) as usize];
        output[output_idx + 1] = table
            [((input[start_of_rem] << 4) | (input[start_of_rem + 1] >> 4) & LOW_SIX_BITS) as usize];
        output[output_idx + 2] = table[((input[start_of_rem + 1] << 2) & LOW_SIX_BITS) as usize];

        output_idx += 3;
    } else if rem == 1 {
        output[output_idx] = table[(input[start_of_rem] >> 2) as usize];
        output[output_idx + 1] = table[((input[start_of_rem] << 4) & LOW_SIX_BITS) as usize];

        output_idx += 2;
    }

    output_idx
}

fn add_padding(len: usize, output: &mut [u8]) -> usize {
    const PAD_BYTE: u8 = b'=';

    let rem = len % 3;
    let mut idx = 0;

    for _ in 0..((3 - rem) % 3) {
        output[idx] = PAD_BYTE;
        idx += 1;
    }

    idx
}
