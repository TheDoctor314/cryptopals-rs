use crate::xor::hamming_distance;

mod hex {
    use crate::hex::*;

    #[test]
    fn test_from_hex() {
        assert_eq!(from_hex("6465616462656566").unwrap(), "deadbeef".as_bytes())
    }

    #[test]
    fn test_to_hex() {
        assert_eq!([0xde, 0xad, 0xbe, 0xef].to_hex(), "deadbeef");
        assert_eq!(b"deadbeef".to_hex(), "6465616462656566")
    }
}

#[test]
fn test_hamming_distance() {
    let a = b"this is a test";
    let b = b"wokka wokka!!!";

    assert_eq!(hamming_distance(a, b), 37);
}

mod aes {
    use crate::aes;

    #[test]
    fn test_xtime() {
        let mut word: u32 = 0x01;

        for expected in aes::RCON {
            assert_eq!(word, expected);

            word = aes::xtime(word);
        }
    }

    #[test]
    fn test_inv_mix_cols() {
        let output_vectors = [
            [0xdb, 0x13, 0x53, 0x45],
            [0xf2, 0x0a, 0x22, 0x5c],
            [0x01, 0x01, 0x01, 0x01],
            [0xc6, 0xc6, 0xc6, 0xc6],
            [0xd4, 0xd4, 0xd4, 0xd5],
            [0x2d, 0x26, 0x31, 0x4c],
        ];

        let input_vectors = [
            [0x8e, 0x4d, 0xa1, 0xbc],
            [0x9f, 0xdc, 0x58, 0x9d],
            [0x01, 0x01, 0x01, 0x01],
            [0xc6, 0xc6, 0xc6, 0xc6],
            [0xd5, 0xd5, 0xd7, 0xd6],
            [0x4d, 0x7e, 0xbd, 0xf8],
        ];

        for (input, expected) in input_vectors.into_iter().zip(output_vectors.into_iter()) {
            let word = u32::from_le_bytes(input);
            let actual = aes::inv_mix_word(word);

            assert_eq!(actual.to_le_bytes(), expected);
        }
    }

    #[test]
    fn test_round_keys() {
        let key: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];

        let expected: [u32; 44] = [
            0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c, 0xa0fafe17, 0x88542cb1, 0x23a33939,
            0x2a6c7605, 0xf2c295f2, 0x7a96b943, 0x5935807a, 0x7359f67f, 0x3d80477d, 0x4716fe3e,
            0x1e237e44, 0x6d7a883b, 0xef44a541, 0xa8525b7f, 0xb671253b, 0xdb0bad00, 0xd4d1c6f8,
            0x7c839d87, 0xcaf2b8bc, 0x11f915bc, 0x6d88a37a, 0x110b3efd, 0xdbf98641, 0xca0093fd,
            0x4e54f70e, 0x5f5fc9f3, 0x84a64fb2, 0x4ea6dc4f, 0xead27321, 0xb58dbad2, 0x312bf560,
            0x7f8d292f, 0xac7766f3, 0x19fadc21, 0x28d12941, 0x575c006e, 0xd014f9a8, 0xc9ee2589,
            0xe13f0cc8, 0xb6630ca6,
        ]
        .map(|w: u32| w.to_be());

        let actual = aes::create_round_keys(&key);

        assert_eq!(actual, expected);
    }
}
