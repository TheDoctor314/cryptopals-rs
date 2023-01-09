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
