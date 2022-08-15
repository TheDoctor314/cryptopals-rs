mod base64 {
    use crate::base64::*;

    #[test]
    fn test_encoded_size() {
        assert_eq!(encoded_size(0), 0);

        assert_eq!(encoded_size(1), 4);
        assert_eq!(encoded_size(2), 4);
        assert_eq!(encoded_size(3), 4);

        assert_eq!(encoded_size(4), 8);
        assert_eq!(encoded_size(5), 8);
        assert_eq!(encoded_size(6), 8);

        assert_eq!(encoded_size(7), 12);
        assert_eq!(encoded_size(8), 12);
        assert_eq!(encoded_size(9), 12);

        assert_eq!(encoded_size(54), 72);

        assert_eq!(encoded_size(55), 76);
        assert_eq!(encoded_size(56), 76);
        assert_eq!(encoded_size(57), 76);

        assert_eq!(encoded_size(58), 80);
    }

    #[test]
    fn test_to_base64() {
        let input = b"Many hands make light work.";
        assert_eq!(to_base64(input), "TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu");
    }
}

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
