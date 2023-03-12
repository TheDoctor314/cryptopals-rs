use cryptopals_rs::*;

#[test]
fn challenge9() {
    let block = b"YELLOW SUBMARINE";

    let expected = b"YELLOW SUBMARINE\x04\x04\x04\x04";

    let actual = aes::pad(block, expected.len());
    assert_eq!(actual, expected);
}
