use cryptopals_rs::*;

use anyhow::Result;
use expect_test::expect_file;

#[test]
fn challenge9() {
    let block = b"YELLOW SUBMARINE";

    let expected = b"YELLOW SUBMARINE\x04\x04\x04\x04";

    let actual = aes::pad(block, expected.len());
    assert_eq!(actual, expected);
}

#[test]
fn challenge10() -> Result<()> {
    let input = base64::from_base64_file("testdata/set2/10.txt")?;
    let key = b"YELLOW SUBMARINE";

    let cipher = aes::Aes128CBC::new(key);
    let mut output = vec![0u8; input.len()];
    cipher.decrypt(&input, &mut output, &[0u8; 16]);

    let plaintext = std::str::from_utf8(&output)?;
    expect_file!["../testdata/set2/10.out.txt"].assert_eq(plaintext);

    Ok(())
}
