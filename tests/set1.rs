use anyhow::Result;

use cryptopals_rs::*;

#[test]
fn challenge1() -> Result<()> {
    let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let output = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

    assert_eq!(from_hex(input)?.to_base64(), output);
    Ok(())
}

#[test]
fn challenge2() -> Result<()> {
    let a = "1c0111001f010100061a024b53535009181c";
    let b = "686974207468652062756c6c277320657965";

    let a = from_hex(a)?;
    let b = from_hex(b)?;

    assert_eq!(
        xor::xor(&a, &b).to_hex(),
        "746865206b696420646f6e277420706c6179"
    );

    Ok(())
}

#[test]
fn challenge3() -> Result<()> {
    use xor::break_single_byte_xor;
    let input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let input = from_hex(input)?;

    let (key, output) = break_single_byte_xor(&input, xor::metrics::score_by_character_freq);
    let output = String::from_utf8(output)?;

    println!("key:{key:#x} '{}', output: {output}", key.escape_ascii());

    // we know this is the answer after solving it
    assert_eq!(output, "Cooking MC's like a pound of bacon");

    Ok(())
}
