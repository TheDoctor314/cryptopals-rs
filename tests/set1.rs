use std::{
    fs::File,
    io::{BufRead, BufReader},
};

use anyhow::Result;
use expect_test::{expect, expect_file};

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

    let xor::DecodeSingleByteXorResult { key: _, plaintext } =
        break_single_byte_xor(&input, xor::metrics::score_by_character_freq);
    let output = std::str::from_utf8(&plaintext)?;

    // we know this is the answer after solving it
    expect!["Cooking MC's like a pound of bacon"].assert_eq(output);

    Ok(())
}

#[test]
fn challenge4() -> Result<()> {
    let reader = BufReader::new(File::open("testdata/set1/4.txt")?);

    // We just iterate over all the lines and ask for the output after xor with possible keys.
    // The output with the lowest score is the line encrypted with single key xor.
    let output = reader
        .lines()
        .filter_map(|line| from_hex(&line.unwrap()).ok())
        .flat_map(|line| (0..128).map(move |key| xor::repeating_xor(&line, &[key])))
        .min_by_key(|line| xor::metrics::score_by_character_freq(line))
        .unwrap();

    let output = std::str::from_utf8(&output)?;

    println!("Output: {output}");

    // we know this is the answer after solving it
    expect!["Now that the party is jumping\n"].assert_eq(output);

    Ok(())
}

#[test]
fn challenge5() -> Result<()> {
    let input = r#"Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"#;
    let key = b"ICE";

    let output = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";

    assert_eq!(xor::repeating_xor(input.as_bytes(), key), from_hex(output)?);
    Ok(())
}

#[test]
fn challenge6() -> Result<()> {
    let input = base64::from_base64_file("testdata/set1/6.txt")?;
    let xor::DecodeRepeatingKeyXorResult { key, plaintext } = xor::break_repeating_key_xor(&input);
    let output = std::str::from_utf8(&plaintext)?;

    let key = std::str::from_utf8(&key)?;
    expect!["Terminator X: Bring the noise"].assert_eq(key);
    expect_file!["../testdata/set1/6.out.txt"].assert_eq(output);

    Ok(())
}

#[test]
fn challenge7() -> Result<()> {
    let input = base64::from_base64_file("testdata/set1/7.txt")?;
    let key = b"YELLOW SUBMARINE";

    let cipher = aes::Aes128ECB::new(key);
    let mut output = vec![0u8; input.len()];
    cipher.decrypt(&input, &mut output);

    let plaintext = std::str::from_utf8(&output)?;
    expect_file!["../testdata/set1/7.out.txt"].assert_eq(plaintext);

    Ok(())
}

#[test]
fn challenge8() -> Result<()> {
    let reader = BufReader::new(File::open("testdata/set1/8.txt")?);

    const BLOCK_SIZE: usize = 16;

    let lines: Vec<_> = reader.lines().collect::<Result<_, _>>()?;
    let candidate = lines
        .iter()
        .map(|line| line.as_bytes())
        .find(|line| {
            let num_blocks = line.len() / (2 * BLOCK_SIZE);

            use std::collections::HashSet;
            let set: HashSet<_> = line.chunks_exact(2 * BLOCK_SIZE).collect();

            set.len() != num_blocks
        })
        .expect("Should have found an aes-128-ecb ciphertext");

    let candidate = std::str::from_utf8(candidate)?;
    expect!["d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a"].assert_eq(candidate);

    Ok(())
}
