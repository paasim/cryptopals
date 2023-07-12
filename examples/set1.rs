use cryptopals::aes::inv_aes;
use cryptopals::block::ecb;
use cryptopals::encode::{block_from_ascii, from_base64, from_hex, to_ascii};
use cryptopals::xor::{
    multi_block_cipher_ks, single_block_cipher, single_block_ciphers, xor_slice,
};
use std::fs;

fn ex3() -> String {
    let str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let bytes = from_hex(str).expect("invalid hex string");
    let mut v: Vec<_> = single_block_cipher(&bytes, 3)
        .into_iter()
        .map(|(_, c)| {
            let mut b = bytes.clone();
            xor_slice(&mut b, &[c]);
            to_ascii(&b)
        })
        .collect();
    v.remove(0)
}

fn ex4() -> String {
    let file = fs::read_to_string("data/4.txt").expect("file missing");
    let bytes_v: Vec<_> = file
        .lines()
        .map(|l| from_hex(l))
        .collect::<Result<Vec<_>, _>>()
        .expect("invalid hex string");
    let bytes_v_ref: Vec<_> = bytes_v.iter().collect();
    let mut v: Vec<_> = single_block_ciphers(&bytes_v_ref, 3)
        .into_iter()
        .map(|(_, c, bs)| {
            let mut b = bs.clone();
            xor_slice(&mut b, &[c]);
            to_ascii(&b)
        })
        .collect();
    v.remove(0)
}

fn ex6() -> String {
    let file = fs::read_to_string("data/6.txt").expect("file missing");
    let file = file.lines().collect::<Vec<_>>().concat();
    let bytes = from_base64(&file);
    let mut v: Vec<_> = multi_block_cipher_ks(&bytes, 30, 3)
        .into_iter()
        .map(|(_, k)| {
            let mut b = bytes.clone();
            xor_slice(&mut b, &k);
            to_ascii(&b)
        })
        .take(1)
        .collect();
    v.remove(0)
}

fn ex7() -> String {
    let file = fs::read_to_string("data/7.txt").expect("file missing");
    let input: String = file.lines().collect::<Vec<_>>().concat();
    let bytes = from_base64(&input);
    let key = block_from_ascii("YELLOW SUBMARINE");
    let decr = ecb(&bytes, &key, inv_aes).expect("incorrect bs");
    to_ascii(&decr)
}

fn main() {
    println!("ex3:\n{}", ex3());
    println!("ex4:\n{}", ex4());
    println!("ex6:\n{}", ex6().chars().take(200).collect::<String>());
    println!("ex7:\n{}", ex7().chars().take(200).collect::<String>());
}
