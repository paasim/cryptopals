use cryptopals::aes::{aes, inv_aes};
use cryptopals::block::{cbc_decr, decrypt_padded_ecb, ecb, pad_with, rand_key};
use cryptopals::encode::{block_from_ascii, from_base64, to_ascii};
use rand::Rng;
use std::fs;

fn ex10() -> String {
    let file = fs::read_to_string("data/10.txt").expect("file missing");
    let input: String = file.lines().collect::<Vec<_>>().concat();
    let bytes = from_base64(&input);

    let key = block_from_ascii("YELLOW SUBMARINE");
    let iv = [0u8; 16];

    let decr = cbc_decr(&bytes, &key, &iv, inv_aes).expect("incorrect bs");
    to_ascii(&decr)
}

fn ex14() -> String {
    let mut str = String::from("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg");
    str += "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq";
    str += "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg";
    str += "YnkK";
    let postfix = from_base64(&str);
    let mut rng = rand::thread_rng();
    let n_pre = rng.gen_range(0..=17);
    let prefix: Vec<_> = (0..n_pre).map(|_| rng.gen()).collect();
    let key = rand_key(&mut rng);
    let encr = |v: &[u8]| {
        ecb(&pad_with(&prefix, &v, &postfix, 16), &key, aes).expect("should have been padded")
    };
    let decr = decrypt_padded_ecb(&encr).expect("should have been padded");
    to_ascii(&decr)
}

fn main() {
    println!("ex10:\n{}", ex10().chars().take(200).collect::<String>());
    println!("ex14:\n{}", ex14().chars().take(200).collect::<String>());
}
