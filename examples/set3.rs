use cryptopals::aes::{aes, inv_aes};
use cryptopals::block::{
    cbc_encr, check_cbc_padding, decrypt_cbc_oracle, pad_pkcs7, rand_key, unpad_pkcs7,
};
use cryptopals::encode::{block_from_ascii, from_base64, to_ascii};
use cryptopals::stream::{break_ctr_blocks, ctr, get_mt19937_seed, mt19937};
use rand::seq::SliceRandom;
use rand::Rng;
use std::fs;

fn ex17() -> String {
    let mut inputs = [
        "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
        "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
        "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
        "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
        "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
        "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
        "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
        "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
        "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
        "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
        "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
    ]
    .map(from_base64);
    const N: usize = 16;
    let mut rng = rand::thread_rng();
    let key = rand_key(&mut rng);
    let iv = rand_key(&mut rng);
    let mut input = inputs.choose_mut(&mut rng).expect("empty array");
    pad_pkcs7(&mut input, N as u8);
    let encr = cbc_encr(&input, &key, &iv, aes).expect("should have been padded");
    pad_pkcs7(input, N as u8);

    let oracle = |v: &[u8; N], iv: &[u8; N]| check_cbc_padding(v, &key, iv, inv_aes);
    let v = decrypt_cbc_oracle(&encr, &iv, &oracle).and_then(unpad_pkcs7);
    to_ascii(&v.expect("should have been padded"))
}

fn ex18() -> String {
    let str = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";
    let input = from_base64(str);
    let key = block_from_ascii("YELLOW SUBMARINE");
    let nonce = 0;

    let v = ctr(&input, &key, nonce, aes);
    to_ascii(&v)
}

fn ex19() -> String {
    let file = fs::read_to_string("data/19.txt").expect("file missing");
    let lines: Vec<_> = file.lines().map(from_base64).collect();
    let mut rng = rand::thread_rng();
    let key = rand_key(&mut rng);
    let nonce = 0;
    let encrs: Vec<_> = lines
        .into_iter()
        .map(|ln| ctr(&ln, &key, nonce as u64, aes))
        .collect();
    let decrs = break_ctr_blocks(&encrs);
    let lines: Vec<_> = decrs.iter().map(|x| to_ascii(x)).collect();
    lines.join("\n")
}

fn ex20() -> String {
    let file = fs::read_to_string("data/20.txt").expect("file missing");
    let encrs: Vec<_> = file.lines().map(from_base64).collect();
    let decrs = break_ctr_blocks(&encrs);
    let lines: Vec<_> = decrs.iter().map(|x| to_ascii(x)).collect();
    lines.join("\n")
}

fn ex24() -> String {
    let mut rng = rand::thread_rng();
    let key = rng.gen();
    let encr = |arr: &[u8]| mt19937(arr, key, &mut rng);
    let key_inferred = get_mt19937_seed(encr);
    format!("key: {}, inferred: {}", key, key_inferred.unwrap())
}

fn main() {
    println!("ex17:\n{}", ex17());
    println!("ex18:\n{}", ex18());
    println!("ex19:\n{}", ex19().chars().take(200).collect::<String>());
    println!("ex20:\n{}\n", ex20().chars().take(200).collect::<String>());
    println!("ex24:\n{}", ex24());
}
