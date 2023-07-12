use cryptopals::aes::{aes, inv_aes};
use cryptopals::block::{ecb, rand_key};
use cryptopals::encode::{block_from_ascii, from_base64, to_ascii};
use cryptopals::stream::{ctr, decrypt_ctr, edit_block};
use rand::Rng;
use std::fs;

fn ex25() -> String {
    let file = fs::read_to_string("data/25.txt").expect("file missing");
    let encr_data: Vec<_> = file.lines().map(from_base64).flatten().collect();
    let ecb_key = block_from_ascii("YELLOW SUBMARINE");
    let data = ecb(&encr_data, &ecb_key, inv_aes).expect("incorrect bs");
    let mut rng = rand::thread_rng();
    let key = rand_key(&mut rng);
    let nonce = rng.gen();
    let encr = ctr(&data, &key, nonce, aes);
    let edit = |arr: &mut [u8], new_block: &[u8; 16], block_pos: usize| {
        edit_block(arr, new_block, block_pos, &key, nonce, aes)
    };
    let decr = decrypt_ctr(&encr, edit);
    to_ascii(&decr)
}


fn main() {
    println!("ex25:\n{}", ex25().chars().take(200).collect::<String>());
}
