use cryptopals::encode::{from_ascii, from_base64, to_ascii};
use cryptopals::rsa::{
    decrypt_rsa_padding_oracle, decrypt_rsa_parity, decrypt_unpadded_rsa, forge_rsa, pad_pkcs15,
    rsa, rsa_keys, rsa_msg, unpad_pkcs15, validate_pkcs15_beginning,
};
use num_bigint::BigUint;

fn ex41(input: &str) -> String {
    let mut rng = rand::thread_rng();
    let msg = from_ascii(input);
    // get n pubkeys
    let (pub_key, priv_key, n) = rsa_keys(msg.len() as u64 * 8, &mut rng);
    let decr = |c: &BigUint| rsa(&priv_key, &n, c);
    let c = BigUint::from_bytes_be(&rsa_msg(&pub_key, &n, &msg));

    to_ascii(&decrypt_unpadded_rsa(&c, &pub_key, &n, decr).to_bytes_be())
}

fn ex42(input: &str) -> String {
    let mut rng = rand::thread_rng();
    let n = 1024;
    let msg = BigUint::from_bytes_be(&from_ascii(input));
    let mut pub_key = rsa_keys(n, &mut rng).0;
    while pub_key != 5u8.into() {
        pub_key = rsa_keys(1024, &mut rng).0;
    }
    let forged = forge_rsa(&msg, 5).pow(5);
    to_ascii(&forged.to_bytes_be())
}

fn ex46() -> String {
    let msg = from_base64("VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==");
    let msg_num = BigUint::from_bytes_be(&msg);
    let mut rng = rand::thread_rng();
    let (pubkey, privkey, n) = rsa_keys(1024, &mut rng);
    let o = |c: &BigUint| c.modpow(&privkey, &n).bit(0);
    let cipher = rsa(&pubkey, &n, &msg_num);
    let msg_decr = decrypt_rsa_parity(&cipher, &pubkey, &n, o);
    to_ascii(&msg_decr.to_bytes_be())
}

fn ex48(input: &str) -> String {
    let mut rng = rand::thread_rng();
    let bits = 1024;
    let bytes = bits / 8;
    let (pubkey, privkey, n) = rsa_keys(bits as u64, &mut rng);
    let msg = from_ascii(input);
    let msg_padded = pad_pkcs15(&msg, &n, &mut rng);
    let cipher = rsa(&pubkey, &n, &BigUint::from_bytes_be(&msg_padded));
    let o = |c: &BigUint| validate_pkcs15_beginning(&rsa(&privkey, &n, c), bytes);
    let decr = decrypt_rsa_padding_oracle(&cipher, &pubkey, &n, o);
    to_ascii(&unpad_pkcs15(decr.to_bytes_be()))
}

fn main() {
    println!("ex41:\n{}", ex41("This is a very serious message"));
    println!("ex42:\n{}", &ex42("hi mom")[0..6]);
    println!("ex46:\n{:?}", ex46());
    println!("ex48:\n{:?}", ex48("whazzawhazzawhazzzzzuuuup!"));
}
