use cryptopals::encode::{from_ascii, to_ascii};
use cryptopals::rsa::{decrypt_rsa_n, rsa_keys, rsa_msg};
use num_bigint::BigUint;

fn ex40(input: &str) -> String {
    let msg = from_ascii(input);
    // get n pubkeys
    let mut keys = [1, 2, 3, 4, 5].map(|_| (0u8.into()));
    let pubk = 5;
    let mut i = 0;
    let mut rng = rand::thread_rng();
    while i < pubk {
        let (pub_key, _, n) = rsa_keys(msg.len() as u64 * 8, &mut rng);
        if pub_key == pubk.into() {
            keys[i] = n;
            i += 1;
        }
    }
    // encrypt same message n times
    let ciphers = keys
        .clone()
        .map(|n| (BigUint::from_bytes_be(&rsa_msg(&pubk.into(), &n, &msg)), n));
    // decrypt
    to_ascii(&decrypt_rsa_n(ciphers).to_bytes_be())
}

fn main() {
    println!("ex40:\n{}", ex40("This is a very serious message"));
}
