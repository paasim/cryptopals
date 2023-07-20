use crate::math::{crt, div, inv_egcd, nth_root};
use crate::prime::mr_prime;
use num_bigint::BigUint;
use std::cmp::{max, min};

pub fn rsa_keys(s: u64, rng: &mut impl rand::Rng) -> (BigUint, BigUint, BigUint) {
    let p = mr_prime(s / 2 - 1, 10, rng);
    let mut q = mr_prime(s / 2 + 1 + s % 2, 10, rng);
    let mut n = &p * &q;
    while n.bits() != s {
        q = mr_prime(s / 2 + 1 + s % 2, 10, rng);
        n = &p * &q;
    }
    let et = (p - 1u8) * (q - 1u8);
    let mut e = BigUint::from(3u8);
    let mut d = inv_egcd(&e, &et);
    while d.is_none() {
        e += 2u8;
        d = inv_egcd(&e, &et);
    }
    let d = d.unwrap();
    (e, d, n)
}

pub fn rsa(key: &BigUint, n: &BigUint, m: &BigUint) -> BigUint {
    m.modpow(key, &n)
}

pub fn rsa_msg(key: &BigUint, n: &BigUint, m: &[u8]) -> Vec<u8> {
    let m = BigUint::from_bytes_be(m);
    rsa(key, n, &m).to_bytes_be()
}

pub fn decrypt_rsa_n<const N: usize>(ciphers: [(BigUint, BigUint); N]) -> BigUint {
    let x_n = crt(&ciphers).0;
    nth_root(x_n, N as u32)
}

pub fn decrypt_unpadded_rsa(
    cipher: &BigUint,
    pubkey: &BigUint,
    n: &BigUint,
    decr: impl Fn(&BigUint) -> BigUint,
) -> BigUint {
    let s = &BigUint::from(2u8);
    let c_ = (s.modpow(pubkey, n) * cipher) % n;
    let p_ = &decr(&c_);
    div(p_, s, n).expect("2 is not invertible mod n")
}

pub fn forge_rsa(msg: &BigUint, pubkey: u32) -> BigUint {
    let mut bits = msg.bits() * 8 * pubkey as u64;
    bits += bits % 8;
    let mut lower = nth_root(msg << bits, pubkey);
    let mut upper = nth_root((msg + 1u8) << bits, pubkey);
    while lower < upper {
        let m = (&lower + &upper) / 2u8;
        let msg_forged = m.pow(pubkey) >> bits;
        if &msg_forged == msg {
            return m;
        } else if &msg_forged < msg {
            upper = m;
        } else if lower == m {
            return lower;
        } else {
            lower = m;
        }
    }
    lower
}

pub fn decrypt_rsa_parity(
    cipher: &BigUint,
    pubkey: &BigUint,
    n: &BigUint,
    oracle: impl Fn(&BigUint) -> bool,
) -> BigUint {
    let mut plain = BigUint::from(0u8);
    let mut cipher = cipher.clone();
    let mut x = n >> 1;
    let two_to_e = &BigUint::from(2u8).modpow(pubkey, n);
    let odd = oracle(&cipher);
    for _ in 0..n.bits() {
        cipher = (cipher * two_to_e) % n;
        if oracle(&cipher) {
            plain += &x + 1u8;
        }
        x >>= 1;
    }
    if odd != plain.bit(0) {
        plain -= 1u8;
    }
    plain
}

// only for encryption
pub fn pad_pkcs15(v: &[u8], n: &BigUint, rng: &mut impl rand::Rng) -> Vec<u8> {
    let k = n.bits() / 8 + min(n.bits() % 8, 1);
    let d = v.len() as u64;
    if d > k - 11 {
        panic!("message too long for the modulus");
    }
    let ps = k - 3 - d;
    let mut msg_padded = vec![0, 2];
    for _ in 0..ps {
        msg_padded.push(rng.gen_range(1..=255));
    }
    msg_padded.push(0);
    msg_padded.extend(v);
    msg_padded
}

pub fn unpad_pkcs15(padded: Vec<u8>) -> Vec<u8> {
    let mut it = padded.into_iter();
    it.next().expect("not pkcs15 encryption-padding");
    it.next().expect("not pkcs15 encryption-padding");
    let mut it2 = it.skip_while(|b| b != &0u8);
    it2.next();
    it2.collect()
}

// only for encryption
pub fn validate_pkcs15_beginning(msg: &BigUint, bytes: usize) -> bool {
    let bs = msg.to_bytes_be();
    bs.len() == bytes - 1 && bs[0] == 2
}

fn b_(n: &BigUint) -> BigUint {
    let k = n.bits() / 8 + min(n.bits() % 8, 1);
    BigUint::from(1u8) << (8 * (k - 2))
}

fn merge_intervals<A: Ord>(mut v: Vec<(A, A)>) -> Vec<(A, A)> {
    v.sort();
    let mut intervals = v.into_iter();
    let mut merged = vec![intervals.next().expect("no intervals")];
    for (ln, un) in intervals {
        let l = merged.len() - 1;
        let u = &mut merged[l].1;
        if &ln <= u {
            if &un > u {
                *u = un;
            }
        } else {
            merged.push((ln, un));
        }
    }
    merged
}

fn search(
    cipher: &BigUint,
    pubkey: &BigUint,
    n: &BigUint,
    oracle: impl Fn(&BigUint) -> bool,
    s_prev: &BigUint,
) -> BigUint {
    let mut s = s_prev.clone();
    while !oracle(&(cipher * &s.modpow(pubkey, n) % n)) {
        s += 1u8;
    }
    s
}

fn search_within_interval(
    cipher: &BigUint,
    pubkey: &BigUint,
    n: &BigUint,
    oracle: impl Fn(&BigUint) -> bool,
    s_prev: &BigUint,
    (l, u): &(BigUint, BigUint),
) -> BigUint {
    let b = &b_(n);
    let mut r = 2u8 * (u * s_prev - 2u8 * b) / n;
    let mut s = (2u8 * b + &r * n) / u;
    let mut s_upper = (3u8 * b + &r * n) / l;
    while !oracle(&(cipher * &s.modpow(pubkey, n) % n)) {
        if s < s_upper {
            s += 1u8;
        } else {
            r += 1u8;
            s_upper = (3u8 * b + &r * n) / l;
            s = (2u8 * b + &r * n) / u;
        }
    }
    s
}

fn div_ceil(x: &BigUint, y: &BigUint) -> BigUint {
    x / y + min(x % y, 1u8.into())
}

fn narrow_intervals(
    n: &BigUint,
    s: &BigUint,
    m_prev: Vec<(BigUint, BigUint)>,
) -> Vec<(BigUint, BigUint)> {
    let mut m = vec![];
    let b = &b_(n);
    for (l, u) in m_prev {
        let mut r = (&l * s - 3u8 * b + 1u8) / n;
        let r_lim = (&u * s - 2u8 * b) / n;
        while r <= r_lim {
            let l = max(l.clone(), div_ceil(&(2u8 * b + &r * n), s));
            let u = min(u.clone(), (3u8 * b - 1u8 + &(&r * n)) / s);
            if l <= u {
                m.push((l, u))
            }
            r += 1u8;
        }
    }
    merge_intervals(m)
}

pub fn decrypt_rsa_padding_oracle(
    cipher: &BigUint,
    pubkey: &BigUint,
    n: &BigUint,
    oracle: impl Fn(&BigUint) -> bool,
) -> BigUint {
    assert!(oracle(cipher));
    // step 2a
    let b = &b_(n);
    let mut s = search(cipher, pubkey, n, &oracle, &div_ceil(n, &(3u8 * b)));
    let mut m = narrow_intervals(n, &s, vec![(2u8 * b, 3u8 * b - 1u8)]);

    while m.len() > 1 || m[0].0 != m[0].1 {
        //step 2
        if m.len() > 1 {
            s = search(cipher, pubkey, n, &oracle, &(&s + 1u8));
        } else {
            s = search_within_interval(cipher, pubkey, n, &oracle, &s, &m[0]);
        }
        // step 3
        m = narrow_intervals(n, &s, m);
    }
    return &m[0].0 % n;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode::{from_ascii, to_ascii, to_hex};
    use num_bigint::RandBigInt;
    use rand::Rng;

    #[test]
    fn rsa_msg_works() {
        let msg = from_ascii("This is a very serious message");
        let mut rng = rand::thread_rng();
        let (priv_key, pub_key, n) = rsa_keys(msg.len() as u64 * 8, &mut rng);
        let encr = rsa_msg(&pub_key, &n, &msg);
        assert!(!to_ascii(&encr).contains("This is a very serious message"));
        let decr = rsa_msg(&priv_key, &n, &encr);
        assert!(to_ascii(&decr).contains("This is a very serious message"));
    }

    #[test]
    fn decrypt_rsa_parity_works() {
        let n = BigUint::from(5u8 * 11u8);
        let mut rng = rand::thread_rng();
        let pub_key = BigUint::from(3u8);
        let priv_key = inv_egcd(&pub_key, &40u8.into()).expect("pubkey not invertible");
        let o = |c: &BigUint| c.modpow(&priv_key, &n).bit(0);
        let secret = rng.gen_biguint_range(&0u8.into(), &(&n - 1u8));
        let cipher = secret.modpow(&pub_key, &n);
        assert_eq!(cipher.modpow(&priv_key, &n), secret);
        let secret2 = decrypt_rsa_parity(&cipher, &pub_key, &n, o);
        assert_eq!(secret, secret2);
    }

    #[test]
    fn b_works() {
        let mut rng = rand::thread_rng();
        let x = rng.gen_biguint(256);
        let b = &b_(&x);
        let x_hex = to_hex(&x.to_bytes_be());
        let twob_hex = to_hex(&(2u8 * b).to_bytes_be());
        let threeb_hex = to_hex(&(3u8 * b).to_bytes_be());
        assert_eq!(x_hex.len() - 2, twob_hex.len());
        assert_eq!(x_hex.len() - 2, threeb_hex.len());
        assert_eq!(&twob_hex[0..2], "02");
        assert_eq!(&threeb_hex[0..2], "03");
    }

    #[test]
    fn merge_intervals_works() {
        let int = vec![(19, 20), (1, 5), (17, 18), (2, 3), (3, 17), (0, 1)];
        let merged = merge_intervals(int);
        assert_eq!(merged, vec![(0, 18), (19, 20)]);
    }

    #[test]
    fn validate_pkcs15_beginning_works() {
        let b = vec![0, 2, 1, 2, 3];
        assert!(validate_pkcs15_beginning(&BigUint::from_bytes_be(&b), 5));
        let b = vec![0, 2, 1, 2, 3, 7, 7];
        assert!(validate_pkcs15_beginning(&BigUint::from_bytes_be(&b), 7));
        let b = vec![1, 2, 1, 2, 3];
        assert!(!validate_pkcs15_beginning(&BigUint::from_bytes_be(&b), 5));
        let b = vec![0, 2, 1, 2, 3, 7, 7];
        assert!(!validate_pkcs15_beginning(&BigUint::from_bytes_be(&b), 5));
    }

    #[test]
    fn pad_pkcs15_works() {
        let mut rng = rand::thread_rng();
        let bits = 1024;
        let bytes = bits / 8;
        let x = rng.gen_biguint(bits);
        let mut msg = vec![];
        for _ in 0..bytes - rng.gen_range(11..=77) {
            msg.push(rng.gen());
        }
        let padded = BigUint::from_bytes_be(&pad_pkcs15(&msg, &x, &mut rng));
        assert!(validate_pkcs15_beginning(&padded, bytes as usize));
    }

    #[test]
    fn unpad_pkcs15_works() {
        let mut rng = rand::thread_rng();
        let bits = 1024;
        let bytes = bits / 8;
        let x = rng.gen_biguint(bits);
        let mut msg = vec![];
        for _ in 0..bytes - rng.gen_range(11..=77) {
            msg.push(rng.gen());
        }
        let padded = pad_pkcs15(&msg, &x, &mut rng);
        let unpadded = unpad_pkcs15(padded);
        assert_eq!(unpadded, msg)
    }

    #[test]
    fn decrypt_rsa_padding_oracle_works() {
        let mut rng = rand::thread_rng();
        let bits = 256;
        let bytes = bits / 8;
        let (pubkey, privkey, n) = rsa_keys(bits as u64, &mut rng);
        let msg = vec![7; 11];
        let msg_padded = pad_pkcs15(&msg, &n, &mut rng);
        let cipher = rsa(&pubkey, &n, &BigUint::from_bytes_be(&msg_padded));
        let o = |c: &BigUint| validate_pkcs15_beginning(&rsa(&privkey, &n, c), bytes);
        assert!(o(&cipher));
        let decr = decrypt_rsa_padding_oracle(&cipher, &pubkey, &n, o).to_bytes_be();
        assert_eq!(decr, msg_padded[1..]);
    }
}
