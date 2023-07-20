use crate::math::{div, inv_egcd};
use crate::prime::pq;
use num_bigint::{BigUint, RandBigInt};

pub fn dsa_parameters(n: u64, l: u64, rng: &mut impl rand::Rng) -> (BigUint, BigUint, BigUint) {
    let (p, q) = pq(l, n, 5, rng);
    let r = (&p - 1u8) / &q;

    let mut g = (rng.gen_biguint_below(&(&p - 4u8)) + 2u8).modpow(&r, &p);
    while g == 1u8.into() {
        g = (rng.gen_biguint_below(&(&p - 4u8)) + 2u8).modpow(&r, &p);
    }
    (p, q, g)
}

pub fn dsa_keys<R: rand::Rng>(
    p: &BigUint,
    q: &BigUint,
    g: &BigUint,
    rng: &mut R,
) -> (BigUint, BigUint) {
    let x = rng.gen_biguint_range(&1u8.into(), &(q - 1u8));
    let y = g.modpow(&x, &p);
    (x, y)
}

pub fn dsa_sign<R: rand::Rng>(
    x: &BigUint,
    hm: &BigUint,
    p: &BigUint,
    q: &BigUint,
    g: &BigUint,
    rng: &mut R,
) -> (BigUint, BigUint) {
    let mut k = rng.gen_biguint_range(&1u8.into(), &(q - 1u8));
    let mut r = g.modpow(&k, p) % q;
    let mut s = div(&(hm + x * &r), &k, q).expect("k is not invertible");
    while r == 0u8.into() || s == 0u8.into() {
        k = rng.gen_biguint_range(&1u8.into(), &(q - 1u8));
        r = g.modpow(&k, p) % q;
        s = div(&(hm + x * &r), &k, q).expect("k is not invertible");
    }
    (r, s)
}

pub fn dsa_verify(
    y: &BigUint,
    r: &BigUint,
    s: &BigUint,
    hm: &BigUint,
    p: &BigUint,
    q: &BigUint,
    g: &BigUint,
) -> bool {
    let zero = BigUint::from(0u8);
    if r == &zero || s == &zero || r >= q || s >= q {
        return false;
    }
    let w = match inv_egcd(s, q) {
        Some(w) => w,
        None => return false,
    };
    let u1 = hm * &w % q;
    let u2 = r * &w % q;
    let v = (g.modpow(&u1, p) * y.modpow(&u2, p)) % p % q;
    &v == r
}

pub fn dsa_privkey(k: &BigUint, r: &BigUint, s: &BigUint, hm: &BigUint, q: &BigUint) -> BigUint {
    div(&((s * k) + q - hm % q), r, q).expect("r is not invertible")
}

pub fn infer_dsa_key(
    y: &BigUint,
    r: &BigUint,
    s: &BigUint,
    hm: &BigUint,
    p: &BigUint,
    q: &BigUint,
    g: &BigUint,
    min_k: usize,
    max_k: usize,
) -> Option<(BigUint, BigUint)> {
    let g_to_sri = g.modpow(&(div(s, r, q).expect("r is not invertible")), p);
    let mut k = min_k;
    let mut y_ = g.modpow(&dsa_privkey(&k.into(), r, s, hm, q), p);
    while k <= max_k {
        if &y_ == y {
            return Some((k.into(), dsa_privkey(&k.into(), r, s, hm, q)));
        }
        y_ = (y_ * &g_to_sri) % p;
        k += 1;
    }
    None
}

pub fn infer_repeated_dsa_key(
    y: &BigUint,
    p: &BigUint,
    q: &BigUint,
    g: &BigUint,
    v: &[(BigUint, BigUint, BigUint)],
) -> Option<(BigUint, BigUint)> {
    for i in 0..v.len() - 1 {
        let (m1, s1, r1) = &v[i];
        for j in i + 1..v.len() {
            let (m2, s2, _) = &v[j];
            if let Some(sd) = inv_egcd(&((s1 + q - s2 % q) % q), q) {
                let k = (m1 + q - m2 % q) * sd % q;
                let x = dsa_privkey(&k, r1, s1, m1, q);
                if &g.modpow(&x, &p) == y {
                    return Some((k, x));
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::str::Lines;

    use super::*;
    use crate::digest::sha1;
    use crate::encode::{from_ascii, to_hex};
    use rand::Rng;

    fn y() -> BigUint {
        let str: String = "84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4
abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004
e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed
1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07b
bb283e6633451e535c45513b2d33c99ea17"
            .lines()
            .collect();
        BigUint::parse_bytes(&str.as_bytes(), 16).expect("not a valid hexstring")
    }

    fn y2() -> BigUint {
        let str: String = "2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c
9c1a3a26c95105d915e2d8cdf26d056b86b8a7b85519b1c23cc3
ecdc6062650462e3063bd179c2a6581519f674a61f1d89a1fff2
7171ebc1b93d4dc57bceb7ae2430f98a6a4d83d8279ee65d71c1
203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821"
            .lines()
            .collect();
        BigUint::parse_bytes(&str.as_bytes(), 16).expect("not a valid hexstring")
    }

    fn r() -> BigUint {
        BigUint::parse_bytes(b"548099063082341131477253921760299949438196259240", 10)
            .expect("not a valid hexstring")
    }
    fn s() -> BigUint {
        BigUint::parse_bytes(b"857042759984254168557880549501802188789837994940", 10)
            .expect("not a valid hexstring")
    }

    fn p() -> BigUint {
        let str: String = "800000000000000089e1855218a0e7dac38136ffafa72eda7
859f2171e25e65eac698c1702578b07dc2a1076da241c76c6
2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe
ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2
b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87
1a584471bb1"
            .lines()
            .collect();
        BigUint::parse_bytes(&str.as_bytes(), 16).expect("not a valid hexstring")
    }
    fn q() -> BigUint {
        BigUint::parse_bytes(b"f4f47f05794b256174bba6e9b396a7707e563c5b", 16)
            .expect("not a valid hexstring")
    }
    fn g() -> BigUint {
        let str: String = "5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119
458fef538b8fa4046c8db53039db620c094c9fa077ef389b5
322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047
0f5b64c36b625a097f1651fe775323556fe00b3608c887892
878480e99041be601a62166ca6894bdd41a7054ec89f756ba
9fc95302291"
            .lines()
            .collect();
        BigUint::parse_bytes(&str.as_bytes(), 16).expect("not a valid hexstring")
    }
    fn hm() -> BigUint {
        let m = "For those that envy a MC it can be hazardous to your health
So be friendly, a matter of life and death, just like a etch-a-sketch
";
        BigUint::from_bytes_be(&sha1(&from_ascii(m)))
    }

    #[test]
    fn dsa_verify_works() {
        let y = y();
        let r = r();
        let s = s();
        let p = p();
        let q = q();
        let g = g();
        let hm = hm();
        assert!(dsa_verify(&y, &r, &s, &hm, &p, &q, &g));
        assert!(!dsa_verify(&y, &(&r + 1u8), &s, &hm, &p, &q, &g));
        assert!(!dsa_verify(&y, &r, &(&s + 1u8), &hm, &p, &q, &g));
    }

    #[test]
    fn infer_dsa_key_works() {
        let y = y();
        let r = r();
        let s = s();
        let p = p();
        let q = q();
        let g = g();
        let hm = hm();
        let (_, x) = infer_dsa_key(&y, &r, &s, &hm, &p, &q, &g, 1, 65536).expect("no valid x");
        let x_hash = to_hex(&sha1(&from_ascii(&to_hex(&x.to_bytes_be()))));
        assert_eq!(x_hash, "0954edd5e0afe5542a4adf012611a91912a3ec16");
    }

    fn parse_44_record(lns: &mut Lines) -> Option<(BigUint, BigUint, BigUint)> {
        let msg = from_ascii(&lns.next()?.split_once(": ")?.1);
        let hm = BigUint::from_bytes_be(&sha1(&msg));
        let s = BigUint::parse_bytes(&from_ascii(&lns.next()?.split_once(": ")?.1), 10);
        let r = BigUint::parse_bytes(&from_ascii(&lns.next()?.split_once(": ")?.1), 10);
        let _m = lns.next()?.split_once(": ")?.1; // this is inferred from msg
        Some((hm, s?, r?))
    }

    #[test]
    fn infer_repeated_dsa_key_works() {
        let y = y2();
        let p = p();
        let q = q();
        let g = g();
        let file = fs::read_to_string("data/44.txt").expect("file missing");
        let mut lns = file.lines();
        let mut records = vec![];
        while let Some(r) = parse_44_record(&mut lns) {
            records.push(r);
        }
        assert_eq!(records.len(), 11);

        let keys = infer_repeated_dsa_key(&y, &p, &q, &g, &records);
        assert!(keys.is_some());
        let x = keys.expect("k and x not found").1;
        let x_hash = to_hex(&sha1(&from_ascii(&to_hex(&x.to_bytes_be()))));
        assert_eq!(x_hash, "ca8f6f7c66fa362d40760d135b763eb8527d3d52");
    }

    #[test]
    fn dsa_sign_works() {
        let hm = BigUint::from_bytes_be(&sha1(&from_ascii("Shoutout to his family")));
        let mut rng = rand::thread_rng();
        let (p, q, g) = dsa_parameters(160, 1024, &mut rng);
        let (x, y) = dsa_keys(&p, &q, &g, &mut rng);
        let (r, s) = dsa_sign(&x, &hm, &p, &q, &g, &mut rng);
        assert!(dsa_verify(&y, &r, &s, &hm, &p, &q, &g));
        let s_ = &s + rng.gen_range(1u8..255u8);
        assert!(!dsa_verify(&y, &r, &s_, &hm, &p, &q, &g));
        let r_ = &r + rng.gen_range(1u8..255u8);
        assert!(!dsa_verify(&y, &r_, &s, &hm, &p, &q, &g));
        let y_ = &y + rng.gen_range(1u8..255u8);
        assert!(!dsa_verify(&y_, &r, &s, &hm, &p, &q, &g));
        assert!(!dsa_verify(&y_, &r_, &s_, &hm, &p, &q, &g));
    }
}
