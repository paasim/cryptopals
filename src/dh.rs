use crate::digest::sha1;
use crate::math::inv_egcd;
use crate::prime::mr_prime;
use num_bigint::{BigUint, RandBigInt};

pub fn dh_keys(p: &BigUint, g: BigUint, r: &mut impl rand::Rng) -> (BigUint, BigUint) {
    let privkey = r.gen_biguint_range(&2u8.into(), p);
    let pubkey = g.modpow(&privkey, p);
    (privkey, pubkey)
}

pub fn dh_session_key(p: &BigUint, pb0: BigUint, priv1: &BigUint) -> [u8; 16] {
    let s = pb0.modpow(priv1, p);
    let mut res = [0u8; 16];
    res.swap_with_slice(&mut sha1(&s.to_bytes_le())[..16]);
    res
}

pub fn rsa_keys(s: u32) -> (BigUint, BigUint, BigUint) {
    let p = mr_prime(s, 5);
    let q = mr_prime(s << 1, 5);
    let n = p.clone() * q.clone();
    let et = (p - 1u8) * (q - 1u8);
    let mut e = 3u16;
    let mut d = inv_egcd(e.into(), et.clone());
    while d.is_none() {
        e += 2;
        d = inv_egcd(e.into(), et.clone());
    }
    let d = d.unwrap();
    (e.into(), d, n)
}

fn rsa(key: &BigUint, n: &BigUint, m: BigUint) -> BigUint {
    m.modpow(key, &n)
}

pub fn rsa_msg(key: &BigUint, n: &BigUint, m: &[u8]) -> Vec<u8> {
    let m = BigUint::from_bytes_be(m);
    rsa(key, n, m).to_bytes_be()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode::{from_ascii, from_hex, to_ascii};

    #[test]
    fn gen_key_works() {
        let mut rng = rand::thread_rng();
        let p = 37u8.into();
        let g = 5u8;
        let (priv0, pb0) = dh_keys(&p, g.into(), &mut rng);
        let (priv1, pb1) = dh_keys(&p, g.into(), &mut rng);
        let s0 = dh_session_key(&p, pb1.clone(), &priv0);
        let s1 = dh_session_key(&p, pb0.clone(), &priv1);
        assert_eq!(s0, s1)
    }

    #[test]
    fn gen_key_works_with_bigger_numbers() {
        let mut rng = rand::thread_rng();
        let p_str = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
fffffffffffff"
            .lines()
            .collect::<String>();
        let p_bytes = from_hex(&p_str).expect("not a hexstring");
        let p = BigUint::from_bytes_be(&p_bytes);
        let g = 2u8;
        let (priv0, pb0) = dh_keys(&p, g.into(), &mut rng);
        let (priv1, pb1) = dh_keys(&p, g.into(), &mut rng);
        let s0 = dh_session_key(&p, pb1.clone(), &priv0);
        let s1 = dh_session_key(&p, pb0.clone(), &priv1);
        assert_eq!(s0, s1)
    }

    #[test]
    fn bad_g_is_predictable() {
        let mut rng = rand::thread_rng();
        let p_str = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
fffffffffffff"
            .lines()
            .collect::<String>();
        let p_bytes = from_hex(&p_str).expect("not a hexstring");
        let p = BigUint::from_bytes_be(&p_bytes);
        let g = 1u8;
        let (priv0, _) = dh_keys(&p, g.into(), &mut rng);
        let (_, pb1) = dh_keys(&p, g.into(), &mut rng);
        let s0 = dh_session_key(&p, pb1.clone(), &priv0);
        assert_eq!(s0, sha1(&[1])[..16]);

        let g = p.clone();
        let (priv0, _) = dh_keys(&p, g.clone(), &mut rng);
        let (_, pb1) = dh_keys(&p, g.into(), &mut rng);
        let s0 = dh_session_key(&p, pb1.clone(), &priv0);
        assert_eq!(s0, sha1(&[0])[..16]);

        let g = p.clone() - 1u8;
        let (priv0, pb0) = dh_keys(&p, g.clone(), &mut rng);
        let (priv1, pb1) = dh_keys(&p, g.clone(), &mut rng);
        println!("{} {} {} {}", priv0, pb0, priv1, pb1);
        let s0 = dh_session_key(&p, pb1.clone(), &priv0);
        let e1 = &sha1(&[1])[..16];
        let eg = &sha1(&g.to_bytes_le())[..16];
        assert!((s0 == e1) | (s0 == eg));
    }

    #[test]
    fn rsa_msg_works() {
        let msg = from_ascii("This is a very serious message");
        let (priv_key, pub_key, n) = rsa_keys(msg.len() as u32 * 8);
        let encr = rsa_msg(&pub_key, &n, &msg);
        assert!(!to_ascii(&encr).contains("This is a very serious message"));
        let decr = rsa_msg(&priv_key, &n, &encr);
        assert!(to_ascii(&decr).contains("This is a very serious message"));
    }
}
