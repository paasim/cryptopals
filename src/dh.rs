use crate::digest::sha1;
use crate::math::{crt, disc_log_incr, div, pollard_lambda};
use crate::prime::factors_up_to;
use num_bigint::{BigUint, RandBigInt};

pub fn dh_keys(p: &BigUint, g: &BigUint, rng: &mut impl rand::Rng) -> (BigUint, BigUint) {
    let privkey = rng.gen_biguint_range(&2u8.into(), p);
    let pubkey = g.modpow(&privkey, p);
    (pubkey, privkey)
}

pub fn dh_session_key(p: &BigUint, pb0: &BigUint, priv1: &BigUint) -> [u8; 16] {
    let s = pb0.modpow(priv1, p);
    let mut res = [0u8; 16];
    res.swap_with_slice(&mut sha1(&s.to_bytes_le())[..16]);
    res
}

pub fn subgroups(
    p: &BigUint,
    q: &BigUint,
    b: u32,
    rng: &mut impl rand::Rng,
) -> Vec<(usize, BigUint)> {
    let pm1 = &(p - 1u8);
    let j = pm1 / q;
    let factors = factors_up_to(&j, 2usize.pow(b));
    let mut orders = vec![];
    let one = BigUint::from(1u8);
    let fp: &BigUint = &factors
        .iter()
        .map(|(f, e)| BigUint::from(*f).pow(*e))
        .product();
    for (f, e) in factors {
        let mut f = f;
        if fp < q {
            f = f.pow(e);
        }
        assert!(pm1 % f == 0u8.into());
        let mut h = rng.gen_biguint_range(&1u8.into(), p).modpow(&(pm1 / f), p);
        while h == one {
            h = rng.gen_biguint_range(&1u8.into(), p).modpow(&(pm1 / f), p);
        }
        orders.push((f, h))
    }
    orders
}

pub fn get_privkey_mod_from_crt(
    subgroups: &[(usize, BigUint)],
    p: &BigUint,
    sign: impl Fn(&BigUint) -> BigUint,
) -> Option<(BigUint, BigUint)> {
    subgroups
        .into_iter()
        .map(|(f, h)| {
            let f = BigUint::from(*f);
            // log(h ^ x mod p) = x % r (when h is of order r)
            let lhx = disc_log_incr(p, &f, h, &sign(h))?;
            Some((lhx, f))
        })
        .collect::<Option<Vec<_>>>()
        .map(|v| crt(&v))
}

pub fn get_privkey_from_rem(
    p: &BigUint,
    q: &BigUint,
    g: &BigUint,
    y: &BigUint,
    n: &BigUint,
    r: &BigUint,
) -> Option<BigUint> {
    let g_ = &g.modpow(r, p);
    let y_ = &div(y, &g.modpow(n, p), p)?;
    let ul = (q - 1u8) / r;
    let k = ul.bits() as u8 / 2;
    let m = pollard_lambda(p, g_, y_, &0u8.into(), &ul, k, 4)?;
    Some(n + m * r)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode::from_hex;
    use crate::prime::{mr_prime, pq};

    #[test]
    fn gen_key_works() {
        let mut rng = rand::thread_rng();
        let p = 37u8.into();
        let g = 5u8.into();
        let (pb0, priv0) = dh_keys(&p, &g, &mut rng);
        let (pb1, priv1) = dh_keys(&p, &g, &mut rng);
        let s0 = dh_session_key(&p, &pb1, &priv0);
        let s1 = dh_session_key(&p, &pb0, &priv1);
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
        let p = BigUint::from_bytes_be(&from_hex(&p_str));
        let g = BigUint::from(2u8);
        let (pb0, priv0) = dh_keys(&p, &g, &mut rng);
        let (pb1, priv1) = dh_keys(&p, &g, &mut rng);
        let s0 = dh_session_key(&p, &pb1, &priv0);
        let s1 = dh_session_key(&p, &pb0, &priv1);
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
        let p_bytes = from_hex(&p_str);
        let p = BigUint::from_bytes_be(&p_bytes);
        let g = BigUint::from(1u8);
        let (_, priv0) = dh_keys(&p, &g, &mut rng);
        let (pb1, _) = dh_keys(&p, &g, &mut rng);
        let s0 = dh_session_key(&p, &pb1, &priv0);
        assert_eq!(s0, sha1(&[1])[..16]);

        let g = p.clone();
        let (_, priv0) = dh_keys(&p, &g, &mut rng);
        let (pb1, _) = dh_keys(&p, &g, &mut rng);
        let s0 = dh_session_key(&p, &pb1, &priv0);
        assert_eq!(s0, sha1(&[0])[..16]);

        let g = p.clone() - 1u8;
        let (_, priv0) = dh_keys(&p, &g, &mut rng);
        let (pb1, _) = dh_keys(&p, &g, &mut rng);
        let s0 = dh_session_key(&p, &pb1, &priv0);
        let e1 = &sha1(&[1])[..16];
        let eg = &sha1(&g.to_bytes_le())[..16];
        assert!((s0 == e1) | (s0 == eg));
    }

    #[test]
    fn get_privkey_from_crt_works() {
        let mut rng = rand::thread_rng();
        let p = &BigUint::parse_bytes(b"7199773997391911030609999317773941274322764333428698921736339643928346453700085358802973900485592910475480089726140708102474957429903531369589969318716771", 10).expect("not a number");
        let q = &BigUint::parse_bytes(b"236234353446506858198510045061214171961", 10)
            .expect("not a number");
        let subs = subgroups(&p, &q, 16, &mut rng);

        let privkey = rng.gen_biguint_range(&2u8.into(), q);
        let sign = |msg: &BigUint| msg.modpow(&privkey, &p);
        let (pk, _) = get_privkey_mod_from_crt(&subs, p, sign).expect("pk not found");
        assert_eq!(pk, privkey);
    }

    #[test]
    fn get_privkey_from_rem_works() {
        let mut rng = rand::thread_rng();
        let k = 5;
        let (p, q) = &pq(1024, 256, k, &mut rng);
        let privkey = rng.gen_biguint_range(&2u8.into(), &(q - 2u8));
        let r = &mr_prime(236, k, &mut rng);
        let n = &privkey % r;
        assert_ne!(privkey, n); // not completely revealed by mod r
        let g = &rng.gen_biguint_range(&2u8.into(), &(p - 2u8));
        let y = &g.modpow(&privkey, &p);
        let pk = get_privkey_from_rem(p, q, g, y, &n, r).expect("pk not found");
        assert_eq!(privkey, pk);
    }
}
