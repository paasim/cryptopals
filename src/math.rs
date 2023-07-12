use num_bigint::{BigInt, BigUint};
use num_traits::Signed;
use std::mem;

const MOD: u8 = 27;

pub const fn multip2(x: u8) -> u8 {
    if x >= 128 {
        (x << 1) ^ MOD
    } else {
        x << 1
    }
}

pub const fn multip(mut x: u8, mut y: u8) -> u8 {
    let mut res = 0;
    while y > 0 {
        if y % 2 == 1 {
            res ^= x
        }
        x = multip2(x);
        y /= 2;
    }
    res
}
const fn precalc_multip(y: u8) -> [u8; 256] {
    let mut res = [0; 256];
    let mut i = 0;
    while i < 255 {
        i += 1;
        res[i as usize] = multip(i, y);
    }
    res
}
pub const MULTIP2: [u8; 256] = precalc_multip(2);
pub const MULTIP9: [u8; 256] = precalc_multip(9);
pub const MULTIP11: [u8; 256] = precalc_multip(11);
pub const MULTIP13: [u8; 256] = precalc_multip(13);
pub const MULTIP14: [u8; 256] = precalc_multip(14);

pub const fn pow(mut x: u8, mut n: u8) -> u8 {
    let mut res = 1;
    while n > 0 {
        if n % 2 == 1 {
            res = multip(res, x);
        }
        x = multip(x, x);
        n /= 2;
    }
    res
}

pub const fn inv(x: u8) -> u8 {
    pow(x, 254)
}

const fn precalc_inv() -> [u8; 256] {
    let mut res = [inv(0); 256];
    let mut i = 0;
    while i < 255 {
        i += 1;
        res[i as usize] = inv(i);
    }
    res
}
pub const INV: [u8; 256] = precalc_inv();

pub fn un_xor_shl_and(mut x: u32, n: u32, and: u32) -> u32 {
    for i in 0..=32 - n {
        x ^= (x << n) & and & (1 << (i + n - 1));
    }
    x
}

pub fn un_xor_shr_and(mut x: u32, n: u32, and: u32) -> u32 {
    for i in 0..=32 - n {
        x ^= (x >> n) & and & (1 << 32 - n - i);
    }
    x
}

pub fn inv_egcd(x: BigUint, m: BigUint) -> Option<BigUint> {
    let m = BigInt::from(m);
    let zero = BigInt::from(0);
    let (mut t, mut tn) = (zero.clone(), BigInt::from(1));
    let (mut r, mut rn) = (m.clone(), BigInt::from(x.clone()));
    while rn != zero {
        let quo = r.clone() / rn.clone();
        mem::swap(&mut t, &mut tn);
        mem::swap(&mut r, &mut rn);
        tn -= &quo * &t;
        rn -= &quo * &r;
    }
    if r > 1u8.into() {
        return None;
    };
    if !t.is_positive() {
        t += &m;
    }
    Some(t.to_biguint().expect("negative result"))
}

#[cfg(test)]
mod tests {
    use crate::prime;

    use super::*;
    use num_bigint::RandBigInt;
    use rand::Rng;

    #[test]
    fn multip_works() {
        assert_eq!(multip(3, 2), 6);
        assert_eq!(multip(0x53, 0xca), 0x01);
    }

    #[test]
    fn pow_works() {
        let x = 37;
        assert_eq!(pow(x, 0), 1);
        assert_eq!(pow(x, 1), x);
        assert_eq!(pow(x, 3), multip(multip(x, x), x));
        assert_eq!(pow(x, 255), 1);
        assert_eq!(pow(42, 255), 1);
    }

    #[test]
    fn inv_works() {
        let x = 2u8.pow(6) + 2u8.pow(4) + 2 + 1;
        let x_inv = inv(x);
        assert_eq!(x_inv, 2u8.pow(7) + 2u8.pow(6) + 2u8.pow(3) + 2u8);
        assert_eq!(multip(x, x_inv), 1);
    }

    #[test]
    fn un_xor_shl_works() {
        let mut rng = rand::thread_rng();
        let s: u32 = 7;
        let t: u32 = 15;
        let b: u32 = 0x9D2C5680;
        let c: u32 = 0xEFC60000;
        for _ in 0..10000 {
            let x: u32 = rng.gen();
            let y = x ^ ((x << s) & b);
            assert_eq!(un_xor_shl_and(y, s, b), x);
            let y = x ^ ((x << t) & c);
            assert_eq!(un_xor_shl_and(y, t, c), x);
        }
    }

    #[test]
    fn un_xor_shr_works() {
        let mut rng = rand::thread_rng();
        let u: u32 = 11;
        let d: u32 = 0xFFFFFFFF;
        let l: u32 = 18;
        for _ in 0..1000 {
            let x: u32 = rng.gen();
            let y = x ^ ((x >> u) & d);
            assert_eq!(un_xor_shr_and(y, u, d), x);
            let y = x ^ ((x >> l) & d);
            assert_eq!(un_xor_shr_and(y, l, d), x);
        }
    }

    #[test]
    fn inv_egcd_works() {
        let x = 5u8.into();
        let m = 14u8.into();
        let i = inv_egcd(x, m).expect("{x} should be invertible mod {m}");
        assert_eq!(i, 3u8.into());

        let x = 2u8.into();
        let m = 5u8.into();
        let i = inv_egcd(x, m).expect("{x} should be invertible mod {m}");
        assert_eq!(i, 3u8.into());

        let x = 2u8.into();
        let m = 7u8.into();
        let i = inv_egcd(x, m).expect("{x} should be invertible mod {m}");
        assert_eq!(i, 4u8.into());

        let x = 17u8.into();
        let m = 3120u16.into();
        assert_eq!(inv_egcd(x, m), Some(2753u16.into()));

        let mut rng = rand::thread_rng();
        let p = prime::mr_prime(500, 5);
        let a = rng.gen_biguint_range(&2u8.into(), &p);
        let b = inv_egcd(a.clone(), p.clone()).expect("{x} should be invertible mod {m}");
        let one = 1u8.into();
        assert_ne!(a, one);
        assert_ne!(b, one);
        assert_eq!(a * b % p, one);
    }

}
