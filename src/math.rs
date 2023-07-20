use num_bigint::BigUint;
use std::mem;

pub fn bezout(a: &BigUint, b: &BigUint, m: &BigUint) -> ((BigUint, BigUint), BigUint) {
    let (mut r, mut rn) = (a.clone(), b.clone());
    let (mut s, mut sn) = (1u8.into(), 0u8.into());
    let (mut t, mut tn) = (0u8.into(), 1u8.into());
    let zero = &BigUint::from(0u8);
    while &rn > zero {
        let quo = &r / &rn;
        mem::swap(&mut r, &mut rn);
        mem::swap(&mut s, &mut sn);
        mem::swap(&mut t, &mut tn);
        rn = (rn + &quo * (m - &r)) % m;
        sn = (sn + &quo * (m - &s)) % m;
        tn = (tn + &quo * (m - &t)) % m;
    }
    // (tn, sn) // quotients by the gcd
    ((s, t), r) // bezout coefs, gcd
}

pub fn inv_egcd(x: &BigUint, m: &BigUint) -> Option<BigUint> {
    let ((_, t), r) = bezout(m, &(x % m), m);
    if r > 1u8.into() {
        return None;
    };
    Some(t)
}

pub fn div(x: &BigUint, y: &BigUint, m: &BigUint) -> Option<BigUint> {
    Some((x * inv_egcd(y, m)?) % m)
}

pub fn nth_root(x_n: BigUint, n: u32) -> BigUint {
    let mut x = BigUint::from(2u8) << (x_n.bits() / n as u64 + n as u64);
    let mut prev_x = &x + 1u8;

    while x < prev_x {
        // x = x*(n-1)/n + x_n / (n * x^n-1), ie. newton
        let t = &x * (n - 1) + &x_n / x.pow(n - 1);
        prev_x = x;
        x = t / n;
    }
    prev_x
}

pub fn crt(v: &[(BigUint, BigUint)]) -> (BigUint, BigUint) {
    let prod: BigUint = v.iter().map(|(_, n)| n).product();
    let s: BigUint = v
        .iter()
        .map(|(a, n)| {
            assert_eq!(&prod % n, 0u8.into());
            let ms = &prod / n;
            assert_ne!(&ms % n, 0u8.into());
            a * &ms * inv_egcd(&ms, n).expect("moduli are not coprime")
        })
        .sum();
    (s % &prod, prod)
}

pub fn disc_log_incr(p: &BigUint, ul: &BigUint, g: &BigUint, gx: &BigUint) -> Option<BigUint> {
    let mut x = BigUint::from(0u8);
    let mut gx_ = BigUint::from(1u8);
    while &x < ul {
        if &gx_ == gx {
            return Some(x);
        }
        gx_ = (gx_ * g) % p;
        x += 1u8;
    }
    None
}

fn pr_step(
    (mut x, mut eg, mut ea): (BigUint, BigUint, BigUint),
    p: &BigUint,
    q: &BigUint,
    g: &BigUint,
) -> (BigUint, BigUint, BigUint) {
    if x.bit(0) {
        x *= g;
        eg += 1u8;
    } else {
        x *= x.clone();
        eg *= 2u8;
        ea *= 2u8;
    }
    (x % p, eg % q, ea % q)
}

pub fn pollard_rho(p: &BigUint, q: &BigUint, g: &BigUint, gx: &BigUint) -> Option<BigUint> {
    let init = (gx.clone(), BigUint::from(0u8), BigUint::from(1u8));
    let f = |tup| pr_step(tup, p, q, g);
    let mut t = f(init);
    let mut h = f(t.clone());
    while t.0 != h.0 {
        t = f(t);
        h = f(f(h));
    }
    div(&(t.1 + q - h.1), &(h.2 + q - t.2), q)
}

pub fn pollard_lambda(
    p: &BigUint,
    g: &BigUint,
    ge: &BigUint,
    ll: &BigUint,
    ul: &BigUint,
    k: u8,
    c: u8,
) -> Option<BigUint> {
    let mut x = g.modpow(ul, p);
    let mut d = BigUint::from(0u8);
    assert!(k <= 120, "k must be smaller than ~120 to fit into u128");
    let get_i = |x: &BigUint| (x % k).to_u64_digits().pop().unwrap_or(0) as usize;
    let f = |i: u8| 1u128 << i;
    // mean of f * c
    let n = ((1u128 << k) - 1) * c as u128 / k as u128;

    let fs: Vec<_> = (0..k).map(f).collect();
    let gs: Vec<_> = fs.iter().map(|e| g.modpow(&(*e).into(), p)).collect();
    for _ in 0..n {
        let i = get_i(&x);
        x = (x * &gs[i]) % p;
        d += fs[i];
    }
    // x = xn = x0 g^d = g^b g^d = g ^ (b+d)
    let mut y = ge.clone();
    let mut c = BigUint::from(0u8);
    let clim = ul - ll + &d;
    while c < clim {
        let i = get_i(&y);
        y = (y * &gs[i]) % p;
        c += fs[i];
        if y == x {
            return Some(ul + d - c);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prime::{mr_prime, pq};
    use num_bigint::RandBigInt;

    #[test]
    fn bezout_works() {
        let mut rng = rand::thread_rng();
        let p = mr_prime(500, 5, &mut rng);
        let a = rng.gen_biguint_range(&2u8.into(), &p);
        let b = rng.gen_biguint_range(&2u8.into(), &p);
        let ((x, y), gcd) = bezout(&a, &b, &p);
        let one = 1u8.into();
        if gcd == one {
            assert_eq!((x * &a + y * &b) % &p, one);
        }
    }

    #[test]
    fn inv_egcd_works() {
        let x = 5u8.into();
        let m = 14u8.into();
        let i = inv_egcd(&x, &m).expect("{x} should be invertible mod {m}");
        assert_eq!(i, 3u8.into());

        let x = 2u8.into();
        let m = 5u8.into();
        let i = inv_egcd(&x, &m).expect("{x} should be invertible mod {m}");
        assert_eq!(i, 3u8.into());

        let x = 2u8.into();
        let m = 7u8.into();
        let i = inv_egcd(&x, &m).expect("{x} should be invertible mod {m}");
        assert_eq!(i, 4u8.into());

        let x = 17u8.into();
        let m = 3120u16.into();
        assert_eq!(inv_egcd(&x, &m), Some(2753u16.into()));

        let mut rng = rand::thread_rng();
        let p = mr_prime(500, 5, &mut rng);
        let a = rng.gen_biguint_range(&2u8.into(), &p);
        let b = inv_egcd(&a, &p).expect("{x} should be invertible mod {m}");
        let one = 1u8.into();
        assert_ne!(a, one);
        assert_ne!(b, one);
        assert_eq!(a * b % p, one);
    }

    #[test]
    fn nth_root_works() {
        let x = BigUint::from(123usize);
        let x_n = x.pow(5);
        let y = nth_root(x_n, 5);
        assert_eq!(x, y);

        let mut rng = rand::thread_rng();
        let x = rng.gen_biguint(100);
        let x_n = x.pow(17);
        let y = nth_root(x_n, 17);
        assert_eq!(x, y);
    }

    #[test]
    fn pollard_rho_works() {
        let mut rng = rand::thread_rng();
        let bits = 20;
        // ensures that q is a prime factor of p-1
        //
        let (p, q) = &pq(bits * 2, bits, 5, &mut rng);
        let r = (p - 1u8) / q;
        let g = &rng
            .gen_biguint_range(&2u8.into(), &(p - 2u8))
            .modpow(&r, &p);
        let x = &rng.gen_biguint_range(&0u8.into(), &(q - 1u8));
        let gx = &g.modpow(x, p);
        let x2 = &pollard_rho(p, q, g, gx).expect("not invertible");
        assert_eq!(x2, x);
    }

    #[test]
    fn pollard_lambda_works() {
        let mut rng = rand::thread_rng();
        let (p, g) = &pq(256, 128, 5, &mut rng);
        let up = 20;
        let ul = &2usize.pow(up).into();
        let ll = &2usize.pow(0).into();
        let x = &rng.gen_biguint_range(ll, ul);
        let y = &g.modpow(x, p);
        let k = up / 2;
        let c = 4;
        let x2 = &pollard_lambda(p, g, y, ll, ul, k as u8, c).expect("did not find x");
        assert_eq!(x, x2);
        assert_eq!(&g.modpow(&x2, p), y);
    }
}
