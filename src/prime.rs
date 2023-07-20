use num_bigint::{BigUint, RandBigInt};
use rand::Rng;

fn turn_wheel(primes: &mut Vec<usize>, coprimes: &mut Vec<usize>, limit: usize) -> bool {
    let mut n = 1;
    for p in primes.iter() {
        n *= *p;
    }
    let p = coprimes[1];
    primes.push(p);
    let l = coprimes.len();
    let mut nn = n;
    let mut limit_reached = false;
    'add_coprimes: for _ in 1..p {
        for j in 0..l {
            let x = nn + coprimes[j];
            if x >= limit {
                limit_reached = true;
                break 'add_coprimes;
            }
            coprimes.push(x);
        }
        nn += n;
    }
    coprimes.retain(|x| x % p != 0);
    return limit_reached;
}

fn filter_wheel(coprimes: Vec<usize>, limit: usize) -> Vec<usize> {
    coprimes
        .into_iter()
        .skip(1)
        .fold((vec![], vec![]), |(mut small, mut res), x| {
            if !small.iter().any(|s| x % s == 0) {
                res.push(x);
            }
            if x * x <= limit {
                small.push(x);
            }
            (small, res)
        })
        .1
}

pub fn wheel_primes(limit: usize) -> Vec<usize> {
    let mut primes: Vec<usize> = vec![2, 3];
    let mut coprimes = vec![1, 5];
    while !turn_wheel(&mut primes, &mut coprimes, limit) {}
    primes.extend(filter_wheel(coprimes, limit));
    primes
}

pub fn factors_up_to(n: &BigUint, limit: usize) -> Vec<(usize, u32)> {
    let mut factors = vec![];
    let primes = wheel_primes(limit);
    let zero = BigUint::from(0u8);
    let mut n = n.clone();
    for p in primes {
        let mut exp = 0;
        while &n % p == zero {
            n /= p;
            exp += 1;
        }
        if exp > 0 {
            factors.push((p, exp));
        }
    }
    factors
}

fn fact_pow2(mut n: BigUint) -> (u32, BigUint) {
    let mut r = 0;
    while !n.bit(0) {
        r += 1;
        n >>= 1;
    }
    (r, n)
}

pub fn mr_prime(size: u64, k: usize, rng: &mut impl rand::Rng) -> BigUint {
    let mut n = rng.gen_biguint(size);
    while n.bits() != size {
        n = rng.gen_biguint(size);
    }
    n.set_bit(0, true);
    while !mrp_check(&n, k, rng) {
        n += 2u8;
    }
    n
}

const SMALL_PRIMES: [u8; 53] = [
    3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
    101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193,
    197, 199, 211, 223, 227, 229, 233, 239, 241, 251,
];

pub fn divided_by_small_prime(n: &BigUint) -> bool {
    let zero = BigUint::from(0u8);
    for p in SMALL_PRIMES {
        if n % p == zero {
            return false;
        }
    }
    true
}

pub fn mrp_check<R: Rng>(n: &BigUint, k: usize, rng: &mut R) -> bool {
    if !divided_by_small_prime(n) {
        return false;
    }
    let one = BigUint::from(1u8);
    let two = BigUint::from(2u8);
    let n_minus_1 = n.clone() - &one;
    let n_minus_2 = n.clone() - &two;
    let (r, d) = fact_pow2(n_minus_1.clone());

    'witness: for _ in 0..k {
        let a = rng.gen_biguint_range(&two, &n_minus_2);
        let mut x = a.modpow(&d, n);
        if x == one || x == n_minus_1 {
            continue;
        }
        for _ in 0..r - 1 {
            x = x.modpow(&2u8.into(), n);
            if x == one {
                return false;
            }
            if x == n_minus_1 {
                continue 'witness;
            }
        }
        return false;
    }
    true
}

pub fn pq(p_bits: u64, q_bits: u64, k: usize, rng: &mut impl rand::Rng) -> (BigUint, BigUint) {
    assert!(q_bits < p_bits - 3, "q must be << p");
    let q = mr_prime(q_bits, k, rng);
    let mut r = rng.gen_biguint(p_bits - q.bits()) << 1; // must be even
    let mut p: BigUint = &q * &r + 1u8;

    while p.bits() != p_bits || !mrp_check(&p, 1, rng) {
        r = rng.gen_biguint(p_bits - q.bits()) << 1;
        p = &q * &r + 1u8;
    }
    (p, q)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wheel_factor_works() {
        let mut primes = vec![2, 3];
        let mut coprimes = vec![1, 5];
        assert!(turn_wheel(&mut primes, &mut coprimes, 14));
        assert_eq!(primes, vec![2, 3, 5]);
        assert_eq!(coprimes, vec![1, 7, 11, 13]);

        let mut primes = vec![2, 3];
        let mut coprimes = vec![1, 5];
        assert!(!turn_wheel(&mut primes, &mut coprimes, 2 * 3 * 5 * 7 - 1));
        assert!(turn_wheel(&mut primes, &mut coprimes, 2 * 3 * 5 * 7 - 1));
        assert_eq!(primes, vec![2, 3, 5, 7]);
        assert!(turn_wheel(&mut primes, &mut coprimes, 2 * 3 * 5 * 7 - 1));
        assert_eq!(primes, vec![2, 3, 5, 7, 11]);
        assert!(turn_wheel(&mut primes, &mut coprimes, 2 * 3 * 5 * 7 - 1));
        assert_eq!(primes, vec![2, 3, 5, 7, 11, 13]);
    }

    #[test]
    fn wheel_primes_works() {
        let size = 1000;
        let primes = wheel_primes(size);
        assert_eq!(primes.len(), 168);

        assert!(primes.contains(&2));
        assert!(primes.contains(&47));
        assert!(primes.contains(&607));
        assert!(primes.contains(&997));
    }

    #[test]
    fn factors_up_to_works() {
        let mut n = BigUint::from(1u8);
        n *= 2usize.pow(3);
        n *= 17usize.pow(1);
        n *= 103usize.pow(5);
        n *= 241usize.pow(2);
        n *= 251usize.pow(1);
        let facts = factors_up_to(&n, 250);
        assert_eq!(facts, vec![(2, 3), (17, 1), (103, 5), (241, 2)]);
    }

    #[test]
    fn fact_pow2_works() {
        let r = 17;
        let d = 1298731usize;
        let n = BigUint::from(2usize.pow(r) * d);
        let (a, b) = fact_pow2(n);
        assert_eq!(a, r);
        assert_eq!(b, BigUint::from(d));
    }

    #[test]
    fn mr_prime_works() {
        let mut rng = rand::thread_rng();
        let p = mr_prime(20, 5, &mut rng)
            .to_u64_digits()
            .pop()
            .expect("0 is not a prime") as usize;
        let w = wheel_primes(p + 1usize);
        assert!(w.contains(&p));

        let p = mr_prime(512, 10, &mut rng);
        assert!(p.bits() >= 512);
    }

    #[test]
    fn pq_works() {
        let mut rng = rand::thread_rng();
        let k = 5;
        let (p, q) = &pq(200, 100, k, &mut rng);
        assert!(p.bits() == 200);
        assert!(q.bits() == 100);
        assert!(mrp_check(p, k, &mut rng));
        assert!(mrp_check(q, k, &mut rng));
    }
}
