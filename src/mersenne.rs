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

const N32: usize = 624;
type MT32 = (usize, [u32; N32]);
pub fn seed_mt(seed: u32) -> MT32 {
    const W: u32 = 32;
    const F: u32 = 1812433253;
    let mut arr = [seed; N32];
    for i in 1..N32 {
        arr[i] = arr[i - 1] ^ (arr[i - 1] >> (W - 2));
        arr[i] = arr[i].wrapping_mul(F);
        arr[i] = arr[i].wrapping_add(i as u32);
    }
    (N32, arr)
}

fn twist(arr: &mut [u32; N32]) {
    const M: usize = 397;
    const A: u32 = 0x9908B0DF;
    const R: u32 = 31;
    for i in 0..N32 {
        let x = (arr[i] & 1u32 << R) | (arr[(i + 1) % N32] & (1u32 << R) - 1);
        arr[i] = arr[(i + M) % N32] ^ x >> 1;
        if x % 2 != 0 {
            arr[i] ^= A;
        }
    }
}

pub fn nxt((n, arr): &mut MT32) -> u32 {
    const U: u32 = 11;
    const S: u32 = 7;
    const T: u32 = 15;
    const L: u32 = 18;
    const D: u32 = 0xFFFFFFFF;
    const B: u32 = 0x9D2C5680;
    const C: u32 = 0xEFC60000;
    if *n == N32 {
        twist(arr);
        *n = 0;
    }
    let mut y = arr[*n];
    *n += 1;
    y ^= y >> U & D;
    y ^= y << S & B;
    y ^= y << T & C;
    y ^= y >> L;

    y
}

const N64: usize = 312;
type MT64 = (usize, [u64; N64]);
pub fn seed_mt64(seed: u64) -> MT64 {
    let mut arr = [seed; N64];
    const W: u64 = 64;
    const F: u64 = 6364136223846793005;
    for i in 1..N64 {
        arr[i] = arr[i - 1] ^ (arr[i - 1] >> (W - 2));
        arr[i] = arr[i].wrapping_mul(F);
        arr[i] = arr[i].wrapping_add(i as u64);
    }
    (N64, arr)
}

fn twist64(arr: &mut [u64; N64]) {
    const M: usize = 156;
    const A: u64 = 0xB5026F5AA96619E9;
    const R: u64 = 31;
    for i in 0..N64 {
        let mut x = arr[i] & (((1u64 << R) - 1) ^ u64::MAX);
        x |= arr[(i + 1) % N64] & (1u64 << R) - 1;
        arr[i] = arr[(i + M) % N64] ^ x >> 1;
        if x % 2 != 0 {
            arr[i] ^= A;
        }
    }
}

pub fn nxt64((n, arr): &mut MT64) -> u64 {
    const U: u32 = 29;
    const S: u32 = 17;
    const T: u32 = 37;
    const L: u32 = 43;
    const D: u64 = 0x5555555555555555;
    const B: u64 = 0x71D67FFFEDA60000;
    const C: u64 = 0xFFF7EEE000000000;
    if *n == N64 {
        twist64(arr);
        *n = 0;
    }
    let mut y = arr[*n];
    *n += 1;
    y ^= y >> U & D;
    y ^= y << S & B;
    y ^= y << T & C;
    y ^= y >> L;

    y
}

pub fn rand_n<const N: usize>(seed: u32) -> [u32; N] {
    let mut state = seed_mt(seed);
    let mut res = [0u32; N];
    for i in 0..N {
        res[i] = nxt(&mut state);
    }
    res
}

pub fn guess_seed(seed_min: u32, seed_max: u32, vals: &[u32]) -> Vec<u32> {
    let mut v = vec![];
    for seed in seed_min..=seed_max {
        let vals_seed = rand_n::<N32>(seed);
        let mut contains = true;
        for v in vals {
            if !vals_seed.contains(v) {
                contains = false;
            }
        }
        if contains {
            v.push(seed);
        }
    }
    v
}

pub fn guess_state(rands: &[u32]) -> Vec<u32> {
    const U: u32 = 11;
    const S: u32 = 7;
    const T: u32 = 15;
    const L: u32 = 18;
    const D: u32 = 0xFFFFFFFF;
    const B: u32 = 0x9D2C5680;
    const C: u32 = 0xEFC60000;
    rands
        .iter()
        .map(|y4| {
            let y3 = un_xor_shr_and(*y4, L, D);
            let y2 = un_xor_shl_and(y3, T, C);
            let y1 = un_xor_shl_and(y2, S, B);
            un_xor_shr_and(y1, U, D)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use rand::Rng;
    use super::*;

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
    fn seeding_works() {
        let (n, arr) = seed_mt(0);
        assert_eq!(n, N32);
        assert_eq!(&arr[0..5], &[0, 1, 1812433255, 1900727105, 1208447044]);
    }

    #[test]
    fn nxt_works() {
        let mut state = seed_mt(17);
        let mut arr = vec![];
        for _ in 0..3 {
            arr.push(nxt(&mut state));
        }
        assert_eq!(&arr, &[1265576559, 780729585, 2278852751]);
    }

    #[test]
    fn seeding64_works() {
        let (n, arr) = seed_mt64(2);
        assert_eq!(n, N64);
        assert_eq!(&arr[0..3], &[2, 12728272447693586011, 8677659224773876903]);
    }

    #[test]
    fn nxt64_works() {
        let mut state = seed_mt64(99);
        let mut arr = vec![];
        for _ in 0..3 {
            arr.push(nxt64(&mut state));
        }
        assert_eq!(
            &arr,
            &[
                8015931446409328671,
                18098496970727876419,
                12361127197502484445
            ]
        );
    }

    #[test]
    fn guess_seed_works() {
        let mut rng = rand::thread_rng();
        let seed = rng.gen_range(10..=20);
        let mut state = seed_mt(seed);
        let mut vals = vec![];
        for _ in 1..30 {
            nxt(&mut state);
        }
        vals.push(nxt(&mut state));
        for _ in 1..13 {
            nxt(&mut state);
        }
        vals.push(nxt(&mut state));
        let matching_seeds = guess_seed(10, 20, &vals);
        assert!(matching_seeds.len() < 2);
        assert!(matching_seeds.contains(&seed));
    }

    #[test]
    fn guess_state_works() {
        let mut rng = rand::thread_rng();
        let seed = rng.gen();
        let mut state = seed_mt(seed);
        let mut rands = vec![];
        let n = N32;
        for _ in 0..n {
            rands.push(nxt(&mut state));
        }
        let vals = guess_state(&rands);
        assert_eq!(&vals, &state.1);
    }
}
