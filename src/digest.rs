use crate::block::{md_be_pad, md_le_pad};
use crate::xor::xor_arr;
use std::num::Wrapping;

type W32 = Wrapping<u32>;

fn lr(w: W32, n: usize) -> W32 {
    w << n | w >> 32 - n % 32
}

fn rr(w: W32, n: usize) -> W32 {
    w >> n | w << 32 - n % 32
}

fn md4r1(arr: &[u32; 4], xi: u32, s: u32) -> u32 {
    let f = |x: u32, y: u32, z: u32| (x & y) | (!x & z);
    arr[0]
        .wrapping_add(f(arr[1], arr[2], arr[3]))
        .wrapping_add(xi)
        .rotate_left(s)
}

fn md4r2(arr: &[u32; 4], xi: u32, s: u32) -> u32 {
    let g = |x: u32, y: u32, z: u32| (x & y) | (x & z) | (y & z);
    arr[0]
        .wrapping_add(g(arr[1], arr[2], arr[3]))
        .wrapping_add(xi)
        .wrapping_add(0x5A827999)
        .rotate_left(s)
}

fn md4r3(a: &[u32; 4], xi: u32, s: u32) -> u32 {
    let h = |x, y, z| x ^ y ^ z;
    a[0].wrapping_add(h(a[1], a[2], a[3]))
        .wrapping_add(xi)
        .wrapping_add(0x6ED9EBA1)
        .rotate_left(s)
}

pub fn md4(msg: &[u8]) -> [u8; 16] {
    let v = md_le_pad(msg, 512);

    let mut a = 0x67452301;
    let mut b = 0xefcdab89;
    let mut c = 0x98badcfe;
    let mut d = 0x10325476;

    for chunk in v.chunks_exact(64) {
        let mut x = [0u32; 16];
        for (i, chk) in chunk.chunks_exact(4).enumerate() {
            x[i] = u32::from_le_bytes(chk.try_into().expect("invalid bs"));
        }

        let s = [3, 7, 11, 19];
        let mut abcd = [a, b, c, d];
        for i in 0..16 {
            abcd[0] = md4r1(&abcd, x[i], s[i % 4]);
            abcd.rotate_right(1);
        }
        let s = [3, 5, 9, 13];
        for i in 0..16 {
            abcd[0] = md4r2(&abcd, x[i / 4 + i % 4 * 4], s[i % 4]);
            abcd.rotate_right(1);
        }

        let s = [3, 9, 11, 15];
        let o = [0, 8, 4, 12, 2, 10, 6, 14];
        for i in 0..16 {
            abcd[0] = md4r3(&abcd, x[i / 8 + o[i % 8]], s[i % 4]);
            abcd.rotate_right(1);
        }

        a = a.wrapping_add(abcd[0]);
        b = b.wrapping_add(abcd[1]);
        c = c.wrapping_add(abcd[2]);
        d = d.wrapping_add(abcd[3]);
    }
    let bytes = [a, b, c, d].into_iter().map(|h| h.to_le_bytes());

    let mut res = [0u8; 16];
    for (i, v) in bytes.flatten().enumerate() {
        res[i] = v;
    }
    res
}

fn sha1_round(w: &[W32; 80], h: &[W32; 5], k: &[W32; 4]) -> [W32; 5] {
    let mut h0 = h.clone();
    for i in 0..80 {
        let f = match i {
            0..=19 => (h0[1] & h0[2]) | (!h0[1] & h0[3]),
            40..=59 => (h0[1] & h0[2]) | (h0[1] & h0[3]) | (h0[2] & h0[3]),
            _ => h0[1] ^ h0[2] ^ h0[3],
        };
        h0[4] += f + lr(h0[0], 5) + k[i / 20] + w[i];
        h0.rotate_right(1);
        h0[2] = lr(h0[2], 30);
    }
    for i in 0..5 {
        h0[i] += h[i];
    }
    h0
}

fn sha1_loop(v: &[u8], mut h: [W32; 5]) -> [W32; 5] {
    let k = [0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6].map(Wrapping);
    for chk in v.chunks_exact(64) {
        let mut w = [Wrapping(0u32); 80];
        for (i, chk32) in chk.chunks_exact(4).enumerate() {
            w[i] = Wrapping(u32::from_be_bytes(chk32.try_into().expect("invalid bs")));
        }
        for i in 16..80 {
            w[i] = lr(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
        }
        h = sha1_round(&w, &h, &k);
    }
    h
}

pub fn sha1(msg: &[u8]) -> [u8; 20] {
    let v = md_be_pad(msg, 512);
    let h0 = 0x67452301_u32;
    let h1 = 0xEFCDAB89_u32;
    let h2 = 0x98BADCFE_u32;
    let h3 = 0x10325476_u32;
    let h4 = 0xC3D2E1F0_u32;
    let h = sha1_loop(&v, [h0, h1, h2, h3, h4].map(Wrapping)).map(|x| x.0);

    let mut res = [0; 20];
    for (i, v) in h.into_iter().map(|h| h.to_be_bytes()).flatten().enumerate() {
        res[i] = v;
    }
    res
}

fn sha256_round(w: &[W32; 64], h: &[W32; 8], k: &[W32; 64]) -> [W32; 8] {
    let mut h0 = h.clone();
    for i in 0..64 {
        let mut temp1 = h0[7] + k[i] + w[i];
        temp1 += (h0[4] & h0[5]) ^ (!h0[4] & h0[6]);
        temp1 += rr(h0[4], 6) ^ rr(h0[4], 11) ^ rr(h0[4], 25);
        h0[7] = rr(h0[0], 2) ^ rr(h0[0], 13) ^ rr(h0[0], 22);
        h0[7] += (h0[0] & h0[1]) ^ (h0[0] & h0[2]) ^ (h0[1] & h0[2]);
        h0.rotate_right(1);
        h0[4] += temp1;
        h0[0] += temp1;
    }
    for i in 0..8 {
        h0[i] += h[i];
    }
    h0
}

fn sha256_loop(v: &[u8], mut h: [W32; 8]) -> [W32; 8] {
    let k: [W32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ]
    .map(Wrapping);
    for chk in v.chunks_exact(64) {
        let mut w = [Wrapping(0u32); 64];
        for (i, chk32) in chk.chunks_exact(4).enumerate() {
            w[i] = Wrapping(u32::from_be_bytes(chk32.try_into().expect("invalid bs")));
        }
        for i in 16..64 {
            w[i] = w[i - 7] + w[i - 16];
            w[i] += rr(w[i - 15], 7) ^ rr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            w[i] += rr(w[i - 2], 17) ^ rr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        }
        h = sha256_round(&w, &h, &k);
    }
    h
}

pub fn sha256(msg: &[u8]) -> [u8; 32] {
    let v = md_be_pad(msg, 512);
    let h0 = 0x6a09e667;
    let h1 = 0xbb67ae85;
    let h2 = 0x3c6ef372;
    let h3 = 0xa54ff53a;
    let h4 = 0x510e527f;
    let h5 = 0x9b05688c;
    let h6 = 0x1f83d9ab;
    let h7 = 0x5be0cd19;
    let h = [h0, h1, h2, h3, h4, h5, h6, h7].map(Wrapping);
    let h = sha256_loop(&v, h).map(|h| h.0);
    let mut res = [0; 32];

    for (i, v) in h.into_iter().map(|h| h.to_be_bytes()).flatten().enumerate() {
        res[i] = v;
    }
    res
}

pub fn hmac_key<const N: usize>(key: &[u8], h: fn(&[u8]) -> [u8; N]) -> [u8; N] {
    if key.len() > N {
        return h(key);
    }
    let mut res = [0u8; N];
    for i in 0..key.len() {
        res[i] = key[i];
    }
    res
}

pub fn hmac<const N: usize>(key: &[u8], msg: &[u8], h: fn(&[u8]) -> [u8; N]) -> [u8; N] {
    let mut key = hmac_key(key, h);
    xor_arr(&mut key, &[0x36; N]);
    let h0 = h(&[&key, msg].concat());
    xor_arr(&mut key, &[0x36 ^ 0x5c; N]);
    h(&[key, h0].concat())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode::{from_ascii, to_hex};

    #[test]
    fn md4_works() {
        let v = md4(&[]);
        assert_eq!(to_hex(&v), "31d6cfe0d16ae931b73c59d7e0c089c0");

        let str = from_ascii("The quick brown fox jumps over the lazy dog");
        let v = md4(&str);
        assert_eq!(to_hex(&v), "1bee69a46ba811185c194762abaeae90");
    }

    #[test]
    fn sha1_works() {
        let v = sha1(&[]);
        let exp = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
        assert_eq!(to_hex(&v), exp);

        let str = from_ascii("The quick brown fox jumps over the lazy dog");
        let v = sha1(&str);
        let exp = "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12";
        assert_eq!(to_hex(&v), exp);
    }

    #[test]
    fn sha256_works() {
        let v = sha256(&[]);
        let exp = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(to_hex(&v), exp);

        let str = from_ascii("abc");
        let v = sha256(&str);
        let exp = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert_eq!(to_hex(&v), exp);
    }
}
