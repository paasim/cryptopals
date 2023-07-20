use crate::xor::xor_arr;
use std::collections::HashSet;

pub fn ecb<const N: usize>(
    arr: &[u8],
    key: &[u8; N],
    f: fn(&[u8; N], &[u8; N]) -> [u8; N],
) -> Option<Vec<u8>> {
    let chunks = arr.chunks_exact(N);
    if chunks.remainder().len() != 0 {
        return None;
    }
    let encr = chunks
        .map(|chk| f(chk.try_into().expect("invalid bs"), &key))
        .collect::<Vec<_>>()
        .concat();
    Some(encr)
}

pub fn cbc_encr<const N: usize>(
    arr: &[u8],
    key: &[u8; N],
    iv: &[u8; N],
    f: fn(&[u8; N], &[u8; N]) -> [u8; N],
) -> Option<Vec<u8>> {
    let chunks = arr.chunks_exact(N);
    if chunks.remainder().len() != 0 {
        return None;
    }
    let (encr, _) = chunks.fold((vec![], *iv), |(mut v, decr_prev), chk| {
        let mut chk = chk.try_into().expect("invalid bs");
        xor_arr(&mut chk, &decr_prev);
        let encr = f(&chk, &key);
        v.extend(encr);
        (v, encr)
    });
    Some(encr)
}

pub fn cbc_decr<const N: usize>(
    arr: &[u8],
    key: &[u8; N],
    iv: &[u8; N],
    f: fn(&[u8; N], &[u8; N]) -> [u8; N],
) -> Option<Vec<u8>> {
    let chunks = arr.chunks_exact(N);
    if chunks.remainder().len() != 0 {
        return None;
    }
    let (encr, _) = chunks.fold((vec![], *iv), |(mut v, encr_prev), chk| {
        let chk: [u8; N] = chk.try_into().expect("invalid bs");
        let mut decr = f(&chk, &key);
        xor_arr(&mut decr, &encr_prev);
        v.extend(decr);
        (v, chk)
    });
    Some(encr)
}

pub fn rand_key<const N: usize, T: rand::Rng>(rng: &mut T) -> [u8; N] {
    rng.gen()
}

pub fn md_be_pad(arr: &[u8], len_bits: usize) -> Vec<u8> {
    let ml = arr.len() * 8; // len in bits
    let mut v = Vec::from(arr);
    v.push(0x80);
    let len = len_bits / 8;
    // - 8 to save space for ml.to_be_bytes;
    let diff = (2 * len - 8 - v.len() % len) % len;
    v.extend(vec![0; diff]);
    v.extend(ml.to_be_bytes());
    v
}

pub fn md_le_pad(arr: &[u8], len_bits: usize) -> Vec<u8> {
    let ml = arr.len() * 8; // len in bits
    let mut v = Vec::from(arr);
    v.push(0x80);
    let len = len_bits / 8;
    // - 8 to save space for ml.to_be_bytes;
    let diff = (2 * len - 8 - v.len()) % len;
    v.extend(vec![0; diff]);
    v.extend(ml.to_le_bytes());
    v
}

pub fn pad_pkcs7(v: &mut Vec<u8>, n: u8) {
    let m = (v.len() % n as usize) as u8;
    let i = n - m;
    for _ in 0..i {
        v.push(i);
    }
}

pub fn unpad_pkcs7(mut v: Vec<u8>) -> Option<Vec<u8>> {
    let n = v.pop()?;
    let mut i = n.checked_sub(1)?;
    while i > 0 {
        if v.pop()? != n {
            return None;
        }
        i -= 1;
    }
    Some(v)
}

pub fn check_cbc_padding<const N: usize>(
    arr: &[u8],
    key: &[u8; N],
    iv: &[u8; N],
    f: fn(&[u8; N], &[u8; N]) -> [u8; N],
) -> bool {
    cbc_decr(arr, key, iv, f).and_then(unpad_pkcs7).is_some()
}

pub fn pad_with(prefix: &[u8], arr: &[u8], postfix: &[u8], bs: u8) -> Vec<u8> {
    let mut v = Vec::from(prefix);
    v.extend(arr);
    v.extend(postfix);
    pad_pkcs7(&mut v, bs);
    v
}

fn detect_blocksize<F: Fn(&[u8]) -> Vec<u8>>(encr: &F) -> (usize, usize) {
    let mut n = 0;
    let l = encr(&vec![0; n]).len();
    let mut e_len = l;
    while e_len == l {
        n += 1;
        e_len = encr(&vec![0; n]).len();
    }
    (e_len - l, l - n)
}

fn detect_prefix_block<F: Fn(&[u8]) -> Vec<u8>>(encr: &F, bs: usize) -> usize {
    let l0 = encr(&[]);
    let l1 = encr(&[0]);
    let mut block = 0;
    while l0[block * bs..(block + 1) * bs] == l1[block * bs..(block + 1) * bs] {
        block += 1;
    }
    block
}

fn detect_prefix<F: Fn(&[u8]) -> Vec<u8>>(encr: &F, bs: usize) -> usize {
    let block = detect_prefix_block(encr, bs);
    let mut prev = encr(&vec![0; 0]);
    let mut n = 1;
    let mut cur = encr(&vec![0; n]);
    while cur[block * bs..(block + 1) * bs] != prev[block * bs..(block + 1) * bs] {
        prev = cur;
        n += 1;
        cur = encr(&vec![0; n]);
    }
    (block + 1) * bs - n + 1
}

pub fn detect_ecb(arr: &[u8], n: usize) -> bool {
    let mut unique_blocks = HashSet::<Vec<u8>>::new();
    let mut chks = arr.chunks(n);
    while let Some(chk) = chks.next() {
        // hashset cannot contain slices
        let v = Vec::from(chk);
        if unique_blocks.contains(chk) {
            return true;
        }
        unique_blocks.insert(v);
    }
    false
}

pub fn valid_pad_bytes<const N: usize>(
    blk: &[u8; N],
    valid_iv: &[u8; N],
    f: &impl Fn(&[u8; N], &[u8; N]) -> bool,
) -> usize {
    let mut pos = 0;
    let mut iv = *valid_iv;
    iv[pos] ^= 1;
    while f(blk, &iv) && pos < N {
        pos += 1;
        iv[pos] ^= 1;
    }
    N - pos
}

pub fn find_valid_iv<const N: usize>(
    blk: &[u8; N],
    iv: &mut [u8; N],
    pos: usize,
    f: &impl Fn(&[u8; N], &[u8; N]) -> bool,
) -> bool {
    while !f(blk, &iv) {
        if iv[pos] == 255 {
            return false;
        }
        iv[pos] += 1;
    }
    true
}

pub fn decrypt_padded_ecb(f: &impl Fn(&[u8]) -> Vec<u8>) -> Option<Vec<u8>> {
    let (bs, l) = detect_blocksize(&f);
    if !detect_ecb(&vec![0u8; 3 * bs], bs) {
        return None;
    }
    let prefix_len = detect_prefix(&f, bs);
    let prefix_pad = bs - prefix_len % bs;
    let prefix_end = (prefix_len / bs + 1) * bs;
    let f_skip = move |v: &[u8]| f(v).into_iter().skip(prefix_end).collect::<Vec<_>>();
    let cache: Vec<_> = (0..bs).map(|l| f_skip(&vec![0; prefix_pad + l])).collect();
    let mut res = vec![];
    let mut arr = vec![0u8; prefix_pad + bs];
    for pos in 0..l - prefix_len {
        let cache_pos = pos / bs * bs;
        while f_skip(&arr)[..bs] != cache[bs - 1 - pos % bs][cache_pos..cache_pos + bs] {
            if arr[prefix_pad + bs - 1] == u8::MAX {
                return None;
            }
            arr[prefix_pad + bs - 1] += 1;
        }
        res.push(arr[prefix_pad + bs - 1]);
        arr.rotate_left(1);
        arr[prefix_pad - 1] = 0;
        arr[prefix_pad + bs - 1] = 0;
    }
    Some(res)
}

pub fn decrypt_cbc_block<const N: usize, F>(blk: &[u8; N], f: &F) -> Option<[u8; N]>
where
    F: Fn(&[u8; N], &[u8; N]) -> bool,
{
    let mut decrypted = [0u8; N];
    for pos in (0..N).rev() {
        let mut x = [0u8; N];
        for i in pos + 1..N {
            x[i] = decrypted[i] ^ (N - pos) as u8;
        }
        if !find_valid_iv(blk, &mut x, pos, f) {
            return None;
        };
        decrypted[pos] = x[pos] ^ valid_pad_bytes(blk, &x, &f) as u8;
        if decrypted[pos] == x[pos] {
            return None; // there was 0 valid pad_bytes
        }
    }
    Some(decrypted)
}

pub fn decrypt_cbc_oracle<const N: usize, F>(arr: &[u8], iv: &[u8; N], f: &F) -> Option<Vec<u8>>
where
    F: Fn(&[u8; N], &[u8; N]) -> bool,
{
    let mut chunks = arr.chunks_exact(N);
    if chunks.remainder().len() != 0 {
        return None;
    }
    chunks
        .try_fold((vec![], *iv), |(mut v, encr_prev), chk| {
            let chk: [u8; N] = chk.try_into().ok()?;
            let mut decr = decrypt_cbc_block(&chk, f)?;
            xor_arr(&mut decr, &encr_prev);
            v.extend(decr);
            Some((v, chk))
        })
        .map(|(encr, _)| encr)
}

pub fn recover_iv_from_decrypt<const N: usize>(f: impl Fn(&[u8]) -> Vec<u8>) -> [u8; N] {
    let encr0 = vec![0; N * 2];
    let d = f(&encr0);
    let mut res = [0; N];
    for i in 0..N {
        res[i] = d[i] ^ d[i + N];
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aes::{aes, inv_aes};
    use crate::encode::{from_ascii, from_hex};
    use rand::Rng;
    use std::fs;

    #[test]
    fn ecb_is_its_own_inverse() {
        let mut rng = rand::thread_rng();
        let n = rng.gen_range(1..=10);
        let mut bytes = vec![];
        for _ in 0..n {
            bytes.extend::<[_; 16]>(rand_key(&mut rng))
        }

        let key = rand_key(&mut rng);
        let encr = ecb(&bytes, &key, aes).expect("incorrect bs");
        assert_ne!(bytes, encr);
        let decr = ecb(&encr, &key, inv_aes).expect("incorrect bs");
        assert_eq!(bytes, decr);
    }

    #[test]
    fn cbc_encr_decr_are_inverses() {
        let mut rng = rand::thread_rng();
        let n = rng.gen_range(1..=10);
        let mut bytes = vec![];
        for _ in 0..n {
            bytes.extend::<[_; 16]>(rand_key(&mut rng))
        }

        let key = rand_key(&mut rng);
        let iv = rand_key(&mut rng);

        let encr = cbc_encr(&bytes, &key, &iv, aes).expect("incorrect bs");
        assert_ne!(bytes, encr);
        let decr = cbc_decr(&encr, &key, &iv, inv_aes).expect("incorrect bs");
        assert_eq!(bytes, decr);
    }

    #[test]
    fn padding_works() {
        let mut input = from_ascii("123456");
        pad_pkcs7(&mut input, 10);
        assert_eq!(input.len(), 10);
        assert_eq!(input.pop(), Some(0x04));
        assert_eq!(input.pop(), Some(0x04));
        assert_eq!(input.pop(), Some(0x04));
        assert_eq!(input.pop(), Some(0x04));
        let mut input = from_ascii("ab");
        pad_pkcs7(&mut input, 2);
        assert_eq!(input.len(), 4);
        assert_eq!(input.pop(), Some(0x02));
        assert_eq!(input.pop(), Some(0x02));
    }

    #[test]
    fn unpadding_works() {
        let input = vec![b'a', 1];
        assert_eq!(unpad_pkcs7(input), Some(vec![b'a']));
        let input = vec![b'a', b'k', 3, 3, 3];
        assert_eq!(unpad_pkcs7(input), Some(vec![b'a', b'k']));
        let input = vec![b'a', b'k', 2, 2, 4];
        assert_eq!(unpad_pkcs7(input), None);
        let input = vec![b'a', b'k', 0];
        assert_eq!(unpad_pkcs7(input), None);
        let input = vec![3, 3, 3];
        assert_eq!(unpad_pkcs7(input), Some(vec![]));
    }

    #[test]
    fn detect_blocksize_works() {
        let mut rng = rand::thread_rng();
        let n_pre = rng.gen_range(5..=30);
        let n_post = rng.gen_range(5..=30);
        let prefix: Vec<_> = (0..n_pre).map(|_| rng.gen()).collect();
        let postfix: Vec<_> = (0..n_post).map(|_| rng.gen()).collect();
        let key = rand_key(&mut rng);
        let encr = |v: &[u8]| {
            ecb(&pad_with(&prefix, &v, &postfix, 16), &key, aes).expect("should have been padded")
        };
        let (bs, l) = detect_blocksize(&encr);
        assert_eq!(bs, 16);
        assert_eq!(l, prefix.len() + postfix.len())
    }

    #[test]
    fn detect_prefix_works() {
        let mut rng = rand::thread_rng();
        let n_pre = rng.gen_range(5..=30);
        let n_post = rng.gen_range(5..=30);
        let prefix: Vec<_> = (0..n_pre).map(|_| rng.gen()).collect();
        let postfix: Vec<_> = (0..n_post).map(|_| rng.gen()).collect();
        let key = rand_key(&mut rng);
        let encr = |v: &[u8]| {
            ecb(&pad_with(&prefix, &v, &postfix, 16), &key, aes).expect("should have been padded")
        };
        let npre = detect_prefix(&encr, 16);
        assert_eq!(npre, n_pre);
    }

    #[test]
    fn detect_ecb_works() {
        let file = fs::read_to_string("data/8.txt").expect("file missing");
        let hexes: Vec<_> = file.lines().map(from_hex).collect();
        let mut vals: Vec<_> = hexes.iter().map(|l| detect_ecb(l, 16)).collect();
        vals.sort();
        // one is ecb
        assert!(vals.pop().expect("should have lines"));
        // the rest are not
        assert!(!vals.pop().expect("should have lines"));
    }

    #[test]
    fn detect_ecb_works_vs_cbc() {
        let mut rng = rand::thread_rng();
        let bs = 16;
        let lines = vec![0u8; 3 * bs];
        for _ in 0..20 {
            let n_pre = rng.gen_range(5..=10);
            let pre: Vec<_> = (0..n_pre).map(|_| rng.gen()).collect();
            let n_post = rng.gen_range(5..=10);
            let post: Vec<_> = (0..n_post).map(|_| rng.gen()).collect();
            let arr = pad_with(&pre, &lines, &post, bs as u8);
            let is_ecb = rng.gen();
            let key = rand_key(&mut rng);
            let mut encr = vec![];
            if is_ecb {
                encr.extend(ecb(&arr, &key, aes).unwrap())
            } else {
                let iv = rand_key(&mut rng);
                encr.extend(cbc_encr(&arr, &key, &iv, aes).unwrap())
            }
            let ecb_detected = detect_ecb(&encr, bs);
            assert_eq!(is_ecb, ecb_detected)
        }
    }

    #[test]
    fn valid_pad_bytes_works() {
        let f = |decr: &[u8; 4], iv: &[u8; 4]| {
            let mut decr = *decr;
            xor_arr(&mut decr, iv);
            unpad_pkcs7(Vec::from(decr)).is_some()
        };
        let iv = &[0, 4, 4, 4];
        let blk = &[0, 7, 7, 7];
        assert_eq!(3, valid_pad_bytes(blk, iv, &f));
        let blk = &[0, 0, 3, 3];
        let iv = &[0, 0, 1, 1];
        assert_eq!(2, valid_pad_bytes(blk, iv, &f));
        let iv = &[17, 6, 0, 0];
        let blk = &[0, 1, 1, 1];
        assert_eq!(1, valid_pad_bytes(blk, iv, &f));
        let iv = &[0, 0, 0, 13];
        let blk = &[0, 0, 0, 12];
        assert_eq!(1, valid_pad_bytes(blk, iv, &f));
        let iv = &[0, 0, 0, 0];
        let blk = &[4, 4, 4, 4];
        assert_eq!(4, valid_pad_bytes(blk, iv, &f));
    }

    #[test]
    fn find_valid_iv_works() {
        let f = |decr: &[u8; 4], iv: &[u8; 4]| {
            let mut decr = *decr;
            xor_arr(&mut decr, iv);
            unpad_pkcs7(Vec::from(decr)).is_some()
        };
        let mut iv = [0, 0, 0, 0];
        let blk = &[0, 0, 0, 12];
        assert!(find_valid_iv(blk, &mut iv, 3, &f));
        assert_eq!(iv, [0, 0, 0, 13]);
    }

    #[test]
    fn decrypt_cbc_block_with_padding_oracle_works() {
        const N: usize = 16;
        let mut rng = rand::thread_rng();
        let key = rand_key(&mut rng);
        let iv = rand_key(&mut rng);
        let input: [u8; N] = rand_key(&mut rng);
        let encr = cbc_encr(&input, &key, &iv, aes)
            .unwrap()
            .try_into()
            .expect("incorrect block size");

        let oracle = |v: &[u8; N], iv: &[u8; N]| check_cbc_padding(v, &key, iv, inv_aes);
        let mut v = decrypt_cbc_block(&encr, &oracle).unwrap();
        xor_arr(&mut v, &iv);
        assert_eq!(&v, &input);
    }

    #[test]
    fn recover_iv_from_decrypt_works() {
        let mut rng = rand::thread_rng();
        let key = rand_key(&mut rng);
        let iv = rand_key(&mut rng);
        let decr = |arr: &[u8]| cbc_decr(arr, &key, &iv, inv_aes).unwrap();
        let iv_inferred = recover_iv_from_decrypt::<16>(decr);
        assert_eq!(iv, iv_inferred);
    }
}
