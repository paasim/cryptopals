use rand::Rng;

use crate::dist::str_score;
use crate::mersenne::{nxt, rand_n, seed_mt};
use crate::xor::xor_slice;
use std::cmp::{max, min};
use std::collections::BinaryHeap;

fn ctr_arr(nonce: u64, ctr: u64) -> [u8; 16] {
    ((nonce as u128) + ((ctr as u128) << 64)).to_le_bytes()
}

pub fn ctr(
    arr: &[u8],
    key: &[u8; 16],
    nonce: u64,
    f: fn(&[u8; 16], &[u8; 16]) -> [u8; 16],
) -> Vec<u8> {
    let chunks = arr.len() as u64 / 16 + min(arr.len() as u64 % 16, 1);
    let mut v = vec![];
    for i in 0..chunks {
        v.extend(f(&ctr_arr(nonce, i), key))
    }
    while v.len() > arr.len() {
        v.pop();
    }
    xor_slice(&mut v, arr);
    v
}

pub fn edit_block(
    arr: &mut [u8],
    new_block: &[u8; 16],
    block_pos: usize,
    key: &[u8; 16],
    nonce: u64,
    f: fn(&[u8; 16], &[u8; 16]) -> [u8; 16],
) {
    let encr_block = f(&ctr_arr(nonce, block_pos as u64), key);
    for i in 0..16 {
        if block_pos * 16 + i >= arr.len() {
            break;
        }
        arr[block_pos * 16 + i] = encr_block[i] ^ new_block[i];
    }
}

pub fn decrypt_ctr<const N: usize>(
    arr: &[u8],
    edit: impl Fn(&mut [u8], &[u8; N], usize),
) -> Vec<u8> {
    let chunks = arr.len() / N + min(arr.len() % N, 1);
    let mut decr = Vec::from(arr);
    for chunk in 0..chunks {
        edit(&mut decr, &[0; N], chunk);
    }
    xor_slice(&mut decr, &arr);
    decr
}

pub fn get_keys_for_block(mut encrs: [Vec<u8>; 16]) -> [u8; 16] {
    let mut res = [0; 16];
    for i in 0..16 {
        let mut scores = BinaryHeap::new();
        let str = &mut encrs[i];
        for c in 0..=255 {
            xor_slice(str, &[c]);
            scores.push((str_score(&str), c));
            xor_slice(str, &[c]);
        }
        res[i] = scores.pop().unwrap().1;
    }
    res
}

pub fn break_ctr_blocks(encrs: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let bs = 16;
    let max_len = encrs.iter().fold(0, |m, a| max(m, a.len()));
    let blocks = max_len / bs + min(max_len % bs, 1);
    let mut key = vec![];
    for blk in 0..blocks {
        let mut encr_block = [0; 16].map(|_| Vec::new());
        for e in encrs {
            let l = e.len();
            if l > blk * bs {
                for i in blk * bs..min(l, (blk + 1) * bs) {
                    encr_block[i % bs].push(e[i]);
                }
            }
        }
        key.extend(get_keys_for_block(encr_block));
    }
    let mut decr = Vec::from(encrs);
    for d in decr.iter_mut() {
        xor_slice(d, &key)
    }
    decr
}

pub fn mt19937(arr: &[u8], seed: u16) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let prefix: Vec<u8> = (0..10).map(|_| rng.gen()).collect();
    let mut state = seed_mt(seed as u32);
    let _: Vec<_> = (0..prefix.len() / 4).map(|_| nxt(&mut state)).collect();
    let mut res = Vec::from(arr);
    let mut i = 0;
    let mut cur_key = nxt(&mut state).to_le_bytes();
    let mut i_key = prefix.len() % 4;
    while i < arr.len() {
        if i_key == 4 {
            i_key = 0;
            cur_key = nxt(&mut state).to_le_bytes();
        }
        res[i] ^= cur_key[i_key];
        i += 1;
        i_key += 1;
    }
    res
}

pub fn get_mt19937_seed(f: impl Fn(&[u8]) -> Vec<u8>) -> Option<u16> {
    let arr = [b'A'; 14];
    let mut encr = f(&arr);
    xor_slice(&mut encr, &arr);
    for seed in u16::MIN..=u16::MAX {
        let ks = rand_n::<624>(seed as u32)
            .into_iter()
            .fold(vec![], |mut v, a| {
                v.extend(a.to_le_bytes());
                v
            });
        let mut i_encr = 0;
        let mut i_ks = 0;
        while i_ks < ks.len() {
            if encr[i_encr] == ks[i_ks] {
                i_encr += 1;
            } else {
                i_encr = 0;
            }
            if i_encr == encr.len() {
                return Some(seed);
            }
            i_ks += 1;
        }
    }
    return None;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aes::aes;
    use crate::block::rand_key;
    use rand::Rng;

    #[test]
    fn ctr_arr_works() {
        let mut rng = rand::thread_rng();
        let nonce = rng.gen();
        let ctr = rng.gen_range(0..=255);
        let key = ctr_arr(nonce, ctr);
        assert_eq!(key[..8], nonce.to_le_bytes());
        assert_eq!(key[8..], ctr.to_le_bytes());
    }

    #[test]
    fn ctr_is_its_own_inverse() {
        let mut rng = rand::thread_rng();
        let n = rng.gen_range(1..=100);
        let mut bytes = vec![];
        for _ in 0..n {
            bytes.push(rng.gen());
        }

        let key = rand_key(&mut rng);
        let nonce = rng.gen();
        let encr = ctr(&bytes, &key, nonce, aes);
        assert_ne!(bytes, encr);
        let decr = ctr(&encr, &key, nonce, aes);
        assert_eq!(bytes, decr);
    }

    #[test]
    fn edit_block_works() {
        let mut rng = rand::thread_rng();
        let nonce = rng.gen();
        let data = vec![b'A'; 40];
        let key = rand_key(&mut rng);
        let mut encr = ctr(&data, &key, nonce, aes);
        let edit = [b'B'; 16];
        edit_block(&mut encr, &edit, 1, &key, nonce, aes);
        let decr = ctr(&encr, &key, nonce, aes);
        assert_eq!(&decr[0..16], &data[0..16]);
        assert_eq!(&decr[16..32], &edit);
        assert_eq!(&decr[32..decr.len()], &data[32..data.len()]);
    }
}
