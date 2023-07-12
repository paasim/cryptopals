use crate::dist::{hamming_score, str_score};
use std::cmp::min;
use std::collections::BinaryHeap;
use std::ops::BitXorAssign;

pub fn xor_slice<T: BitXorAssign + Copy>(v1: &mut [T], v2: &[T]) {
    for i in 0..v1.len() {
        v1[i] ^= v2[i % v2.len()];
    }
}

pub fn xor_arr<const N: usize, T: BitXorAssign + Copy>(arr: &mut [T; N], key: &[T; N]) {
    for i in 0..N {
        arr[i] ^= key[i];
    }
}

pub fn single_block_cipher(bytes: &[u8], n: usize) -> Vec<(usize, u8)> {
    let mut scores = BinaryHeap::new();

    for b in u8::MIN..=u8::MAX {
        let mut xor = Vec::from(bytes);
        xor_slice(&mut xor, &[b]);
        scores.push((str_score(&xor), b))
    }
    scores.into_iter().take(n).collect()
}

pub fn single_block_ciphers<'a>(
    bytes_v: &[&'a Vec<u8>],
    n: usize,
) -> Vec<(usize, u8, &'a Vec<u8>)> {
    let mut scores = BinaryHeap::new();
    for bytes in bytes_v {
        for (sc, c) in single_block_cipher(bytes, n) {
            scores.push((sc, c, *bytes))
        }
    }
    scores.into_iter().take(n).collect()
}

pub fn keysize(bytes: &[u8], n: usize) -> Vec<(isize, usize)> {
    let mut scores = BinaryHeap::new();
    for keylen in 2..=min(40, bytes.len() / 2) {
        let sc = hamming_score(&bytes[0..keylen], &bytes[keylen..2 * keylen]) / keylen as isize;
        scores.push((sc, keylen))
    }
    scores.into_iter().take(n).collect()
}

pub fn into_blocks(bytes: &[u8], blocksize: usize) -> Vec<Vec<u8>> {
    let mut v: Vec<_> = (0..blocksize).map(|_| Vec::new()).collect();
    for (i, &b) in bytes.iter().enumerate() {
        v[i % blocksize].push(b)
    }
    v
}

fn multi_block_cipher(bytes: &[u8], blocksize: usize, n: usize) -> Vec<(usize, Vec<u8>)> {
    into_blocks(bytes, blocksize)
        .into_iter()
        .map(|v| single_block_cipher(&v, n))
        .map(|v| {
            v.into_iter()
                .map(|(sc, k)| (sc, vec![k]))
                .collect::<Vec<_>>()
        })
        .reduce(|v1s, v2s| {
            let mut scs = BinaryHeap::new();
            for (sc1, k1) in v1s {
                for (sc2, k2) in v2s.iter() {
                    let mut k1_copy = k1.clone();
                    for k in k2 {
                        k1_copy.push(*k);
                    }
                    scs.push((sc1 + sc2, k1_copy))
                }
            }
            scs.into_iter().take(n).collect()
        })
        .expect("empty array")
}

pub fn multi_block_cipher_ks(bytes: &[u8], n: usize, n_ks: usize) -> Vec<(usize, Vec<u8>)> {
    let mut scores = BinaryHeap::new();
    for (_, ks) in keysize(&bytes, n) {
        for (sc, k) in multi_block_cipher(bytes, ks, n_ks) {
            scores.push((sc, k))
        }
    }
    scores.into_iter().take(n).collect()
}

pub fn top_n<T: Ord>(v: &[T], n: usize) -> Vec<&T> {
    v.into_iter()
        .collect::<BinaryHeap<_>>()
        .into_iter()
        .take(n)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dist::str_score;
    use crate::encode::{from_ascii, from_hex, to_hex};

    #[test]
    fn xor_works() {
        let hex1 = "1c0111001f010100061a024b53535009181c";
        let hex2 = "686974207468652062756c6c277320657965";
        let xor = "746865206b696420646f6e277420706c6179";
        let mut bytes1 = from_hex(hex1).expect("should have been hex");
        let bytes2 = from_hex(hex2).expect("should have been hex");
        xor_slice(&mut bytes1, &bytes2);

        assert_eq!(to_hex(&bytes1), xor)
    }

    #[test]
    fn xor_block_works_with_smaller_block() {
        let str1 = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
        let str2 = "ICE";
        let mut xor = from_ascii(str1);
        xor_slice(&mut xor, &from_ascii(str2));
        let hex = to_hex(&xor);
        let res = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
        assert_eq!(hex, res)
    }

    #[test]
    fn xor_arr_works() {
        let mut input = [
            0xdb, 0x13, 0x53, 0x45, 0xd4, 0xd4, 0xd4, 0xd5, 0x01, 0x01, 0x01, 0x01, 0xf2, 0x0a,
            0x22, 0x5c,
        ];
        let cln = input.clone();
        let key = [
            0x8e, 0x4d, 0xa1, 0xbc, 0xd5, 0xd5, 0xd7, 0xd6, 0x01, 0x01, 0x01, 0x01, 0x9f, 0xdc,
            0x58, 0x9d,
        ];
        xor_arr(&mut input, &key);
        assert_ne!(input, cln);
        assert_eq!(input[2], 0x53 ^ 0xa1);
        xor_arr(&mut input, &key);
        assert_eq!(input, cln);
    }

    #[test]
    fn keysize_works() {
        let b1 = &[1, 2, 5, 1, 2, 3, 1, 2, 3];
        let b2 = &[1, 2, 1, 4, 1, 2];
        let kss1 = keysize(b1, 3);
        let (_, ks1) = kss1[0];
        let kss2 = keysize(b2, 3);
        let (_, ks2) = kss2[0];
        assert_eq!(3, ks1);
        assert_eq!(2, ks2);
    }

    #[test]
    fn into_blocks_works() {
        let v = vec![1, 2, 3, 4, 5, 6];
        let blks = into_blocks(&v, 2);
        assert_eq!(blks, vec![vec![1, 3, 5], vec![2, 4, 6]]);
    }

    #[test]
    fn top_n_works() {
        let str0 = from_ascii("b .");
        let str1 = from_ascii("Aea");
        let str2 = from_ascii("qqq");
        let sc0 = str_score(&str0);
        let sc1 = str_score(&str1);

        let strs = vec![&str0, &str1, &str2];
        let scored: Vec<_> = strs.into_iter().map(|str| (str_score(str), str)).collect();
        let topn = top_n(&scored, 2);
        assert_eq!(topn, vec![&(sc1, &str1), &(sc0, &str0)]);
    }
}
