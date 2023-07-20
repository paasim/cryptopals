use crate::xor::xor_arr;

const MOD8: u8 = 27;

pub const fn multip2(x: u8) -> u8 {
    if x >= 128 {
        (x << 1) ^ MOD8
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
        y >>= 1;
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

fn shift4(i: usize) -> usize {
    // i / 4 is current col
    // i % 4 current row
    // 16 - i is the modification to columns
    (i / 4 + 16 - i) % 4 * 4 + i % 4
}

fn shift_rows(arr: &mut [u8; 16]) {
    let cln = arr.clone();
    for i in 0..16 {
        arr[shift4(i)] = cln[i];
    }
}

fn inv_shift_rows(arr: &mut [u8; 16]) {
    let cln = arr.clone();
    for i in 0..16 {
        arr[i] = cln[shift4(i)];
    }
}

fn mix_columns(arr: &mut [u8; 16]) {
    let arr1 = arr.clone();
    let arr2 = arr.map(multip2);
    for i in 0..16 {
        arr[i] = arr2[i]
            ^ arr1[i / 4 * 4 + (i + 3) % 4]
            ^ arr1[i / 4 * 4 + (i + 2) % 4]
            ^ arr2[i / 4 * 4 + (i + 1) % 4]
            ^ arr1[i / 4 * 4 + (i + 1) % 4]
    }
}

fn inv_mix_columns(arr: &mut [u8; 16]) {
    let arr9 = arr.map(|x| multip(x, 9));
    let arr11 = arr.map(|x| multip(x, 11));
    let arr13 = arr.map(|x| multip(x, 13));
    *arr = arr.map(|x| multip(x, 14));
    for i in 0..16 {
        arr[i] ^= arr11[i / 4 * 4 + (i + 1) % 4]
            ^ arr13[i / 4 * 4 + (i + 2) % 4]
            ^ arr9[i / 4 * 4 + (i + 3) % 4];
    }
}

pub const fn sbox(a: u8) -> u8 {
    let b = INV[a as usize];
    b ^ b.rotate_left(1) ^ b.rotate_left(2) ^ b.rotate_left(3) ^ b.rotate_left(4) ^ 0x63
}

pub const fn inv_sbox(s: u8) -> u8 {
    INV[(s.rotate_left(1) ^ s.rotate_left(3) ^ s.rotate_left(6) ^ 0x05) as usize]
}

fn sub_bytes<const N: usize>(arr: &mut [u8; N]) {
    for i in 0..N {
        arr[i] = sbox(arr[i]);
    }
}

fn inv_sub_bytes<const N: usize>(arr: &mut [u8; N]) {
    for i in 0..N {
        arr[i] = inv_sbox(arr[i]);
    }
}

const fn rc(n: u8) -> u8 {
    pow(2, n - 1)
}

const fn precalc_rc() -> [u8; 10] {
    let mut res = [0u8; 10];
    let mut i = 0;
    while i < 10 {
        res[i as usize] = rc(i + 1);
        i += 1;
    }
    res
}

const RC: [u8; 10] = precalc_rc();

fn next_key(key: &mut [u8; 16], n: u8) {
    for i in 0..4 {
        key[i] ^= sbox(key[12 + (i + 1) % 4]);
    }
    key[0] ^= RC[n as usize - 1];
    for i in 4..16 {
        key[i] ^= key[i - 4];
    }
}

fn prev_key(key: &mut [u8; 16], n: u8) {
    for i in (4..16).rev() {
        key[i] ^= key[i - 4];
    }
    for i in 0..4 {
        key[i] ^= sbox(key[12 + (i + 1) % 4]);
    }
    key[0] ^= RC[n as usize - 1];
}

fn last_key(key: &mut [u8; 16]) {
    for i in 1..=10 {
        next_key(key, i);
    }
}

pub fn aes(arr: &[u8; 16], key: &[u8; 16]) -> [u8; 16] {
    let mut arr = arr.clone();
    let mut key = key.clone();
    xor_arr(&mut arr, &key);
    next_key(&mut key, 1);
    for i in 2..=10 {
        sub_bytes(&mut arr);
        shift_rows(&mut arr);
        mix_columns(&mut arr);
        xor_arr(&mut arr, &key);
        next_key(&mut key, i);
    }
    sub_bytes(&mut arr);
    shift_rows(&mut arr);
    xor_arr(&mut arr, &key);
    arr
}

pub fn inv_aes(arr: &[u8; 16], key: &[u8; 16]) -> [u8; 16] {
    let mut arr = arr.clone();
    let mut key = key.clone();
    last_key(&mut key);
    xor_arr(&mut arr, &key);
    inv_shift_rows(&mut arr);
    inv_sub_bytes(&mut arr);
    for i in 0..=8 {
        prev_key(&mut key, 10 - i);
        xor_arr(&mut arr, &key);
        inv_mix_columns(&mut arr);
        inv_shift_rows(&mut arr);
        inv_sub_bytes(&mut arr);
    }
    prev_key(&mut key, 1);
    xor_arr(&mut arr, &key);
    arr
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode::block_from_ascii;

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
    fn shift_rows_works() {
        let mut input = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15];
        shift_rows(&mut input);
        let expected = [0, 5, 10, 15, 1, 6, 11, 12, 2, 7, 8, 13, 3, 4, 9, 14];
        assert_eq!(input, expected);
    }

    #[test]
    fn inv_shift_rows_works() {
        let mut input = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let orig = input.clone();
        shift_rows(&mut input);
        assert_ne!(input, orig);
        inv_shift_rows(&mut input);
        assert_eq!(input, orig);
    }

    #[test]
    fn mix_columns_works() {
        let mut input = [
            0xdb, 0x13, 0x53, 0x45, 0xd4, 0xd4, 0xd4, 0xd5, 0x01, 0x01, 0x01, 0x01, 0xf2, 0x0a,
            0x22, 0x5c,
        ];
        let expected = [
            0x8e, 0x4d, 0xa1, 0xbc, 0xd5, 0xd5, 0xd7, 0xd6, 0x01, 0x01, 0x01, 0x01, 0x9f, 0xdc,
            0x58, 0x9d,
        ];
        mix_columns(&mut input);
        assert_eq!(input, expected);
    }

    #[test]
    fn inv_mix_columns_works() {
        let mut input = [
            0x8e, 0x4d, 0xa1, 0xbc, 0xd5, 0xd5, 0xd7, 0xd6, 0x01, 0x01, 0x01, 0x01, 0x9f, 0xdc,
            0x58, 0x9d,
        ];
        let expected = [
            0xdb, 0x13, 0x53, 0x45, 0xd4, 0xd4, 0xd4, 0xd5, 0x01, 0x01, 0x01, 0x01, 0xf2, 0x0a,
            0x22, 0x5c,
        ];
        inv_mix_columns(&mut input);
        assert_eq!(input, expected);
        let mut input = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let cln = input.clone();
        mix_columns(&mut input);
        inv_mix_columns(&mut input);
        assert_eq!(input, cln);
    }

    #[test]
    fn sbox_works() {
        assert_eq!(sbox(0x9a), 0xb8);
        assert_eq!(sbox(0x36), 0x05);
        assert_eq!(sbox(0), 0x63);
    }

    #[test]
    fn sub_bytes_works() {
        let mut input = [0x9a, 0x00, 0x01];
        let expected = [0xb8, 0x63, 0x7c];
        sub_bytes(&mut input);
        assert_eq!(expected, input);
    }

    #[test]
    fn inv_sub_bytes_works() {
        let mut input = [1, 2, 14, 238, 121, 77, 4, 12, 0, 255];
        let orig = input.clone();
        sub_bytes(&mut input);
        assert_ne!(input, orig);
        inv_sub_bytes(&mut input);
        assert_eq!(input, orig);
    }

    #[test]
    fn next_and_prev_key_are_inverses() {
        let mut input = [
            0xdb, 0x13, 0x53, 0x45, 0xd4, 0xd4, 0xd4, 0xd5, 0x01, 0x01, 0x01, 0x01, 0xf2, 0x0a,
            0x22, 0x5c,
        ];
        let cln = input.clone();
        next_key(&mut input, 1);
        assert_ne!(input, cln);
        next_key(&mut input, 2);
        assert_ne!(input, cln);
        prev_key(&mut input, 2);
        prev_key(&mut input, 1);
        assert_eq!(input, cln);

        next_key(&mut input, 10);
        assert_ne!(input, cln);
        prev_key(&mut input, 10);
        assert_eq!(input, cln);
    }

    #[test]
    fn aes_works_simple() {
        let bytes: [u8; 16] = block_from_ascii("fellow cubmarine");
        let key: [u8; 16] = block_from_ascii("YELLOW SUBMARINE");
        let encr = aes(&bytes, &key);
        assert_ne!(bytes, encr);
        let decr = inv_aes(&encr, &key);
        assert_eq!(bytes, decr);
    }
}
