pub fn from_hex(hex: &str) -> Vec<u8> {
    let mut bytes = vec![];
    let m = hex.len() % 2;
    if m == 1 {
        bytes.push(u8::from_str_radix(&hex[0..1], 16).expect("not a base16 character"));
    }
    for i in (0..hex.len() / 2).map(|i| i * 2 + m) {
        bytes.push(u8::from_str_radix(&hex[i..i + 2], 16).expect("not a base16 character"));
    }
    bytes
}

pub fn to_hex(bytes: &[u8]) -> String {
    bytes
        .into_iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("")
}

fn b64_from_u8_triplet(b0: u8, b1: Option<u8>, b2: Option<u8>) -> [char; 4] {
    [
        b64_render(b0 >> 2),
        b64_render(((b0 & 3) << 4) + (b1.unwrap_or(0) >> 4)),
        b64_render(b1.map_or(64, |b1| ((b1 & 15) << 2) + (b2.unwrap_or(0) >> 6))),
        b64_render(b2.map_or(64, |b2| b2 & 63)),
    ]
}

fn u8_from_b64_quartet(c0: char, c1: char, c2: char, c3: char) -> [u8; 3] {
    let b0 = b64_parse(c0);
    let b1 = b64_parse(c1);
    let b2 = b64_parse(c2);
    let b3 = b64_parse(c3);
    [
        (b0 << 2) + (b1 >> 4),
        ((b1 & 15) << 4) + (b2 >> 2),
        ((b2 & 3) << 6) + b3,
    ]
}

fn b64_parse(c: char) -> u8 {
    match c {
        'A'..='Z' => c as u8 - 65,
        'a'..='z' => c as u8 + 26 - 97,
        '0'..='9' => c as u8 + 52 - 48,
        '+' => 62,
        '/' => 63,
        '=' => 0,
        c => panic!("{} is not a base64 character", c),
    }
}

fn b64_render(b64: u8) -> char {
    match b64 {
        0..=25 => (b64 + 65) as char,
        26..=51 => (b64 - 26 + 97) as char,
        52..=61 => (b64 - 52 + 48) as char,
        62 => '+',
        63 => '/',
        64 => '=',
        _ => panic!("{} is larger than 64", b64),
    }
}

pub fn from_base64(b64: &str) -> Vec<u8> {
    let mut it = b64.chars();
    let mut res = Vec::new();
    while let Some(c0) = it.next().to_owned() {
        let c1 = it
            .next()
            .map(|c| c)
            .expect("invalid number of b64-characters");
        let c2 = it
            .next()
            .map(|c| c)
            .expect("invalid number of b64-characters");
        let c3 = it
            .next()
            .map(|c| c)
            .expect("invalid number of b64-characters");
        for b in u8_from_b64_quartet(c0, c1, c2, c3) {
            res.push(b)
        }
    }
    res
}

pub fn to_base64(bytes: &[u8]) -> String {
    let mut it = bytes.into_iter();
    let mut res = String::new();
    while let Some(b0) = it.next().to_owned() {
        let b1 = it.next().map(|b| *b);
        let b2 = it.next().map(|b| *b);
        for c in b64_from_u8_triplet(*b0, b1, b2) {
            res.push(c)
        }
    }
    res
}

pub fn from_ascii(str: &str) -> Vec<u8> {
    str.bytes().collect()
}

pub fn block_from_ascii<const N: usize>(str: &str) -> [u8; N] {
    str.bytes()
        .collect::<Vec<_>>()
        .try_into()
        .expect("incorrect bs")
}

pub fn to_ascii(bytes: &[u8]) -> String {
    let ascii = bytes
        .into_iter()
        .filter(|c| c.is_ascii())
        .map(|c| *c)
        .collect();
    String::from_utf8(ascii).expect("should have had only ascii left")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64_ascii_works() {
        let result1 = b64_render(5);
        let result2 = b64_render(37);
        let result3 = b64_render(64);
        assert_eq!(result1, 'F');
        assert_eq!(result2, 'l');
        assert_eq!(result3, '=');
    }

    #[test]
    fn b64_works() {
        let result = b64_from_u8_triplet(b'M', Some(b'a'), Some(b'n'));
        assert_eq!(result, ['T', 'W', 'F', 'u']);
    }

    #[test]
    fn to_base64_works() {
        let result = to_base64(&[b'M', b'a', b'n', b'y']);
        assert_eq!(result, String::from("TWFueQ=="));
    }

    #[test]
    fn from_base64_works() {
        let str = &[b'M', b'a', b'n', b'y'];
        let b64 = to_base64(str);
        let result = from_base64(&b64);
        assert_eq!(&result[0..4], str);
    }

    #[test]
    fn from_hex_works() {
        let bytes = from_hex("49276d");
        assert_eq!(bytes, vec![4 * 16 + 9, 2 * 16 + 7, 6 * 16 + 13]);
    }

    #[test]
    fn to_hex_works() {
        let input = String::from("49276d");
        let bytes = from_hex(&input);
        assert_eq!(input, to_hex(&bytes))
    }

    #[test]
    fn hex_to_base64_works() {
        let str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let bytes = from_hex(&str);
        let result = to_base64(&bytes);
        assert_eq!(
            result,
            String::from("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")
        );
    }
}
