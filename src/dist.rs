use crate::xor::xor_slice;

fn char_score(c: u8) -> usize {
    if c.is_ascii_whitespace() {
        return 140;
    }
    if c.is_ascii_punctuation() {
        return 50;
    }
    let mut sc = match c {
        b'a' | b'A' => 82,
        b'b' | b'B' => 15,
        b'c' | b'C' => 28,
        b'd' | b'D' => 43,
        b'e' | b'E' => 127,
        b'f' | b'F' => 22,
        b'g' | b'G' => 20,
        b'h' | b'H' => 61,
        b'i' | b'I' => 70,
        b'j' | b'J' => 2,
        b'k' | b'K' => 8,
        b'l' | b'L' => 40,
        b'm' | b'M' => 24,
        b'n' | b'N' => 67,
        b'o' | b'O' => 75,
        b'p' | b'P' => 19,
        b'q' | b'Q' => 1,
        b'r' | b'R' => 60,
        b's' | b'S' => 63,
        b't' | b'T' => 91,
        b'u' | b'U' => 28,
        b'v' | b'V' => 10,
        b'w' | b'W' => 24,
        b'x' | b'X' => 2,
        b'y' | b'Y' => 20,
        b'z' | b'Z' => 7,
        _ => 0,
    };
    if c.is_ascii_lowercase() {
        sc *= 2;
    }
    sc
}

pub fn str_score(str: &[u8]) -> usize {
    str.iter().fold(0, |s, c| s + char_score(*c))
}

pub fn hamming_score(b1: &[u8], b2: &[u8]) -> isize {
    let mut v = Vec::from(b1);
    xor_slice(&mut v, b2);
    -(v.iter().fold(0, |s, b| s + b.count_ones()) as isize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode::from_ascii;

    #[test]
    fn str_score_works() {
        let result1 = str_score(&[97, 83, 100]);
        assert_eq!(result1, 82 * 2 + 63 + 43 * 2);
    }

    #[test]
    fn hamming_works() {
        let b1 = from_ascii("this is a test");
        let b2 = from_ascii("wokka wokka!!!");
        let result1 = hamming_score(&b1, &b2);
        assert_eq!(result1, -37);
    }
}
