extern crate regex;

use std::fmt;
use std::num::ParseIntError;
use std::ops;
use std::str::FromStr;

use regex::Regex;

#[derive(PartialEq)]
struct Fe25519 {
    // 63+64+64+64=255
    x3: u64,
    x2: u64,
    x1: u64,
    x0: u64,
}

impl fmt::Display for Fe25519 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0x{:016x}-{:016x}-{:016x}-{:016x}", self.x3, self.x2, self.x1, self.x0)
    }
}

impl fmt::Debug for Fe25519 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0x{:016x}-{:016x}-{:016x}-{:016x}", self.x3, self.x2, self.x1, self.x0)
    }
}

#[derive(Debug)]
enum ParseError {
    LengthToShort,
    LengthToLong,
    Missing0x,
    ParseErrorX3(ParseIntError),
    ParseErrorX2(ParseIntError),
    ParseErrorX1(ParseIntError),
    ParseErrorX0(ParseIntError),
}

impl FromStr for Fe25519 {
    type Err = self::ParseError;
    fn from_str(hex_str: &str) -> Result<Self, self::ParseError> {
        if &hex_str[0..2] != "0x" { return Err(self::ParseError::Missing0x); };
        let re = Regex::new(r"[^A-Fa-f0-9]").unwrap();
        let tmp_str = re.replace_all(hex_str, "");
        let x = tmp_str.len();
        if x < 65 { return Err(ParseError::LengthToShort); }
        if x > 65 { return Err(ParseError::LengthToLong); }
        let (x3, x2, x1, x0) = match
            (u64::from_str_radix(&tmp_str[(x - 64)..(x - 48)], 16),
             u64::from_str_radix(&tmp_str[(x - 48)..(x - 32)], 16),
             u64::from_str_radix(&tmp_str[(x - 32)..(x - 16)], 16),
             u64::from_str_radix(&tmp_str[(x - 16)..x], 16)) {
            (Ok(x3), Ok(x2), Ok(x1), Ok(x0)) => (x3, x2, x1, x0),
            (Err(e), _, _, _) => return Err(self::ParseError::ParseErrorX3(e)),
            (_, Err(e), _, _) => return Err(self::ParseError::ParseErrorX2(e)),
            (_, _, Err(e), _) => return Err(self::ParseError::ParseErrorX1(e)),
            (_, _, _, Err(e)) => return Err(self::ParseError::ParseErrorX0(e)),
        };
        Ok(Fe25519 { x3, x2, x1, x0 })
    }
}

impl ops::Add<Fe25519> for Fe25519 {
    type Output = Fe25519;
    fn add(self, _rhs: Fe25519) -> Fe25519 {
        let mut z = self.x0 as u128 + _rhs.x0 as u128;
        let x0 = z as u64;
        z = self.x1 as u128 + _rhs.x1 as u128 + (z >> 64);
        let x1 = z as u64;
        z = self.x2 as u128 + _rhs.x2 as u128 + (z >> 64);
        let x2 = z as u64;
        z = self.x3 as u128 + _rhs.x3 as u128 + (z >> 64);
        let x3 = z as u64 & 0x7FFFFFFFFFFFFFFF;
        Fe25519 { x3, x2, x1, x0 }
    }
}

impl ops::Mul<Fe25519> for Fe25519 {
    type Output = (Fe25519, Fe25519);
    fn mul(self: Fe25519, _rhs: Fe25519) -> (Fe25519, Fe25519) {
        let a = self;
        let b = _rhs;

        let mut z = a.x0 as u128 * b.x0 as u128;
        let t0 = z as u64;
        z = a.x0 as u128 * b.x1 as u128 + (z >> 64);
        let t1 = z as u64;
        z = a.x0 as u128 * b.x2 as u128 + (z >> 64);
        let t2 = z as u64;
        z = a.x0 as u128 * b.x3 as u128 + (z >> 64);
        let t3 = z as u64;
        let t4 = (z >> 64) as u64;

        let mut z = a.x1 as u128 * b.x0 as u128 + t1 as u128;
        let t1 = z as u64;
        z = a.x1 as u128 * b.x1 as u128 + (z >> 64) + t2 as u128;
        let t2 = z as u64;
        z = a.x1 as u128 * b.x2 as u128 + (z >> 64) + t3 as u128;
        let t3 = z as u64;
        z = a.x1 as u128 * b.x3 as u128 + (z >> 64) + t4 as u128;
        let t4 = z as u64;
        let t5 = (z >> 64) as u64;

        let mut z = a.x2 as u128 * b.x0 as u128 + t2 as u128;
        let t2 = z as u64;
        z = a.x2 as u128 * b.x1 as u128 + (z >> 64) + t3 as u128;
        let t3 = z as u64;
        z = a.x2 as u128 * b.x2 as u128 + (z >> 64) + t4 as u128;
        let t4 = z as u64;
        z = a.x2 as u128 * b.x3 as u128 + (z >> 64) + t5 as u128;
        let t5 = z as u64;
        let t6 = (z >> 64) as u64;

        let mut z = a.x3 as u128 * b.x0 as u128 + t3 as u128;
        let t3 = z as u64;
        z = a.x3 as u128 * b.x1 as u128 + (z >> 64) + t4 as u128;
        let t4 = z as u64;
        z = a.x3 as u128 * b.x2 as u128 + (z >> 64) + t5 as u128;
        let t5 = z as u64;
        z = a.x3 as u128 * b.x3 as u128 + (z >> 64) + t6 as u128;
        let t6 = z as u64;
        let t7 = (z >> 64) as u64;


        let lsb = Fe25519 { x3: t3, x2: t2, x1: t1, x0: t0 };
        let msb = Fe25519 { x3: t7, x2: t6, x1: t5, x0: t4 };
        (msb, lsb)
    }
}

#[cfg(test)]
mod tests {
    #[cfg(test)]
    extern crate num_bigint;
    extern crate rand;
    extern crate num_traits;

    use num_bigint::{BigUint, RandomBits};
    use num_traits::One;
    use rand::Rng;

    use super::*;

    #[test]
    fn test_fuzz_add() {
        let mut rng = rand::thread_rng();
        for _index in 1..10000 {
            let a_expected: BigUint = rng.sample(RandomBits::new(254));
            let b_expected: BigUint = rng.sample(RandomBits::new(254));
            let s_expected = Fe25519::from_str(&format!("0x{:064x}", &a_expected + &b_expected)).unwrap();
            let a_actual = Fe25519::from_str(&format!("0x{:064x}", a_expected)).unwrap();
            let b_actual = Fe25519::from_str(&format!("0x{:064x}", b_expected)).unwrap();
            let s_actual = a_actual + b_actual;
            assert_eq!(s_expected, s_actual);
        }
    }

    #[test]
    fn test_fuzz_mul() {
        let mut rng = rand::thread_rng();
        let one: BigUint = One::one();
        let two_256 = one << 256;
        for _index in 1..10000 {
            let a_expected: BigUint = rng.sample(RandomBits::new(256));
            let b_expected: BigUint = rng.sample(RandomBits::new(256));
            let lsb_expected = Fe25519::from_str(&format!("0x{:064x}", (&a_expected * &b_expected) % &two_256)).unwrap();
            let msb_expected = Fe25519::from_str(&format!("0x{:064x}", (&a_expected * &b_expected) / &two_256)).unwrap();
            let a_actual = Fe25519::from_str(&format!("0x{:064x}", a_expected)).unwrap();
            let b_actual = Fe25519::from_str(&format!("0x{:064x}", b_expected)).unwrap();
            let actual = a_actual * b_actual;
            assert_eq!(lsb_expected, actual.1);
            assert_eq!(msb_expected, actual.0);
        }
    }
}
