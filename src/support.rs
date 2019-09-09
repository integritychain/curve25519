#![deny(clippy::all)]

use std::fmt;
use std::num::ParseIntError;
use std::str::FromStr;

use regex::Regex;

use crate::arith::Fe25519;

impl fmt::Display for Fe25519 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0x{:016x}-{:016x}-{:016x}-{:016x}", self.x3, self.x2, self.x1, self.x0)
    }
}

impl fmt::Binary for Fe25519 {
    // Hijack this for big-endian display
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0x{:016x}-{:016x}-{:016x}-{:016x}", u64::from_be(self.x0), u64::from_be(self.x1), u64::from_be(self.x2), u64::from_be(self.x3))
    }
}

impl fmt::Debug for Fe25519 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0x{:016x}-{:016x}-{:016x}-{:016x}", self.x3, self.x2, self.x1, self.x0)
    }
}

#[derive(Debug)]
pub enum ParseError {
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
        if &hex_str[0..2] != "0x" {
            return Err(self::ParseError::Missing0x);
        };
        let re = Regex::new(r"[^A-Fa-f0-9]").unwrap();
        let tmp_str = re.replace_all(hex_str, "");
        let x = tmp_str.len();
        if x < 65 {
            return Err(ParseError::LengthToShort);
        }
        if x > 65 {
            return Err(ParseError::LengthToLong);
        }
        let (x3, x2, x1, x0) = match (
            u64::from_str_radix(&tmp_str[(x - 64)..(x - 48)], 16),
            u64::from_str_radix(&tmp_str[(x - 48)..(x - 32)], 16),
            u64::from_str_radix(&tmp_str[(x - 32)..(x - 16)], 16),
            u64::from_str_radix(&tmp_str[(x - 16)..x], 16),
        ) {
            (Ok(x3), Ok(x2), Ok(x1), Ok(x0)) => (x3, x2, x1, x0),
            (Err(e), _, _, _) => return Err(self::ParseError::ParseErrorX3(e)),
            (_, Err(e), _, _) => return Err(self::ParseError::ParseErrorX2(e)),
            (_, _, Err(e), _) => return Err(self::ParseError::ParseErrorX1(e)),
            (_, _, _, Err(e)) => return Err(self::ParseError::ParseErrorX0(e)),
        };
        Ok(Fe25519 { x3, x2, x1, x0 })
    }
}

pub fn check_size(src: &Fe25519) -> bool {
    if (src.x3 < 0x7FFF_FFFF_FFFF_FFFF)
        | ((src.x3 == 0x7FFF_FFFF_FFFF_FFFF)
        & ((src.x2 < 0xFFFF_FFFF_FFFF_FFFF) | (src.x1 < 0xFFFF_FFFF_FFFF_FFFF) | (src.x0 < 0xFFFF_FFFF_FFFF_FFED)))
    {
        true
    } else {
        println!("Oversize value encountered: {}", src);
        false
    }
}
