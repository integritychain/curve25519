#[macro_use]
extern crate lazy_static;
extern crate regex;

use std::ops;

mod support;

#[cfg(test)]
mod tests;

#[derive(PartialEq)]
pub struct Fe25519 {
    // 63+64+64+64=255; X3 is MSB
    x3: u64,
    x2: u64,
    x1: u64,
    x0: u64,
}

impl ops::Add<Fe25519> for Fe25519 {
    type Output = Fe25519;
    fn add(self, _rhs: Fe25519) -> Fe25519 {
        // add
        let z0 = self.x0 as u128 + _rhs.x0 as u128;
        let t0 = z0 as u64;
        let z1 = self.x1 as u128 + _rhs.x1 as u128 + (z0 >> 64);
        let t1 = z1 as u64;
        let z2 = self.x2 as u128 + _rhs.x2 as u128 + (z1 >> 64);
        let t2 = z2 as u64;
        let z3 = self.x3 as u128 + _rhs.x3 as u128 + (z2 >> 64);
        let t3 = z3 as u64;

        // reduce
        let z4 = t0 as u128 + (z3 >> 63) * 19;
        let x0 = z4 as u64;
        let z5 = t1 as u128 + (z4 >> 64);
        let x1 = z5 as u64;
        let z6 = t2 as u128 + (z5 >> 64);
        let x2 = z6 as u64;
        let z7 = t3 as u128 + (z6 >> 64);
        let x3 = (z7 as u64) & ((1 << 63 as u64) - 1);

        // this could still be > 2*255-19; need to add 19; and if it rolls over return that result, otherwise return original

        // add 19
        let a0 = x0 as u128 + 19;
        let a1 = (a0 >> 64) + x1 as u128;
        let a2 = (a1 >> 64) + x2 as u128;
        let a3 = (a2 >> 64) + x3 as u128;

        // if it rolled over, return the rollover
        if (a3 >> 63) == 1 {
            Fe25519 {
                x3: (a3 as u64) & 0x7FFFFFFFFFFFFFFF,
                x2: a2 as u64,
                x1: a1 as u64,
                x0: a0 as u64,
            }
        } else {
            Fe25519 { x3, x2, x1, x0 }
        }
    }
}

impl ops::Mul<Fe25519> for Fe25519 {
    type Output = (Fe25519, Fe25519);
    fn mul(self: Fe25519, _rhs: Fe25519) -> (Fe25519, Fe25519) {
        // Algorithm 2.9 from p31 of Guide to Elliptic Curve Cryptography

        let z0 = self.x0 as u128 * _rhs.x0 as u128;
        let mut x0 = z0 as u64;
        let z1 = self.x0 as u128 * _rhs.x1 as u128 + (z0 >> 64);
        let t0 = z1 as u64;
        let z2 = self.x0 as u128 * _rhs.x2 as u128 + (z1 >> 64);
        let t1 = z2 as u64;
        let z3 = self.x0 as u128 * _rhs.x3 as u128 + (z2 >> 64);
        let t2 = z3 as u64;
        let t3 = (z3 >> 64) as u64;

        let z4 = self.x1 as u128 * _rhs.x0 as u128 + t0 as u128;
        let mut x1 = z4 as u64;
        let z5 = self.x1 as u128 * _rhs.x1 as u128 + (z4 >> 64) + t1 as u128;
        let t4 = z5 as u64;
        let z6 = self.x1 as u128 * _rhs.x2 as u128 + (z5 >> 64) + t2 as u128;
        let t5 = z6 as u64;
        let z7 = self.x1 as u128 * _rhs.x3 as u128 + (z6 >> 64) + t3 as u128;
        let t6 = z7 as u64;
        let t7 = (z7 >> 64) as u64;

        let z8 = self.x2 as u128 * _rhs.x0 as u128 + t4 as u128;
        let mut x2 = z8 as u64;
        let z9 = self.x2 as u128 * _rhs.x1 as u128 + (z8 >> 64) + t5 as u128;
        let t8 = z9 as u64;
        let za = self.x2 as u128 * _rhs.x2 as u128 + (z9 >> 64) + t6 as u128;
        let t9 = za as u64;
        let zb = self.x2 as u128 * _rhs.x3 as u128 + (za >> 64) + t7 as u128;
        let ta = zb as u64;
        let tb = (zb >> 64) as u64;

        let zc = self.x3 as u128 * _rhs.x0 as u128 + t8 as u128;
        let mut x3 = zc as u64;
        let zd = self.x3 as u128 * _rhs.x1 as u128 + (zc >> 64) + t9 as u128;
        let x4 = zd as u64;
        let ze = self.x3 as u128 * _rhs.x2 as u128 + (zd >> 64) + ta as u128;
        let x5 = ze as u64;
        let zf = self.x3 as u128 * _rhs.x3 as u128 + (ze >> 64) + tb as u128;
        let x6 = zf as u64;
        let x7 = (zf >> 64) as u64;

        let zz0 = x0 as u128 + (x4 as u128 * 38);
        x0 = zz0 as u64;
        let zz1 = x1 as u128 + (x5 as u128 * 38) + (zz0 >> 64);
        x1 = zz1 as u64;
        let zz2 = x2 as u128 + (x6 as u128 * 38) + (zz1 >> 64);
        x2 = zz2 as u64;
        let zz3 = x3 as u128 + (x7 as u128 * 38) + (zz2 >> 64);
        x3 = zz3 as u64;

        // Orig
        //        let zz0 = x0 as u128 + ((x3 >> 63) as u128 | (x4 << 1) as u128) * 19;
        //        x0 = zz0 as u64;
        //        let zz1 = x1 as u128 + ((x4 >> 63) as u128 | (x5 << 1) as u128) * 19 + (zz0 >> 64);
        //        x1 = zz1 as u64;
        //        let zz2 = x2 as u128 + ((x5 >> 63) as u128 | (x6 << 1) as u128) * 19 + (zz1 >> 64);
        //        x2 = zz2 as u64;
        //        let zz3 = x3 as u128 + ((x6 >> 63) as u128 | (x7 << 1) as u128) * 19 + (zz2 >> 64);
        //        x3 = zz3 as u64;

        //let zzz0 = x0 as u128 + ((zz3 >> 63) as u128 * 19); // + ((x7 >> 63) as u128 * 19); // what happened to LSB of x7!!!!!
        //x0 = zzz0 as u64;
        // sometimes we return too large of a result (by 19!)
        // probably have to roll the carries through again?

        x3 = x3 & ((1 << 63 as u64) - 1);
        let lsb = Fe25519 {
            x3: x3,
            x2: x2,
            x1: x1,
            x0: x0,
        };
        let msb = Fe25519 {
            x3: 0,
            x2: 0,
            x1: 0,
            x0: 0,
        };
        (msb, lsb)
    }
}
