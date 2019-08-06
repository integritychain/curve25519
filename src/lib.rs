#![deny(clippy::all)]

// TODO:
//   1. Can some of the MSB mults could be folded into a reduce round?
//   2. Can mults be reordered by 128b sums, e.g. x0*x1 + x1*x0?
//   3. Can a Karatsuba approach be folded in?

#[macro_use]
extern crate lazy_static;
extern crate regex;

use std::ops;

mod support;

#[cfg(test)]
mod tests;

const UMASK63: u64 = (1 << 63) - 1; // 0x7FFF_FFFF_FFFF_FFFF

#[derive(PartialEq)]
pub struct Fe25519 {
    // 63+64+64+64=255; x3 is MSB
    x3: u64,
    x2: u64,
    x1: u64,
    x0: u64,
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl ops::Add<Fe25519> for Fe25519 {
    type Output = Fe25519;
    fn add(self, _rhs: Fe25519) -> Fe25519 {
        debug_assert!(  // Check the input is less than 2**255 - 19
                        (self.x3 != 0x7FFF_FFFF_FFFF_FFFF)
                            | (self.x2 != 0xFFFF_FFFF_FFFF_FFFF)
                            | (self.x1 != 0xFFFF_FFFF_FFFF_FFFF)
                            | (self.x0 < 0xFFFF_FFFF_FFFF_FFED)
        );
        debug_assert!(
            (_rhs.x3 != 0x7FFF_FFFF_FFFF_FFFF)
                | (_rhs.x2 != 0xFFFF_FFFF_FFFF_FFFF)
                | (_rhs.x1 != 0xFFFF_FFFF_FFFF_FFFF)
                | (_rhs.x0 < 0xFFFF_FFFF_FFFF_FFED)
        );
        // standard add with carry from one to the next; max sum will be 2**256 - 38
        let x0px0 = u128::from(self.x0) + u128::from(_rhs.x0);
        let x00p = x0px0 as u64;
        let x1px1 = u128::from(self.x1) + u128::from(_rhs.x1) + (x0px0 >> 64);
        let x11p = x1px1 as u64;
        let x2px2 = u128::from(self.x2) + u128::from(_rhs.x2) + (x1px1 >> 64);
        let x22p = x2px2 as u64;
        let x3px3 = u128::from(self.x3) + u128::from(_rhs.x3) + (x2px2 >> 64);
        let x33p = x3px3 as u64;

        // reduce with 2**255 = 19 (so depends upon MSB); max sum here is 2**255
        let x0p19 = u128::from(x00p) + (x3px3 >> 63) * 19;
        let x0 = x0p19 as u64;
        let x1p19 = u128::from(x11p) + (x0p19 >> 64);
        let x1 = x1p19 as u64;
        let x2p19 = u128::from(x22p) + (x1p19 >> 64);
        let x2 = x2p19 as u64;
        let x3p19 = u128::from(x33p) + (x2p19 >> 64);
        let x3 = (x3p19 as u64) & UMASK63;

        // sum may still be too large, so add 19 and check rollover
        let r0 = u128::from(x0) + 19;
        let r1 = (r0 >> 64) + u128::from(x1);
        let r2 = (r1 >> 64) + u128::from(x2);
        let r3 = (r2 >> 64) + u128::from(x3);
        let rollover = 0u64.overflowing_sub((r3 >> 63) as u64).0; // extend 1111... or 0000...

        // Based on rollover, choose original sum or 'incremented by 19' sum
        let result = Fe25519 {
            x3: UMASK63 & (!rollover & x3 | rollover & (r3 as u64)),
            x2: !rollover & x2 | rollover & (r2 as u64),
            x1: !rollover & x1 | rollover & (r1 as u64),
            x0: !rollover & x0 | rollover & (r0 as u64),
        };

        debug_assert!(
            (result.x3 != 0x7FFF_FFFF_FFFF_FFFF)
                | (result.x2 != 0xFFFF_FFFF_FFFF_FFFF)
                | (result.x1 != 0xFFFF_FFFF_FFFF_FFFF)
                | (result.x0 < 0xFFFF_FFFF_FFFF_FFED)
        );
        result
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl ops::Mul<Fe25519> for Fe25519 {
    type Output = Fe25519;
    fn mul(self: Fe25519, _rhs: Fe25519) -> Fe25519 {
        debug_assert!(
            (self.x3 != 0x7FFF_FFFF_FFFF_FFFF)
                | (self.x2 != 0xFFFF_FFFF_FFFF_FFFF)
                | (self.x1 != 0xFFFF_FFFF_FFFF_FFFF)
                | (self.x0 < 0xFFFF_FFFF_FFFF_FFED)
        );
        debug_assert!(
            (_rhs.x3 != 0x7FFF_FFFF_FFFF_FFFF)
                | (_rhs.x2 != 0xFFFF_FFFF_FFFF_FFFF)
                | (_rhs.x1 != 0xFFFF_FFFF_FFFF_FFFF)
                | (_rhs.x0 < 0xFFFF_FFFF_FFFF_FFED)
        );

        // for each self.X multiply and sum _rhs (4 'paragraphs')
        let x0mx0 = u128::from(self.x0) * u128::from(_rhs.x0);
        let t00 = x0mx0 as u64;
        let x0mx1 = u128::from(self.x0) * u128::from(_rhs.x1) + (x0mx0 >> 64);
        let t01 = x0mx1 as u64;
        let x0mx2 = u128::from(self.x0) * u128::from(_rhs.x2) + (x0mx1 >> 64);
        let t02 = x0mx2 as u64;
        let x0mx3 = u128::from(self.x0) * u128::from(_rhs.x3) + (x0mx2 >> 64);
        let t03 = x0mx3 as u64;
        let t04 = (x0mx3 >> 64) as u64;

        let x1mx0 = u128::from(self.x1) * u128::from(_rhs.x0) + u128::from(t01);
        let t10 = x1mx0 as u64;
        let x1mx1 = u128::from(self.x1) * u128::from(_rhs.x1) + (x1mx0 >> 64) + u128::from(t02);
        let t11 = x1mx1 as u64;
        let x1mx2 = u128::from(self.x1) * u128::from(_rhs.x2) + (x1mx1 >> 64) + u128::from(t03);
        let t12 = x1mx2 as u64;
        let x1m3 = u128::from(self.x1) * u128::from(_rhs.x3) + (x1mx2 >> 64) + u128::from(t04);
        let t13 = x1m3 as u64;
        let t14 = (x1m3 >> 64) as u64;

        let x2mx0 = u128::from(self.x2) * u128::from(_rhs.x0) + u128::from(t11);
        let t20 = x2mx0 as u64;
        let x2mx1 = u128::from(self.x2) * u128::from(_rhs.x1) + (x2mx0 >> 64) + u128::from(t12);
        let t21 = x2mx1 as u64;
        let x2mx2 = u128::from(self.x2) * u128::from(_rhs.x2) + (x2mx1 >> 64) + u128::from(t13);
        let t22 = x2mx2 as u64;
        let x2mx3 = u128::from(self.x2) * u128::from(_rhs.x3) + (x2mx2 >> 64) + u128::from(t14);
        let t23 = x2mx3 as u64;
        let t24 = (x2mx3 >> 64) as u64;

        let x3mx0 = u128::from(self.x3) * u128::from(_rhs.x0) + u128::from(t21);
        let t30 = x3mx0 as u64;
        let x3mx1 = u128::from(self.x3) * u128::from(_rhs.x1) + (x3mx0 >> 64) + u128::from(t22);
        let t31 = x3mx1 as u64;
        let x3mx2 = u128::from(self.x3) * u128::from(_rhs.x2) + (x3mx1 >> 64) + u128::from(t23);
        let t32 = x3mx2 as u64;
        let x3mx3 = u128::from(self.x3) * u128::from(_rhs.x3) + (x3mx2 >> 64) + u128::from(t24);
        let t33 = x3mx3 as u64;
        let t34 = (x3mx3 >> 64) as u64;

        // Reduce t00..t30 by taking 2**256=38
        let r00 = u128::from(t00) + (u128::from(t31) * 38);
        let s00 = r00 as u64;
        let r10 = u128::from(t10) + (u128::from(t32) * 38) + (r00 >> 64);
        let s10 = r10 as u64;
        let r20 = u128::from(t20) + (u128::from(t33) * 38) + (r10 >> 64);
        let s20 = r20 as u64;
        let r30 = u128::from(t30) + (u128::from(t34) * 38) + (r20 >> 64);
        let s30 = r30 as u64;

        // If MSB is set add 19
        let w00 = u128::from(s00) + (r30 >> 63) as u128 * 19;
        let x0 = w00 as u64;
        let w01 = u128::from(s10) + (w00 >> 64);
        let x1 = w01 as u64;
        let w02 = u128::from(s20) + (w01 >> 64);
        let x2 = w02 as u64;
        let w03 = u128::from(s30) + (w02 >> 64);
        let mut x3 = w03 as u64;
        x3 &= UMASK63;

        // We could still be above 2**255 - 19; increment and see if we rollover
        let i0 = u128::from(x0) + 19;
        let i1 = (i0 >> 64) + u128::from(x1);
        let i2 = (i1 >> 64) + u128::from(x2);
        let i3 = (i2 >> 64) + u128::from(x3);
        let rollover = 0u64.overflowing_sub((i3 >> 63) as u64).0; // extend 1111... or 0000...

        // If no rollover take the original value, otherwise take the 'increment by 19'
        let result = Fe25519 {
            x3: UMASK63 & (!rollover & x3 | rollover & (i3 as u64)),
            x2: !rollover & x2 | rollover & (i2 as u64),
            x1: !rollover & x1 | rollover & (i1 as u64),
            x0: !rollover & x0 | rollover & (i0 as u64),
        };

        debug_assert!(
            (result.x3 != 0x7FFF_FFFF_FFFF_FFFF)
                | (result.x2 != 0xFFFF_FFFF_FFFF_FFFF)
                | (result.x1 != 0xFFFF_FFFF_FFFF_FFFF)
                | (result.x0 < 0xFFFF_FFFF_FFFF_FFED)
        );
        result
    }
}
