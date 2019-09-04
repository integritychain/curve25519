#![deny(clippy::all)]

// TODO:
//   1. Double check random number generator (should be fine)
//   2. Implement cswap and other oddities
//   3. General clean up; clippy; lint messages
//   4. Implement scalar montgomery via RFC 7748 and/or "Montgomery's original paper"

#[macro_use]
extern crate lazy_static;
extern crate regex;

use std::ops;

use crate::support::check_size;

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

fn fe_add(dest: &mut Fe25519, src1: &Fe25519, src2: &Fe25519) {
    // Check the inputs are less than 2**255 - 19
    debug_assert!(check_size(src1));
    debug_assert!(check_size(src2));

    // Add while propagating carry; Max sum will be < 2**256 - 38
    let x0_add_x0 = u128::from(src1.x0) + u128::from(src2.x0);
    let sum_x0 = x0_add_x0 as u64;
    let x1_add_x1 = u128::from(src1.x1) + u128::from(src2.x1) + (x0_add_x0 >> 64);
    let sum_x1 = x1_add_x1 as u64;
    let x2_add_x2 = u128::from(src1.x2) + u128::from(src2.x2) + (x1_add_x1 >> 64);
    let sum_x2 = x2_add_x2 as u64;
    let x3_add_x3 = u128::from(src1.x3) + u128::from(src2.x3) + (x2_add_x2 >> 64);
    let sum_x3 = x3_add_x3 as u64;

    // Reduce with 2**255 = 19 mod p (so depends upon MSB)
    // Max sum is (2**255 - 20) + (2**255 - 20) = 2**256 - 40
    let x0_inc_19 = u128::from(sum_x0) + (x3_add_x3 >> 63) * 19;
    let inc_x0 = x0_inc_19 as u64;
    let x1_inc_19 = u128::from(sum_x1) + (x0_inc_19 >> 64);
    let inc_x1 = x1_inc_19 as u64;
    let x2_inc_19 = u128::from(sum_x2) + (x1_inc_19 >> 64);
    let inc_x2 = x2_inc_19 as u64;
    let x3_inc_19 = u128::from(sum_x3) + (x2_inc_19 >> 64);
    let inc_x3 = (x3_inc_19 as u64) & UMASK63;

    // Rollover logic driven by the case (2**255 - 19) + (small, e.g. 4) --> CAN WE OPTIMIZE?
    // Need run-time check; point mult may never encounter this
    let x0_roll_19 = u128::from(inc_x0) + 19;
    let roll_x0 = x0_roll_19 as u64;
    let x1_roll_19 = (x0_roll_19 >> 64) + u128::from(inc_x1);
    let roll_x1 = x1_roll_19 as u64;
    let x2_roll_19 = (x1_roll_19 >> 64) + u128::from(inc_x2);
    let roll_x2 = x2_roll_19 as u64;
    let x3_roll_19 = (x2_roll_19 >> 64) + u128::from(inc_x3);
    let roll_x3 = x3_roll_19 as u64;
    let rollover = 0u64.overflowing_sub((x3_roll_19 >> 63) as u64).0; // extend 1111... or 0000...

    // Based on rollover, choose original sum or 'incremented by 19' sum
    dest.x3 = UMASK63 & (!rollover & inc_x3 | rollover & roll_x3);
    dest.x2 = !rollover & inc_x2 | rollover & roll_x2;
    dest.x1 = !rollover & inc_x1 | rollover & roll_x1;
    dest.x0 = !rollover & inc_x0 | rollover & roll_x0;

    // Check the output is less than 2**255 - 19
    debug_assert!(check_size(dest));
}

// For a - b, if b > a then it wraps around 2*255 and we need to adjust by -19
fn fe_sub(dest: &mut Fe25519, src1: &Fe25519, src2: &Fe25519) {
    debug_assert!(check_size(&src1));
    debug_assert!(check_size(&src2));

    let x0_sub_x0 = u128::from(src1.x0).overflowing_sub(u128::from(src2.x0)).0; // .0 is result
    let sub_x0 = x0_sub_x0 as u64;
    let x1_sub_x1 = u128::from(src1.x1)
        .overflowing_sub(u128::from(src2.x1))
        .0
        .overflowing_sub(x0_sub_x0 >> 127)
        .0;
    let sub_x1 = x1_sub_x1 as u64;
    let x2_sub_x2 = u128::from(src1.x2)
        .overflowing_sub(u128::from(src2.x2))
        .0
        .overflowing_sub(x1_sub_x1 >> 127)
        .0;
    let sub_x2 = x2_sub_x2 as u64;
    let x3_sub_x3 = u128::from(src1.x3)
        .overflowing_sub(u128::from(src2.x3))
        .0
        .overflowing_sub(x2_sub_x2 >> 127)
        .0;
    let sub_x3 = x3_sub_x3 as u64;

    // If carry set, we decrement another 19
    let x0_dec_19 = u128::from(sub_x0)
        .overflowing_sub(u128::from(sub_x3 >> 63) * 19)
        .0;
    dest.x0 = x0_dec_19 as u64;
    let x1_dec_19 = (x0_dec_19 >> 64) + u128::from(sub_x1);
    dest.x1 = x1_dec_19 as u64;
    let x2_dec_19 = (x1_dec_19 >> 64) + u128::from(sub_x2);
    dest.x2 = x2_dec_19 as u64;
    let x3_dec_19 = (x2_dec_19 >> 64) + u128::from(sub_x3);
    dest.x3 = (x3_dec_19 as u64) & UMASK63;

    debug_assert!(check_size(&dest));
}

fn fe_mul(dest: &mut Fe25519, src1: &Fe25519, src2: &Fe25519) {
    debug_assert!(check_size(&src1));
    debug_assert!(check_size(&src2));

    // for each src1.X multiply and sum src2 (4 'paragraphs')
    let x0_mul_x0 = u128::from(src1.x0) * u128::from(src2.x0);
    let mul_x00 = x0_mul_x0 as u64;
    let x0_mul_x1 = u128::from(src1.x0) * u128::from(src2.x1) + (x0_mul_x0 >> 64);
    let mul_x01 = x0_mul_x1 as u64;
    let x0_mul_x2 = u128::from(src1.x0) * u128::from(src2.x2) + (x0_mul_x1 >> 64);
    let mul_x02 = x0_mul_x2 as u64;
    let x0_mul_x3 = u128::from(src1.x0) * u128::from(src2.x3) + (x0_mul_x2 >> 64);
    let mul_x03 = x0_mul_x3 as u64;
    let mul_x04 = (x0_mul_x3 >> 64) as u64;

    let x1_mul_x0 = u128::from(src1.x1) * u128::from(src2.x0) + u128::from(mul_x01);
    let mul_x10 = x1_mul_x0 as u64;
    let x1_mul_x1 =
        u128::from(src1.x1) * u128::from(src2.x1) + (x1_mul_x0 >> 64) + u128::from(mul_x02);
    let mul_x11 = x1_mul_x1 as u64;
    let x1_mul_x2 =
        u128::from(src1.x1) * u128::from(src2.x2) + (x1_mul_x1 >> 64) + u128::from(mul_x03);
    let mu_x12 = x1_mul_x2 as u64;
    let x1_mul_x3 =
        u128::from(src1.x1) * u128::from(src2.x3) + (x1_mul_x2 >> 64) + u128::from(mul_x04);
    let mul_x13 = x1_mul_x3 as u64;
    let mul_x14 = (x1_mul_x3 >> 64) as u64;

    let x2_mul_x0 = u128::from(src1.x2) * u128::from(src2.x0) + u128::from(mul_x11);
    let mul_x20 = x2_mul_x0 as u64;
    let x2_mul_x1 =
        u128::from(src1.x2) * u128::from(src2.x1) + (x2_mul_x0 >> 64) + u128::from(mu_x12);
    let mul_x21 = x2_mul_x1 as u64;
    let x2_mul_x2 =
        u128::from(src1.x2) * u128::from(src2.x2) + (x2_mul_x1 >> 64) + u128::from(mul_x13);
    let mul_x22 = x2_mul_x2 as u64;
    let x2_mul_x3 =
        u128::from(src1.x2) * u128::from(src2.x3) + (x2_mul_x2 >> 64) + u128::from(mul_x14);
    let mul_x23 = x2_mul_x3 as u64;
    let mul_x24 = (x2_mul_x3 >> 64) as u64;

    let x3_mul_x0 = u128::from(src1.x3) * u128::from(src2.x0) + u128::from(mul_x21);
    let mul_x30 = x3_mul_x0 as u64;
    let x3_mul_x1 =
        u128::from(src1.x3) * u128::from(src2.x1) + (x3_mul_x0 >> 64) + u128::from(mul_x22);
    let mul_x31 = x3_mul_x1 as u64;
    let x3_mul_x2 =
        u128::from(src1.x3) * u128::from(src2.x2) + (x3_mul_x1 >> 64) + u128::from(mul_x23);
    let mul_x32 = x3_mul_x2 as u64;
    let x3_mul_x3 =
        u128::from(src1.x3) * u128::from(src2.x3) + (x3_mul_x2 >> 64) + u128::from(mul_x24);
    let mul_x33 = x3_mul_x3 as u64;
    let mul_x34 = (x3_mul_x3 >> 64) as u64;

    // Reduce t00..t30 by taking 2**256=38
    let x00_red_38 = u128::from(mul_x00) + (u128::from(mul_x31) * 38);
    let red_x00 = x00_red_38 as u64;
    let x10_red_38 = u128::from(mul_x10) + (u128::from(mul_x32) * 38) + (x00_red_38 >> 64);
    let red_x10 = x10_red_38 as u64;
    let x20_red_38 = u128::from(mul_x20) + (u128::from(mul_x33) * 38) + (x10_red_38 >> 64);
    let red_x20 = x20_red_38 as u64;
    let x30_red_38 = u128::from(mul_x30) + (u128::from(mul_x34) * 38) + (x20_red_38 >> 64);
    let red_x30 = x30_red_38 as u64;

    // If MSB is set add 19
    let x00_inc_19 = u128::from(red_x00) + (x30_red_38 >> 63) as u128 * 19;
    let inc_x00 = x00_inc_19 as u64;
    let x10_inc_19 = u128::from(red_x10) + (x00_inc_19 >> 64);
    let inc_x10 = x10_inc_19 as u64;
    let x20_inc_19 = u128::from(red_x20) + (x10_inc_19 >> 64);
    let inc_x20 = x20_inc_19 as u64;
    let x30_inc_19 = u128::from(red_x30) + (x20_inc_19 >> 64);
    let inc_x30 = x30_inc_19 as u64 & UMASK63;

    // We could still be above 2**255 - 19; increment and see if we rollover
    let x00_roll_19 = u128::from(inc_x00) + 19;
    let x10_roll_19 = (x00_roll_19 >> 64) + u128::from(inc_x10);
    let x20_roll_19 = (x10_roll_19 >> 64) + u128::from(inc_x20);
    let x30_roll_19 = (x20_roll_19 >> 64) + u128::from(inc_x30);
    let rollover = 0u64.overflowing_sub((x30_roll_19 >> 63) as u64).0; // extend 1111... or 0000...

    // If no rollover take the original value, otherwise take the 'roll by 19'
    dest.x3 = UMASK63 & (!rollover & inc_x30 | rollover & (x30_roll_19 as u64));
    dest.x2 = !rollover & inc_x20 | rollover & (x20_roll_19 as u64);
    dest.x1 = !rollover & inc_x10 | rollover & (x10_roll_19 as u64);
    dest.x0 = !rollover & inc_x00 | rollover & (x00_roll_19 as u64);

    debug_assert!(check_size(&dest));
}

fn fe_mul_121665(dest: &mut Fe25519) {
    debug_assert!(check_size(&dest));

    // multiply by 121665 and propagate carries
    let x0_mul_12 = u128::from(dest.x0) * 121_665;
    let mul_x0 = x0_mul_12 as u64;
    let x1_mul_12 = u128::from(dest.x1) * 121_665 + (x0_mul_12 >> 64);
    let mul_x1 = x1_mul_12 as u64;
    let x2_mul_12 = u128::from(dest.x2) * 121_665 + (x1_mul_12 >> 64);
    let mul_x2 = x2_mul_12 as u64;
    let x3_mul_12 = u128::from(dest.x3) * 121_665 + (x2_mul_12 >> 64);
    let mul_x3 = x3_mul_12 as u64;
    //let t04 = (x0mx3 >> 63) as u64;

    // reduce 2**255 = 19
    let x0_inc_19 = u128::from(mul_x0) + 19 * (x3_mul_12 >> 63);
    let inc_x0 = x0_inc_19 as u64;
    let x1_inc_19 = u128::from(mul_x1) + (x0_inc_19 >> 64);
    let inc_x1 = x1_inc_19 as u64;
    let x2_inc_19 = u128::from(mul_x2) + (x1_inc_19 >> 64);
    let inc_x2 = x2_inc_19 as u64;
    let x3_inc_19 = u128::from(mul_x3) + (x2_inc_19 >> 64);
    let inc_x3 = x3_inc_19 as u64;

    // Seems like we need a rollover check here ?!?!?

    dest.x3 = UMASK63 & inc_x3;
    dest.x2 = inc_x2;
    dest.x1 = inc_x1;
    dest.x0 = inc_x0;

    debug_assert!(check_size(&dest));
}
