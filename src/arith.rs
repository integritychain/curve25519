#![deny(clippy::all)]


//#[macro_use]
//extern crate lazy_static;

use std::str::FromStr;
use test::test_main;

use crate::support::check_size;

//mod support;

//#[cfg(test)]
//mod tests;

const UMASK63: u64 = (1 << 63) - 1; // 0x7FFF_FFFF_FFFF_FFFF

#[derive(PartialEq, Clone, Copy, Default)]
pub struct Fe25519 {
    // 63+64+64+64=255; x3 is MSB
    pub x3: u64,
    pub x2: u64,
    pub x1: u64,
    pub x0: u64,
}

// Per section 5 for RFC7748 - BUT DON'T SEE REDUCTION!
//pub fn get_u(src: &str) -> Fe25519 {
//    let new_u = format!("0x{}", src);
//    let mut temp = Fe25519::from_str(&new_u).unwrap();
//    temp.x3 = temp.x3 & UMASK63;
//    // Rollover logic driven by the case (2**255 - 19) + (small, e.g. 4) --> CAN WE OPTIMIZE?
//    // Need run-time check; point mult may never encounter this
//    let x0_roll_19 = u128::from(temp.x0) + 19;
//    let roll_x0 = x0_roll_19 as u64;
//    let x1_roll_19 = (x0_roll_19 >> 64) + u128::from(temp.x1);
//    let roll_x1 = x1_roll_19 as u64;
//    let x2_roll_19 = (x1_roll_19 >> 64) + u128::from(temp.x2);
//    let roll_x2 = x2_roll_19 as u64;
//    let x3_roll_19 = (x2_roll_19 >> 64) + u128::from(temp.x3);
//    let roll_x3 = x3_roll_19 as u64;
//    let mut rollover = 0u64;
//    if (roll_x3 >> 63) == 1 {
//        rollover = 0xFFFF_FFFF_FFFF_FFFF;
//        println!("rollover from u");
//    }
//    //let rollover = 0u64.overflowing_sub((x3_roll_19 >> 63) as u64).0; // extend 1111... or 0000...
//
//    // Based on rollover, choose original sum or 'incremented by 19' sum
//    let dest = Fe25519 {
//        x3: UMASK63 & (!rollover & temp.x3 | rollover & roll_x3),
//        x2: !rollover & temp.x2 | rollover & roll_x2,
//        x1: !rollover & temp.x1 | rollover & roll_x1,
//        x0: !rollover & temp.x0 | rollover & roll_x0,
//    };
//    println!("Dest U : {}", dest);
//    dest
//}

pub fn get_u(src: &str) -> Fe25519 {
    let new_u = format!("{}", src);
    let temp1 = Fe25519::from_str(&new_u).unwrap();
    let temp2 = Fe25519 { x3: u64::from_be(temp1.x0), x2: u64::from_be(temp1.x1), x1: u64::from_be(temp1.x2), x0: u64::from_be(temp1.x3) };

    //temp2.x3 = temp2.x3 & UMASK63;
    // Rollover logic driven by the case (2**255 - 19) + (small, e.g. 4) --> CAN WE OPTIMIZE?
    // Need run-time check; point mult may never encounter this
    let x0_roll_19 = u128::from(temp2.x0) + 19;
    let roll_x0 = x0_roll_19 as u64;
    let x1_roll_19 = (x0_roll_19 >> 64) + u128::from(temp2.x1);
    let roll_x1 = x1_roll_19 as u64;
    let x2_roll_19 = (x1_roll_19 >> 64) + u128::from(temp2.x2);
    let roll_x2 = x2_roll_19 as u64;
    let x3_roll_19 = (x2_roll_19 >> 64) + u128::from(temp2.x3);
    let roll_x3 = x3_roll_19 as u64;
    //let mut rollover = 0u64;
//    if (roll_x3 >> 63) == 1 {
//        rollover = 0xFFFF_FFFF_FFFF_FFFF;
//        println!("rollover from u");
//    }
    let rollover = 0u64.overflowing_sub((x3_roll_19 >> 63) as u64).0; // extend 1111... or 0000...

    // Based on rollover, choose original sum or 'incremented by 19' sum
    let dest = Fe25519 {
        x3: UMASK63 & (!rollover & temp2.x3 | rollover & roll_x3),
        x2: !rollover & temp2.x2 | rollover & roll_x2,
        x1: !rollover & temp2.x1 | rollover & roll_x1,
        x0: !rollover & temp2.x0 | rollover & roll_x0,
    };
    //println!("Dest U : {}", dest);
    dest
}


//pub fn get_k(src: &str) -> Fe25519 {
//    let new_k = format!("0x{}", src);
//    let mut temp = Fe25519::from_str(&new_k).unwrap();
//    temp.x0 = temp.x0 & 0xFFFF_FFFF_FFFF_FFF8;
//    temp.x3 = temp.x3 & 0x7FFF_FFFF_FFFF_FFFF;
//    //temp.x3 = temp.x3 | 0x4000_0000_0000_0000;
//    println!("K is {}", temp);
//    temp
//}

pub fn get_k(src: &str) -> Fe25519 {
    let new_k = format!("{}", src);
    let temp1 = Fe25519::from_str(&new_k).unwrap();
    let mut temp2 = Fe25519 { x3: u64::from_be(temp1.x0), x2: u64::from_be(temp1.x1), x1: u64::from_be(temp1.x2), x0: u64::from_be(temp1.x3) };
    temp2.x0 = temp2.x0 & 0xFFFF_FFFF_FFFF_FFF8;
    temp2.x3 = temp2.x3 & 0x7FFF_FFFF_FFFF_FFFF;
    temp2.x3 = temp2.x3 | 0x4000_0000_0000_0000;
    //println!("K is {}", temp2);
    debug_assert!(check_size(&temp2));
    temp2
}

pub(crate) fn fe_add(dest: &mut Fe25519, src1: &Fe25519, src2: &Fe25519) {
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
pub(crate) fn fe_sub(dest: &mut Fe25519, src1: &Fe25519, src2: &Fe25519) {
    debug_assert!(check_size(&src1));
    debug_assert!(check_size(&src2));

    let x0_sub_x0 = u128::from(src1.x0).overflowing_sub(u128::from(src2.x0)).0; // .0 is result
    let sub_x0 = x0_sub_x0 as u64;
    let x1_sub_x1 = u128::from(src1.x1).overflowing_sub(u128::from(src2.x1)).0.overflowing_sub(x0_sub_x0 >> 127).0;
    let sub_x1 = x1_sub_x1 as u64;
    let x2_sub_x2 = u128::from(src1.x2).overflowing_sub(u128::from(src2.x2)).0.overflowing_sub(x1_sub_x1 >> 127).0;
    let sub_x2 = x2_sub_x2 as u64;
    let x3_sub_x3 = u128::from(src1.x3).overflowing_sub(u128::from(src2.x3)).0.overflowing_sub(x2_sub_x2 >> 127).0;
    let sub_x3 = x3_sub_x3 as u64;

    // If carry set, we decrement another 19
    let x0_dec_19 = u128::from(sub_x0).overflowing_sub(u128::from(sub_x3 >> 63) * 19).0;
    dest.x0 = x0_dec_19 as u64;
    let x1_dec_19 = (x0_dec_19 >> 64) + u128::from(sub_x1);
    dest.x1 = x1_dec_19 as u64;
    let x2_dec_19 = (x1_dec_19 >> 64) + u128::from(sub_x2);
    dest.x2 = x2_dec_19 as u64;
    let x3_dec_19 = (x2_dec_19 >> 64) + u128::from(sub_x3);
    dest.x3 = (x3_dec_19 as u64) & UMASK63;

    debug_assert!(check_size(&dest));
}

pub fn fe_mul(dest: &mut Fe25519, src1: &Fe25519, src2: &Fe25519) {
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
    let x1_mul_x1 = u128::from(src1.x1) * u128::from(src2.x1) + (x1_mul_x0 >> 64) + u128::from(mul_x02);
    let mul_x11 = x1_mul_x1 as u64;
    let x1_mul_x2 = u128::from(src1.x1) * u128::from(src2.x2) + (x1_mul_x1 >> 64) + u128::from(mul_x03);
    let mu_x12 = x1_mul_x2 as u64;
    let x1_mul_x3 = u128::from(src1.x1) * u128::from(src2.x3) + (x1_mul_x2 >> 64) + u128::from(mul_x04);
    let mul_x13 = x1_mul_x3 as u64;
    let mul_x14 = (x1_mul_x3 >> 64) as u64;

    let x2_mul_x0 = u128::from(src1.x2) * u128::from(src2.x0) + u128::from(mul_x11);
    let mul_x20 = x2_mul_x0 as u64;
    let x2_mul_x1 = u128::from(src1.x2) * u128::from(src2.x1) + (x2_mul_x0 >> 64) + u128::from(mu_x12);
    let mul_x21 = x2_mul_x1 as u64;
    let x2_mul_x2 = u128::from(src1.x2) * u128::from(src2.x2) + (x2_mul_x1 >> 64) + u128::from(mul_x13);
    let mul_x22 = x2_mul_x2 as u64;
    let x2_mul_x3 = u128::from(src1.x2) * u128::from(src2.x3) + (x2_mul_x2 >> 64) + u128::from(mul_x14);
    let mul_x23 = x2_mul_x3 as u64;
    let mul_x24 = (x2_mul_x3 >> 64) as u64;

    let x3_mul_x0 = u128::from(src1.x3) * u128::from(src2.x0) + u128::from(mul_x21);
    let mul_x30 = x3_mul_x0 as u64;
    let x3_mul_x1 = u128::from(src1.x3) * u128::from(src2.x1) + (x3_mul_x0 >> 64) + u128::from(mul_x22);
    let mul_x31 = x3_mul_x1 as u64;
    let x3_mul_x2 = u128::from(src1.x3) * u128::from(src2.x2) + (x3_mul_x1 >> 64) + u128::from(mul_x23);
    let mul_x32 = x3_mul_x2 as u64;
    let x3_mul_x3 = u128::from(src1.x3) * u128::from(src2.x3) + (x3_mul_x2 >> 64) + u128::from(mul_x24);
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

#[inline]
pub(crate) fn fe_square(dest: &mut Fe25519, src: &Fe25519) {
    debug_assert!(check_size(&dest));

    let x0_mul_x0 = u128::from(src.x0) * u128::from(src.x0);
    let x0_mul_x1 = u128::from(src.x0) * u128::from(src.x1);
    let x0_mul_x2 = u128::from(src.x0) * u128::from(src.x2);
    let x0_mul_x3 = u128::from(src.x0) * u128::from(src.x3);
    let x1_mul_x1 = u128::from(src.x1) * u128::from(src.x1);
    let x1_mul_x2 = u128::from(src.x1) * u128::from(src.x2);
    let x1_mul_x3 = u128::from(src.x1) * u128::from(src.x3);
    let x2_mul_x2 = u128::from(src.x2) * u128::from(src.x2);
    let x2_mul_x3 = u128::from(src.x2) * u128::from(src.x3);
    let x3_mul_x3 = u128::from(src.x3) * u128::from(src.x3);

    let scan_1 = (x0_mul_x0 >> 64) + 2 * u128::from(x0_mul_x1 as u64);
    let scan_2 = 2 * (x0_mul_x1 >> 64) + 2 * u128::from(x0_mul_x2 as u64) + u128::from(x1_mul_x1 as u64) + (scan_1 >> 64);
    let scan_3 = 2 * (x0_mul_x2 >> 64) + (x1_mul_x1 >> 64) + 2 * u128::from(x0_mul_x3 as u64) + 2 * u128::from(x1_mul_x2 as u64) + (scan_2 >> 64);
    let scan_4 = 2 * (x0_mul_x3 >> 64) + 2 * (x1_mul_x2 >> 64) + u128::from(x2_mul_x2 as u64) + 2 * u128::from(x1_mul_x3 as u64) + (scan_3 >> 64);
    let scan_5 = 2 * (x1_mul_x3 >> 64) + (x2_mul_x2 >> 64) + 2 * u128::from(x2_mul_x3 as u64) + (scan_4 >> 64);
    let scan_6 = 2 * (x2_mul_x3 >> 64) + u128::from(x3_mul_x3 as u64) + (scan_5 >> 64);

    let mul_0 = x0_mul_x0 as u64;
    let mul_1 = scan_1 as u64;
    let mul_2 = scan_2 as u64;
    let mul_3 = scan_3 as u64;
    let mul_4 = scan_4 as u64;
    let mul_5 = scan_5 as u64;
    let mul_6 = scan_6 as u64;
    let mul_7 = (x3_mul_x3 >> 64) + (scan_6 >> 64);

    // Reduce t00..t30 by taking 2**256=38
    let x00_red_38 = u128::from(mul_0) + (u128::from(mul_4) * 38);
    let red_x00 = x00_red_38 as u64;
    let x10_red_38 = u128::from(mul_1) + (u128::from(mul_5) * 38) + (x00_red_38 >> 64);
    let red_x10 = x10_red_38 as u64;
    let x20_red_38 = u128::from(mul_2) + (u128::from(mul_6) * 38) + (x10_red_38 >> 64);
    let red_x20 = x20_red_38 as u64;
    let x30_red_38 = u128::from(mul_3) + (u128::from(mul_7) * 38) + (x20_red_38 >> 64);
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

pub(crate) fn fe_mul_121665(dest: &mut Fe25519, src: &Fe25519) {
    debug_assert!(check_size(&dest));

    // multiply by 121665 and propagate carries
    let x0_mul_12 = u128::from(src.x0) * 121_665;
    let mul_x0 = x0_mul_12 as u64;
    let x1_mul_12 = u128::from(src.x1) * 121_665 + (x0_mul_12 >> 64);
    let mul_x1 = x1_mul_12 as u64;
    let x2_mul_12 = u128::from(src.x2) * 121_665 + (x1_mul_12 >> 64);
    let mul_x2 = x2_mul_12 as u64;
    let x3_mul_12 = u128::from(src.x3) * 121_665 + (x2_mul_12 >> 64);
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

    // Seems like we need a rollover check here too ?!?!?

    dest.x3 = UMASK63 & inc_x3;
    dest.x2 = inc_x2;
    dest.x1 = inc_x1;
    dest.x0 = inc_x0;

    debug_assert!(check_size(&dest));
}

fn fe_cswap(swap: &Fe25519, x_2: &mut Fe25519, x_3: &mut Fe25519) {
    let dummy = Fe25519 {
        x3: swap.x3 & (x_2.x3 ^ x_3.x3),
        x2: swap.x2 & (x_2.x2 ^ x_3.x2),
        x1: swap.x1 & (x_2.x1 ^ x_3.x1),
        x0: swap.x0 & (x_2.x0 ^ x_3.x0),
    };
    x_2.x3 ^= dummy.x3;
    x_2.x2 ^= dummy.x2;
    x_2.x1 ^= dummy.x1;
    x_2.x0 ^= dummy.x0;
    x_3.x3 ^= dummy.x3;
    x_3.x2 ^= dummy.x2;
    x_3.x1 ^= dummy.x1;
    x_3.x0 ^= dummy.x0;
}

// To be optimized away...
fn k_t(k: &Fe25519, t: i16) -> Fe25519 {
    //= (k >> t) & 1
    let x0: u64;//= 0;
    // match against range is experimental, so use if-else-etc
    if t <= 63 {
        x0 = k.x0 >> t as u64;
    } else if (t >= 64) & (t <= 127) {
        x0 = k.x1 >> (t as u64 - 64);
    } else if (t >= 128) & (t <= 191) {
        x0 = k.x2 >> (t as u64 - 128);
    } else {
        x0 = k.x3 >> (t as u64 - 192);
    }

    if (x0 & 01) != 0 {
        //println!("Swap!");
        Fe25519 { x3: 0xFFFFFFFFFFFFFFFF, x2: 0xFFFFFFFFFFFFFFFF, x1: 0xFFFFFFFFFFFFFFFF, x0: 0xFFFFFFFFFFFFFFFF }
    } else {
        Fe25519 { x3: 0, x2: 0, x1: 0, x0: 0 }
    }
}

pub fn fe_invert(result: &mut Fe25519, z: &Fe25519) {
    let mut t0 = Fe25519::default();
    fe_square(&mut t0, &z);

    /* t1 = t0 ** (2 ** 2) = z ** 8 */
    let mut t1 = Fe25519::default();
    fe_square(&mut t1, &t0);
    let xx0 = t1;
    fe_square(&mut t1, &xx0);

    /* t1 = z * t1 = z ** 9 */
    let xx1 = t1;
    fe_mul(&mut t1, &z, &xx1);
    /* t0 = t0 * t1 = z ** 11 -- stash t0 away for the end. */
    let xx2 = t0;
    fe_mul(&mut t0, &xx2, &t1);

    /* t2 = t0 ** 2 = z ** 22 */
    let mut t2 = Fe25519::default();
    fe_square(&mut t2, &t0);

    /* t1 = t1 * t2 = z ** (2 ** 5 - 1) */
    let xx3 = t1;
    fe_mul(&mut t1, &xx3, &t2);

    /* t2 = t1 ** (2 ** 5) = z ** ((2 ** 5) * (2 ** 5 - 1)) */
    fe_square(&mut t2, &t1);
    for _i in 1..5 {
        //(i = 1; i < 5; ++i)
        let xx4 = t2;
        fe_square(&mut t2, &xx4);
    }

    /* t1 = t1 * t2 = z ** ((2 ** 5 + 1) * (2 ** 5 - 1)) = z ** (2 ** 10 - 1) */
    let xx5 = t1;
    fe_mul(&mut t1, &t2, &xx5);

    /* Continuing similarly... */

    /* t2 = z ** (2 ** 20 - 1) */
    fe_square(&mut t2, &t1);
    for _i in 1..10 {
        // (i = 1; i < 10; ++i)
        let xx6 = t2;
        fe_square(&mut t2, &xx6);
    }

    let xx7 = t2;
    fe_mul(&mut t2, &xx7, &t1);

    /* t2 = z ** (2 ** 40 - 1) */
    let mut t3 = Fe25519::default();
    fe_square(&mut t3, &t2);
    for _i in 1..20 {
        // (i = 1; i < 20; ++i)
        let xx8 = t3;
        fe_square(&mut t3, &xx8);
    }
    let xx9 = t2;
    fe_mul(&mut t2, &t3, &xx9);

    /* t2 = z ** (2 ** 10) * (2 ** 40 - 1) */
    for _i in 0..10 {
        //(i = 0; i < 10; ++i)
        let xx10 = t2;
        fe_square(&mut t2, &xx10);
    }

    /* t1 = z ** (2 ** 50 - 1) */
    let xx11 = t1;
    fe_mul(&mut t1, &t2, &xx11);

    /* t2 = z ** (2 ** 100 - 1) */
    fe_square(&mut t2, &t1);
    for _i in 1..50 {
        //(i = 1; i < 50; ++i)
        let xx12 = t2;
        fe_square(&mut t2, &xx12);
    }
    let xx13 = t2;
    fe_mul(&mut t2, &xx13, &t1);

    /* t2 = z ** (2 ** 200 - 1) */
    fe_square(&mut t3, &t2);
    for _i in 1..100 {
        // (i = 1; i < 100; ++i)
        let xx14 = t3;
        fe_square(&mut t3, &xx14);
    }
    let xx15 = t2;
    fe_mul(&mut t2, &t3, &xx15);

    /* t2 = z ** ((2 ** 50) * (2 ** 200 - 1) */
    for _i in 0..50 {
        // (i = 0; i < 50; ++i)
        let xx16 = t2;
        fe_square(&mut t2, &xx16);
    }

    /* t1 = z ** (2 ** 250 - 1) */
    let xx17 = t1;
    fe_mul(&mut t1, &t2, &xx17);

    /* t1 = z ** ((2 ** 5) * (2 ** 250 - 1)) */
    for _i in 0..5 {
        // (i = 0; i < 5; ++i)
        let xx18 = t1;
        fe_square(&mut t1, &xx18);
    }
    /* Recall t0 = z ** 11; out = z ** (2 ** 255 - 21) */
    let mut out = Fe25519::default();
    fe_mul(&mut out, &t1, &t0);

    *result = Fe25519 { ..out };
}

#[allow(non_snake_case)]
pub(crate) fn mul(result: &mut Fe25519, k: &Fe25519, u: Fe25519) {
    let x_1 = u; // x_1 = u
    let mut x_2 = Fe25519 { x3: 0, x2: 0, x1: 0, x0: 1 }; // x_2 = 1
    let mut z_2 = Fe25519 { x3: 0, x2: 0, x1: 0, x0: 0 }; // z_2 = 0
    let mut x_3 = u; //x_3 = u
    let mut z_3 = Fe25519 { x3: 0, x2: 0, x1: 0, x0: 1 }; //z_3 = 1
    let mut swap = Fe25519 { x3: 0, x2: 0, x1: 0, x0: 0 }; //swap = 0
    let mut A = Fe25519::default();
    let mut AA = Fe25519::default();
    let mut B = Fe25519::default();
    let mut BB = Fe25519::default();
    let mut C = Fe25519::default();
    let mut CB = Fe25519::default();
    let mut D = Fe25519::default();
    let mut DA = Fe25519::default();
    let mut E = Fe25519::default();
    let mut t1 = Fe25519::default();
    let mut t2 = Fe25519::default();
    let mut t3 = Fe25519::default();
    let mut t4 = Fe25519::default();
    let mut t5 = Fe25519::default();

    for t in (0..=(255i16 - 1)).rev() {
        //println!("{}", t);
        //                                                  For t = bits-1 down to 0:
        let k_t = k_t(&k, t); //                       k_t = (k >> t) & 1
        //println!("{}", x_3);
        swap.x3 ^= k_t.x3; //                                   swap ^= k_t
        swap.x2 ^= k_t.x2;
        swap.x1 ^= k_t.x1;
        swap.x0 ^= k_t.x0;
        fe_cswap(&swap, &mut x_2, &mut x_3); //                 (x_2, x_3) = cswap(swap, x_2, x_3)
        fe_cswap(&swap, &mut z_2, &mut z_3); //       (z_2, z_3) = cswap(swap, z_2, z_3)
        swap = k_t; //                                          swap = k_t
        //println!("{}", swap);

        fe_add(&mut A, &x_2, &z_2); //          A = x_2 + z_2
        fe_mul(&mut AA, &A, &A); //             AA = A^2
        fe_sub(&mut B, &x_2, &z_2); //          B = x_2 - z_2
        fe_mul(&mut BB, &B, &B); //             BB = B^2
        fe_sub(&mut E, &AA, &BB); //            E = AA - BB
        fe_add(&mut C, &x_3, &z_3); //          C = x_3 + z_3
        fe_sub(&mut D, &x_3, &z_3); //          D = x_3 - z_3
        fe_mul(&mut DA, &D, &A); //             DA = D * A
        fe_mul(&mut CB, &C, &B); //             CB = C * B
        fe_add(&mut t1, &DA, &CB); //           x_3 = (DA + CB)^2
        fe_mul(&mut x_3, &t1, &t1);
        fe_sub(&mut t2, &DA, &CB); //           z_3 = x_1 * (DA - CB)^2
        fe_mul(&mut t3, &t2, &t2);
        fe_mul(&mut z_3, &x_1, &t3);
        fe_mul(&mut x_2, &AA, &BB); //          x_2 = AA * BB
        fe_mul_121665(&mut t4, &E);
        fe_add(&mut t5, &AA, &t4); //           z_2 = E * (AA + a24 * E)
        fe_mul(&mut z_2, &E, &t5);
    }
    fe_cswap(&swap, &mut x_2, &mut x_3); //                 (x_2, x_3) = cswap(swap, x_2, x_3)
    fe_cswap(&swap, &mut z_2, &mut z_3); //       (z_2, z_3) = cswap(swap, z_2, z_3)

    let mut t000 = Fe25519::default();
    fe_invert(&mut t000, &z_2);

    let mut out = Fe25519::default();
    fe_mul(&mut out, &x_2, &t000);

    *result = Fe25519 { ..out };
}
