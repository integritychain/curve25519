#![feature(test)]

#![deny(clippy::all)]

// See: https://tools.ietf.org/html/rfc7748

// TODO:
//   0. Decode u and k per RFC (tweak bits)
//   1. General clean up; clippy; lint messages
//   2. Finish mul point
//   3. Add logic to gimme number for middle 0xFFFFF


#[macro_use]
extern crate lazy_static;
extern crate test;

use std::str::FromStr;

use num_bigint::BigUint;

use crate::arith::{Fe25519, fe_invert, fe_mul};
use crate::tests::gimme_number;

mod arith;
mod support;

//#[cfg(test)]
mod tests;

#[cfg(test)]
mod tests2 {
    use test::Bencher;

    use super::*;

    #[bench]
    fn bench_invert(b: &mut Bencher) {
        let one = Fe25519::from_str("0x0000000000000000-0000000000000000-0000000000000000-0000000000000001").unwrap();
        let mut result = Fe25519::default();
        let mut result_act = Fe25519::default();
        let mut operand1: BigUint;
        loop {
            operand1 = gimme_number(254);
            if operand1 != BigUint::from_str("0").unwrap() {
                break;
            }
        }
        let operand2 = Fe25519::from_str(&format!("0x{:064x}", operand1)).unwrap();
        fe_invert(&mut result, &operand2);
        fe_mul(&mut result_act, &operand2, &result);
        assert_eq!(one, result_act);

        b.iter(|| fe_invert(&mut result, &operand2));
    }
}

fn main() {
    println!("Starting test...");
    let one = Fe25519::from_str("0x0000000000000000-0000000000000000-0000000000000000-0000000000000001").unwrap();
    let mut result = Fe25519::default();
    let mut result_act = Fe25519::default();
    for _index in 1..10_000 {
        let operand1 = gimme_number(254);
        if operand1 == BigUint::from_str("0").unwrap() {
            continue;
        }
        let operand2 = Fe25519::from_str(&format!("0x{:064x}", operand1)).unwrap();
        fe_invert(&mut result, &operand2);
        fe_mul(&mut result_act, &operand2, &result);
        assert_eq!(one, result_act);
    }
}
