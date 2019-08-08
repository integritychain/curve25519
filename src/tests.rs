#![deny(clippy::all)]

#[cfg(test)]
use std::ops::Sub;
use std::str::FromStr;

use num_bigint::{BigUint, RandomBits};
use num_traits::One;
use rand::Rng;

use super::*;

lazy_static! {
    static ref TWO255M19: BigUint = {
        let one: BigUint = One::one();
        let two255m19 = (one << 255).sub(19 as u32);
        two255m19
    };
}

fn gimme_number(bits: usize) -> BigUint {
    let mut rng = rand::thread_rng();
    let mut result: BigUint;
    loop {
        result = match rng.gen_range(0, 100) {
            0 => BigUint::from_str("0").unwrap(),
            1 => BigUint::from_str("1").unwrap(),
            2 => BigUint::from_str("2").unwrap(),
            3 => BigUint::from_str("3").unwrap(),
            4 => (&*TWO255M19).clone().sub(3 as u32),
            5 => (&*TWO255M19).clone().sub(2 as u32),
            6 => (&*TWO255M19).clone().sub(1 as u32),
            7 => (&*TWO255M19).clone().sub(0 as u32),
            _ => rng.sample(RandomBits::new(bits)),
        };
        if result < *TWO255M19 {
            break;
        }
    }
    result
}

#[test]
fn test_fuzz_add() {
    for _index in 1..100_000 {
        let a_exp = gimme_number(256);
        let b_exp = gimme_number(256);
        let sum_exp =
            Fe25519::from_str(&format!("0x{:064x}", (&a_exp + &b_exp) % &*TWO255M19)).unwrap();
        let a_actual = Fe25519::from_str(&format!("0x{:064x}", a_exp)).unwrap();
        let b_actual = Fe25519::from_str(&format!("0x{:064x}", b_exp)).unwrap();
        let s_actual = a_actual + b_actual;
        assert_eq!(sum_exp, s_actual);
    }
}

#[test]
fn test_fuzz_sub() {
    for _index in 1..100_000 {
        let a_exp = gimme_number(256);
        let b_exp = gimme_number(256);
        // b - b = 0 = 2**255-19 --> -b = 2**255-19 - b --> a - b = a + 2**255-19 - b
        let c_exp = &*TWO255M19 - &b_exp;
        let sum_exp =
            Fe25519::from_str(&format!("0x{:064x}", (&a_exp + &c_exp) % &*TWO255M19)).unwrap();
        let a_actual = Fe25519::from_str(&format!("0x{:064x}", a_exp)).unwrap();
        let b_actual = Fe25519::from_str(&format!("0x{:064x}", b_exp)).unwrap();
        let s_actual = a_actual - b_actual;
        assert_eq!(sum_exp, s_actual);
    }
}

#[test]
fn text_fuzz_mul() {
    for _index in 1..100_000 {
        let a_exp = gimme_number(256);
        let b_exp = gimme_number(256);
        let mul_exp =
            Fe25519::from_str(&format!("0x{:064x}", (&a_exp * &b_exp) % &*TWO255M19)).unwrap();
        let a_act = Fe25519::from_str(&format!("0x{:064x}", a_exp)).unwrap();
        let b_act = Fe25519::from_str(&format!("0x{:064x}", b_exp)).unwrap();
        let mul_act = a_act * b_act;
        assert_eq!(mul_exp, mul_act);
    }
}

#[test]
fn text_fuzz_mul_24() {
    for _index in 1..100_000 {
        let a_exp = gimme_number(256);
        let b_exp = BigUint::from_str("121665").unwrap();
        let mul_exp =
            Fe25519::from_str(&format!("0x{:064x}", (&a_exp * &b_exp) % &*TWO255M19)).unwrap();
        let mut a_act = Fe25519::from_str(&format!("0x{:064x}", a_exp)).unwrap();
        let b_act = Fe25519::from_str(&format!("0x{:064x}", b_exp)).unwrap();
        a_act = a_act.mul_121665();
        assert_eq!(mul_exp, a_act);
    }
}
