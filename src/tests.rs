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
    let mut result;
    loop {
        result = rng.sample(RandomBits::new(bits));
        if result < *TWO255M19 {
            break;
        }
    }
    result
}

#[test]
fn test_corner_add() {
    let a_exp = (&*TWO255M19).clone().sub(1 as u32);
    let b_exp: BigUint = One::one(); //= &(&*TWO255M19).clone().sub(1 as u32);
    let sum_exp =
        Fe25519::from_str(&format!("0x{:064x}", (&a_exp + &b_exp) % &*TWO255M19)).unwrap();
    let a_act = Fe25519::from_str(&format!("0x{:064x}", &a_exp)).unwrap();
    let b_act = Fe25519::from_str(&format!("0x{:064x}", &b_exp)).unwrap();
    let sum_act = a_act + b_act;
    assert_eq!(sum_exp, sum_act);
}

#[test]
fn test_fuzz_add() {
    for _index in 1..10000 {
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
fn text_fuzz_mul() {
    for _index in 1..10000 {
        let a_exp = gimme_number(256);
        let b_exp = gimme_number(256);
        let mul_exp =
            Fe25519::from_str(&format!("0x{:064x}", (&a_exp * &b_exp) % &*TWO255M19)).unwrap();
        let mul_orig = &a_exp * &b_exp;
        if mul_orig == *TWO255M19 {
            println!("{}", mul_orig);
        }
        let a_act = Fe25519::from_str(&format!("0x{:064x}", a_exp)).unwrap();
        let b_act = Fe25519::from_str(&format!("0x{:064x}", b_exp)).unwrap();
        let mul_act = a_act * b_act;
        assert_eq!(mul_exp, mul_act);
    }
}
