#![deny(clippy::all)]

use std::ops::Sub;
use std::str::FromStr;

use num_bigint::{BigUint, RandomBits};
use num_traits::One;
use rand::Rng;

use crate::arith::{fe_add, fe_mul, fe_mul_121665, fe_square, fe_sub, get_k, get_u, mul};

use super::*;

lazy_static! {
    static ref TWO255M19: BigUint = {
        let one: BigUint = One::one();
        let two255m19 = (one << 255).sub(19 as u32);
        two255m19
    };
}

pub fn gimme_number(bits: usize) -> BigUint {
    let mut rng = rand::thread_rng();
    let mut result: BigUint;
    loop {
        result = match rng.gen_range(0, 100) {
            0 => BigUint::from_str("0").unwrap(),
            1 => BigUint::from_str("1").unwrap(),
            2 => BigUint::from_str("2").unwrap(),
            3 => BigUint::from_str("3").unwrap(),
            4 => (&*TWO255M19).clone().sub(4 as u32), // Adjust matching for smaller bit widths
            5 => (&*TWO255M19).clone().sub(3 as u32),
            6 => (&*TWO255M19).clone().sub(2 as u32),
            7 => (&*TWO255M19).clone().sub(1 as u32),
            _ => rng.sample(RandomBits::new(bits)),
        };
        if result < *TWO255M19 {
            break;
        }
    }
    result
}

#[test]
fn fuzz_add() {
    let mut s_actual = Fe25519 { x3: 0, x2: 0, x1: 0, x0: 0 };
    for _index in 1..1_000 {
        let a_exp = gimme_number(256);
        let b_exp = gimme_number(256);
        let sum_exp = Fe25519::from_str(&format!("0x{:064x}", (&a_exp + &b_exp) % &*TWO255M19)).unwrap();
        let a_actual = Fe25519::from_str(&format!("0x{:064x}", a_exp)).unwrap();
        let b_actual = Fe25519::from_str(&format!("0x{:064x}", b_exp)).unwrap();
        fe_add(&mut s_actual, &a_actual, &b_actual);
        assert_eq!(sum_exp, s_actual);
    }
}

#[test]
fn fuzz_sub() {
    let mut s_actual = Fe25519 { x3: 0, x2: 0, x1: 0, x0: 0 };

    for _index in 1..1_000 {
        let a_exp = gimme_number(256);
        let b_exp = gimme_number(256);
        // b - b = 0 = 2**255-19 --> -b = 2**255-19 - b --> a - b = a + 2**255-19 - b
        let c_exp = &*TWO255M19 - &b_exp;
        let sum_exp = Fe25519::from_str(&format!("0x{:064x}", (&a_exp + &c_exp) % &*TWO255M19)).unwrap();
        let a_actual = Fe25519::from_str(&format!("0x{:064x}", a_exp)).unwrap();
        let b_actual = Fe25519::from_str(&format!("0x{:064x}", b_exp)).unwrap();
        fe_sub(&mut s_actual, &a_actual, &b_actual);
        assert_eq!(sum_exp, s_actual);
    }
}

#[test]
fn fuzz_mul() {
    let mut mul_act = Fe25519 { x3: 0, x2: 0, x1: 0, x0: 0 };
    for _index in 1..1_000 {
        let a_exp = gimme_number(256);
        let b_exp = gimme_number(256);
        let mul_exp = Fe25519::from_str(&format!("0x{:064x}", (&a_exp * &b_exp) % &*TWO255M19)).unwrap();
        let a_act = Fe25519::from_str(&format!("0x{:064x}", a_exp)).unwrap();
        let b_act = Fe25519::from_str(&format!("0x{:064x}", b_exp)).unwrap();
        fe_mul(&mut mul_act, &a_act, &b_act);
        assert_eq!(mul_exp, mul_act);
    }
}

#[test]
fn fuzz_square() {
    let mut sqr_act = Fe25519 { x3: 0, x2: 0, x1: 0, x0: 0 };
    for _index in 1..1_000 {
        let a_exp = gimme_number(256);
        let sqr_exp = Fe25519::from_str(&format!("0x{:064x}", (&a_exp * &a_exp) % &*TWO255M19)).unwrap();
        let a_act = Fe25519::from_str(&format!("0x{:064x}", a_exp)).unwrap();
        fe_square(&mut sqr_act, &a_act);
        assert_eq!(sqr_exp, sqr_act);
    }
}

#[test]
fn fuzz_mul_121665() {
    let mut mul_act = Fe25519 { x3: 0, x2: 0, x1: 0, x0: 0 };
    for _index in 1..1_000 {
        let a_exp = gimme_number(256);
        let b_exp = BigUint::from_str("121665").unwrap();
        let mul_exp = Fe25519::from_str(&format!("0x{:064x}", (&a_exp * &b_exp) % &*TWO255M19)).unwrap();
        let a_act = Fe25519::from_str(&format!("0x{:064x}", a_exp)).unwrap();
        fe_mul_121665(&mut mul_act, &a_act);
        assert_eq!(mul_exp, mul_act);
    }
}

#[test]
fn fuzz_inverse() {
    let one = Fe25519::from_str("0x0000000000000000-0000000000000000-0000000000000000-0000000000000001").unwrap();
    let mut result = Fe25519::default();
    let mut result_act = Fe25519::default();
    for _index in 1..1_000 {
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


//#[test]
//fn fuzz_p_mul() {
//    let result_exp = "0x422c8e7a6227d7bc-a1350b3e2bb7279f-7897b87bb6854b78-3c60e80311ae3079";
//    //let k = get_k("4000000000000000-0000000000000000-0000000000000000-0000000000000009");
//    let mut k = get_k("0900000000000000-0000000000000000-0000000000000000-0000000000000000"); // big endian?
//    //let u = get_u("0000000000000000-0000000000000000-0000000000000000-0000000000000009");
//    let mut u = get_u("0900000000000000-0000000000000000-0000000000000000-0000000000000000");
//    let mut result_act = Fe25519::default();
//    for _index in 1..10_000 {
//        mul(&mut result_act, &k, u);
//        let res = format!("{:b}", result_act);
//        assert_eq!(result_exp, res);
//    }
//}


#[test]
fn fuzz_p_mul() {
    // The second type of test vector consists of...once
    let mut result_exp = "0x422c8e7a6227d7bc-a1350b3e2bb7279f-7897b87bb6854b78-3c60e80311ae3079";
    let mut k = get_k("0x0900000000000000-0000000000000000-0000000000000000-0000000000000000");
    let mut u = get_u("0x0900000000000000-0000000000000000-0000000000000000-0000000000000000");
    let mut result_act = Fe25519::default();
    mul(&mut result_act, &k, u);
    let res = format!("{:b}", result_act);
    assert_eq!(result_exp, res);

    // The second type of test vector consists of...1000
    result_exp = "0x684cf59ba8330955-2800ef566f2f4d3c-1c3887c49360e387-5f2eb94d99532c51";
    k = get_k("0x0900000000000000-0000000000000000-0000000000000000-0000000000000000");
    u = get_u("0x0900000000000000-0000000000000000-0000000000000000-0000000000000000");
    for index in 0..1_001 {
        mul(&mut result_act, &k, u);
        println!("{} Res: {:b}", index, result_act);
        u = get_u(&format!("{:b}", k));
        k = get_k(&format!("{:b}", result_act));
    }
    let res = format!("{:b}", result_act);
    //println!("Res: {:b}", result_act);
    assert_eq!(result_exp, res);
}
