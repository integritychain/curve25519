#![deny(clippy::all)]

use std::ops::Sub;
use std::str::FromStr;
use std::time::Instant;

use num_bigint::{BigUint, RandomBits};
use num_traits::One;
use rand::Rng;

use crate::arith::{Fe25519, fe_add, fe_invert, fe_mul, fe_mul_121665, fe_square, fe_sub, get_k, get_u, mul};

lazy_static! {
    static ref TWO255M19: BigUint = {
        let one: BigUint = One::one();
        let two255m19 = (one << 255).sub(19 as u32);
        two255m19
    };
}

pub fn generate_operand(bits: usize) -> BigUint {
    let mut rng = rand::thread_rng();
    let mut result: BigUint;
    loop {
        result = match rng.gen_range(0, 100) {
            0 => BigUint::from_str("0").unwrap(),
            1 => BigUint::from_str("1").unwrap(),
            2 => BigUint::from_str("2").unwrap(),
            3 => BigUint::from_str("3").unwrap(),
            4 => (&*TWO255M19).clone().sub(4 as u32),
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
        let a_exp = generate_operand(256);
        let b_exp = generate_operand(256);
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
        let a_exp = generate_operand(256);
        let b_exp = generate_operand(256);
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
        let a_exp = generate_operand(256);
        let b_exp = generate_operand(256);
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
        let a_exp = generate_operand(256);
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
        let a_exp = generate_operand(256);
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
        let operand1 = generate_operand(254);
        if operand1 == BigUint::from_str("0").unwrap() {
            continue;
        }
        let operand2 = Fe25519::from_str(&format!("0x{:064x}", operand1)).unwrap();
        fe_invert(&mut result, &operand2);
        fe_mul(&mut result_act, &operand2, &result);
        assert_eq!(one, result_act);
    }
}

#[test]
fn iterative_mul() {
    let k = get_k("0x0900000000000000-0000000000000000-0000000000000000-0000000000000000");
    let u = get_u("0x0900000000000000-0000000000000000-0000000000000000-0000000000000000");
    let mut result_act = Fe25519::default();
    mul(&mut result_act, &k, u);
    let result_str = format!("{:b}", result_act);
    assert_eq!(result_str, "0x422c8e7a6227d7bc-a1350b3e2bb7279f-7897b87bb6854b78-3c60e80311ae3079");
    println!("Passed 'once' iterative_mul test");

    let k = get_k("0xa546e36bf0527c9d-3b16154b82465edd-62144c0ac1fc5a18-506a2244ba449ac4");
    let u = get_u("0xe6db6867583030db-3594c1a424b15f7c-726624ec26b3353b-10a903a6d0ab1c4c");
    let mut result_act = Fe25519::default();
    mul(&mut result_act, &k, u);
    let result_str = format!("{:b}", result_act);
    assert_eq!(result_str, "0xc3da55379de9c690-8e94ea4df28d084f-32eccf03491c71f7-54b4075577a28552");
    println!("Passed 'first' iterative_mul test");

    let mut k_string = "0x0900000000000000-0000000000000000-0000000000000000-0000000000000000".to_string();
    let mut u_string = "0x0900000000000000-0000000000000000-0000000000000000-0000000000000000".to_string();
    let start_time = Instant::now();
    for index in 0..5_000 {  // Set to 1M for full test
        let k = get_k(&k_string);
        let u = get_u(&u_string);
        mul(&mut result_act, &k, u);
        let result_str = format!("{:b}", result_act);
        match index {
            0 => {
                assert_eq!(result_str, "0x422c8e7a6227d7bc-a1350b3e2bb7279f-7897b87bb6854b78-3c60e80311ae3079");
                println!("Passed 1X iterative_mul case");
            },
            999 => {
                assert_eq!(result_str, "0x684cf59ba8330955-2800ef566f2f4d3c-1c3887c49360e387-5f2eb94d99532c51");
                println!("Passed 1,000X iterative_mul case")
            },
            4_999 => {
                assert_eq!(result_str, "0x90aca1c8dab080cc-cf82d3e972f2dbac-319e1a1424a77852-a8b57a5957458353");
                println!("Passed 5,000X iterative_mul case")
            },
            999_999 => {
                assert_eq!(result_str, "0x7c3911e0ab2586fd-864497297e575e6f-3bc601c0883c30df-5f4dd2d24f665424");
                println!("Passed 1,000,000X iterative_mul case")
            }
            _ => {},
        }
        u_string = k_string;
        k_string = result_str;
    }

    // Yes, tests are running in parallel and potentially unoptimized ... this is a relative metric ; )
    let duration = start_time.elapsed();
    println!("Mul rate is {:3.3}k per second.", 5_000.0 / duration.as_millis() as f64);
}
