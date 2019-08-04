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
    let a_expected = &*TWO255M19;
    let b_expected = &*TWO255M19;
    let s_expected = Fe25519::from_str(&format!(
        "0x{:064x}",
        (a_expected + b_expected) % &*TWO255M19
    ))
        .unwrap();
    let a_actual = Fe25519::from_str(&format!("0x{:064x}", a_expected)).unwrap();
    let b_actual = Fe25519::from_str(&format!("0x{:064x}", b_expected)).unwrap();
    let s_actual = a_actual + b_actual;
    assert_eq!(s_expected, s_actual);
}

#[test]
fn test_fuzz_add() {
    for _index in 1..1000 {
        let a_expected = gimme_number(256);
        let b_expected = gimme_number(256);
        let s_expected = Fe25519::from_str(&format!(
            "0x{:064x}",
            (&a_expected + &b_expected) % &*TWO255M19
        ))
            .unwrap();
        let a_actual = Fe25519::from_str(&format!("0x{:064x}", a_expected)).unwrap();
        let b_actual = Fe25519::from_str(&format!("0x{:064x}", b_expected)).unwrap();
        let s_actual = a_actual + b_actual;
        assert_eq!(s_expected, s_actual);
    }
}

#[test]
fn text_fuzz_mul() {
    for _index in 1..1000 {
        let a_expected = gimme_number(26);
        let b_expected = gimme_number(26);
        let lsb_expected = Fe25519::from_str(&format!(
            "0x{:064x}",
            (&a_expected * &b_expected) % &*TWO255M19
        ))
            .unwrap();
        let a_actual = Fe25519::from_str(&format!("0x{:064x}", a_expected)).unwrap();
        let b_actual = Fe25519::from_str(&format!("0x{:064x}", b_expected)).unwrap();
        let lsb_actual = (a_actual * b_actual).1;
        assert_eq!(lsb_expected, lsb_actual);
    }
}
