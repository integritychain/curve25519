#![deny(clippy::all)]

// See: https://tools.ietf.org/html/rfc7748
// cargo test --color=always --package curve25519 --bin curve25519 -- --nocapture

#[macro_use]
extern crate lazy_static;

mod arith;
mod support;
mod tests;

// TODO: The actual tests are in tests.rs - not here!!!
fn main() {
    println!("Starting...");
}
