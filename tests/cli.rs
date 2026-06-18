//! Integration tests for the `rxray` CLI gate (exit-code contract).

use std::process::Command;

fn run(args: &[&str]) -> (i32, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_rxray"))
        .args(args)
        .output()
        .expect("run rxray");
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    (code, stdout)
}

#[test]
fn safe_pattern_exits_zero() {
    let (code, out) = run(&["a+b+"]);
    assert_eq!(code, 0);
    assert!(out.contains("Linear"));
}

#[test]
fn exponential_pattern_exits_one() {
    let (code, out) = run(&["(a+)+$"]);
    assert_eq!(code, 1);
    assert!(out.contains("Exponential"));
}

#[test]
fn polynomial_exceeds_linear_but_passes_poly_threshold() {
    assert_eq!(run(&["a*a*$"]).0, 1); // default threshold linear → exceeds
    assert_eq!(run(&["--max-complexity", "poly", "a*a*$"]).0, 0); // poly allowed
    assert_eq!(run(&["--max-complexity", "poly:1", "a*a*$"]).0, 1); // O(n^2) > 1
}

#[test]
fn parse_error_exits_two() {
    assert_eq!(run(&["("]).0, 2);
}

#[test]
fn attack_flag_prints_attack_for_exponential() {
    let (code, out) = run(&["--attack", "(a+)+$"]);
    assert_eq!(code, 1);
    assert!(out.contains("attack"));
}
