//! Curated ReDoS corpus — empirical validation of the analyzer.
//!
//! Hand-labeled from ReDoS classics, CVEs, and the literature. The product-
//! automaton EDA detector is sound AND complete for exponential ambiguity, so
//! the bar is strict: every genuinely-exponential pattern must be flagged
//! `Exponential`, and NO safe/polynomial pattern may be (zero false positives).
//!
//! This is a curated subset, not the full vuln-regex-detector/ReDoSHunter
//! corpora (the Phase-1 GO gate). It validates the EDA work and surfaces gaps.

use rxray::{analyze, ComplexityClass, Engine};

/// Patterns with genuine exponential backtracking → must be `Exponential`.
const EXPONENTIAL: &[&str] = &[
    "(a+)+$",
    "(a*)*$",
    "(aa|a)+$",
    "(a|aa)+$",
    r"(\d+)+$",
    "([a-z]+)+$",
    "(x+x+)+y",
    "(a+)+b",
    "(.*)*$",
    r"(\d+)*$",   // nested via star
    "(x*)*y",     // empty-loop nested
    r"(\s*)*$",   // empty-loop
    "([a-z]*)*$", // empty-loop
    "(a?)+$",     // nullable body under +
];

/// Patterns that are polynomial (IDA) — quadratic+ but NOT exponential.
const POLYNOMIAL: &[&str] = &[
    "a*a*$",
    r"\d*\d*$",
    ".*.*$",
    r"\d*-?\d*$", // non-adjacent reps — structural heuristic missed this
    r"\w*\w*$",
    "[a-z]*[a-z]*$",
    "a*a*a*a*$", // higher degree
];

/// Safe, linear patterns → must never be flagged exponential.
const SAFE: &[&str] = &[
    "abc",
    "a+",
    "[a-z]+",
    r"\d{3}-\d{4}",
    "(ab)+",
    "a*b*",
    "https?://",
    r"^[a-z0-9]+@[a-z0-9]+\.[a-z]+$",
    r"\w+",
    "(ab+)+", // looks nested but needs a fresh separator — not exponential
    r"^\d+$",
    "foo|bar|baz",
    r"\d{4}-\d{2}-\d{2}",
    "(abc)+def",
    r"[A-Za-z0-9._%+-]+",
];

fn is_exponential(pattern: &str) -> bool {
    matches!(
        analyze(pattern, Engine::Pcre2).map(|r| r.worst),
        Ok(ComplexityClass::Exponential)
    )
}

#[test]
fn eda_detector_has_no_false_positives() {
    let mut false_positives = Vec::new();
    for &p in POLYNOMIAL.iter().chain(SAFE) {
        if is_exponential(p) {
            false_positives.push(p);
        }
    }
    assert!(
        false_positives.is_empty(),
        "non-exponential patterns wrongly flagged Exponential: {false_positives:?}"
    );
}

#[test]
fn eda_detector_catches_all_exponential() {
    let mut missed = Vec::new();
    for &p in EXPONENTIAL {
        if !is_exponential(p) {
            missed.push(p);
        }
    }
    let recall = (EXPONENTIAL.len() - missed.len()) as f64 / EXPONENTIAL.len() as f64;
    assert!(
        missed.is_empty(),
        "missed exponential patterns (recall {recall:.2}): {missed:?}"
    );
}

#[test]
fn polynomial_patterns_are_detected_as_polynomial() {
    // Sound NFA-based IDA: every polynomial pattern must be flagged Polynomial
    // (not Linear, not over-escalated to Exponential).
    let mut wrong = Vec::new();
    for &p in POLYNOMIAL {
        if !matches!(
            analyze(p, Engine::Pcre2).map(|r| r.worst),
            Ok(ComplexityClass::Polynomial(_))
        ) {
            wrong.push((p, analyze(p, Engine::Pcre2).map(|r| r.worst)));
        }
    }
    assert!(
        wrong.is_empty(),
        "polynomial patterns misclassified: {wrong:?}"
    );
}
