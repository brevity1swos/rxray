//! HIR-level ambiguity helpers that complement the NFA product analyses.
//!
//! - [`has_empty_loop_eda`] catches the nullable-body EDA family (`(a*)*`,
//!   `(.*)*`, `(a?)*`) that the product-automaton detector folds away.
//! - [`worst`] reduces a finding list to its worst complexity class.

use regex_syntax::hir::{Hir, HirKind};

use crate::{ComplexityClass, Finding};

/// Worst complexity across `findings` (`Linear` if none).
pub(crate) fn worst(findings: &[Finding]) -> ComplexityClass {
    findings
        .iter()
        .map(|f| f.class)
        .max_by(severity)
        .unwrap_or(ComplexityClass::Linear)
}

/// Empty-loop EDA: an unbounded repetition whose body is nullable and can also
/// match a non-empty string, e.g. `(a*)*`, `(.*)*`, `(a?)*`.
///
/// Such a loop can pad any input with empty iterations, so a run of input
/// splits among outer iterations in exponentially many ways. The product-
/// automaton detector folds away these epsilon-cycles and misses them, so this
/// sound HIR-level rule complements it.
pub(crate) fn has_empty_loop_eda(hir: &Hir) -> bool {
    let here = matches!(
        hir.kind(),
        HirKind::Repetition(rep)
            if rep.max.is_none() && nullable(&rep.sub) && matches_nonempty(&rep.sub)
    );
    here || children(hir).into_iter().any(has_empty_loop_eda)
}

/// Can `hir` match the empty string?
fn nullable(hir: &Hir) -> bool {
    match hir.kind() {
        HirKind::Empty | HirKind::Look(_) => true,
        HirKind::Literal(lit) => lit.0.is_empty(),
        HirKind::Class(_) => false,
        HirKind::Repetition(rep) => rep.min == 0 || nullable(&rep.sub),
        HirKind::Capture(cap) => nullable(&cap.sub),
        HirKind::Concat(subs) => subs.iter().all(nullable),
        HirKind::Alternation(subs) => subs.iter().any(nullable),
    }
}

/// Can `hir` match a non-empty string?
fn matches_nonempty(hir: &Hir) -> bool {
    match hir.kind() {
        HirKind::Empty | HirKind::Look(_) => false,
        HirKind::Literal(lit) => !lit.0.is_empty(),
        HirKind::Class(_) => true,
        HirKind::Repetition(rep) => rep.max != Some(0) && matches_nonempty(&rep.sub),
        HirKind::Capture(cap) => matches_nonempty(&cap.sub),
        HirKind::Concat(subs) | HirKind::Alternation(subs) => subs.iter().any(matches_nonempty),
    }
}

/// Direct HIR children of a node.
fn children(hir: &Hir) -> Vec<&Hir> {
    match hir.kind() {
        HirKind::Repetition(rep) => vec![&rep.sub],
        HirKind::Capture(cap) => vec![&cap.sub],
        HirKind::Concat(subs) | HirKind::Alternation(subs) => subs.iter().collect(),
        HirKind::Empty | HirKind::Literal(_) | HirKind::Class(_) | HirKind::Look(_) => Vec::new(),
    }
}

/// Ordering on complexity classes by severity (Linear < Polynomial < Exponential).
fn severity(a: &ComplexityClass, b: &ComplexityClass) -> std::cmp::Ordering {
    fn rank(c: &ComplexityClass) -> u64 {
        match c {
            ComplexityClass::Linear => 0,
            ComplexityClass::Polynomial(k) => 1 + u64::from(*k),
            ComplexityClass::Exponential => u64::MAX,
        }
    }
    rank(a).cmp(&rank(b))
}
