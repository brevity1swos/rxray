//! Structural IDA (polynomial) analysis over the `regex-syntax` HIR.
//!
//! Detects a run of `k` adjacent unbounded repetitions whose bodies overlap,
//! e.g. `a*a*` → `Polynomial(2)`. Exponential ambiguity (EDA) is handled by the
//! sound product-automaton analysis in [`crate::eda`], not here.
//!
//! The sound NFA-based *IDA* analysis (replacing this structural heuristic) and
//! the corpus-validated precision/recall gate are the remaining Phase 1 work.

use regex_syntax::hir::{Class, Hir, HirKind, Repetition};

use crate::{AmbiguityKind, ComplexityClass, Finding};

/// Structural IDA (polynomial) findings in a parsed pattern, in source order.
pub(crate) fn ida_findings(hir: &Hir) -> Vec<Finding> {
    let mut out = Vec::new();
    collect_ida(hir, &mut out);
    out
}

/// Worst complexity across `findings` (`Linear` if none).
pub(crate) fn worst(findings: &[Finding]) -> ComplexityClass {
    findings
        .iter()
        .map(|f| f.class)
        .max_by(severity)
        .unwrap_or(ComplexityClass::Linear)
}

fn collect_ida(hir: &Hir, out: &mut Vec<Finding>) {
    if let HirKind::Concat(subs) = hir.kind() {
        if let ComplexityClass::Polynomial(k) = ida_in_concat(subs) {
            out.push(Finding {
                class: ComplexityClass::Polynomial(k),
                kind: AmbiguityKind::Ida,
                explanation: format!(
                    "{k} adjacent unbounded repetitions over overlapping input cause \
                    polynomial O(n^{k}) backtracking"
                ),
            });
        }
    }

    for child in children(hir) {
        collect_ida(child, out);
    }
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

/// Longest run of adjacent, pairwise-overlapping unbounded repetitions → poly degree.
fn ida_in_concat(subs: &[Hir]) -> ComplexityClass {
    let mut best_k: u32 = 1;
    let mut run: u32 = 0;
    let mut prev_body: Option<&Hir> = None;

    for sub in subs {
        match unbounded_repetition_body(sub) {
            Some(body) => {
                let overlaps_prev = prev_body.map(|p| bodies_overlap(p, body)).unwrap_or(false);
                run = if overlaps_prev { run + 1 } else { 1 };
                best_k = best_k.max(run);
                prev_body = Some(body);
            }
            None => {
                run = 0;
                prev_body = None;
            }
        }
    }

    if best_k >= 2 {
        ComplexityClass::Polynomial(best_k)
    } else {
        ComplexityClass::Linear
    }
}

/// If `hir` is an unbounded repetition, return its body.
fn unbounded_repetition_body(hir: &Hir) -> Option<&Hir> {
    match hir.kind() {
        HirKind::Repetition(rep) if is_unbounded(rep) => Some(&rep.sub),
        _ => None,
    }
}

/// A repetition that can pump unboundedly (`*`, `+`, `{n,}`).
fn is_unbounded(rep: &Repetition) -> bool {
    rep.max.is_none()
}

/// Do two repetition bodies share any matchable first character?
///
/// Conservative: if either body's character set can't be determined, assume
/// overlap (favor flagging — precision is tuned against the corpus later).
fn bodies_overlap(a: &Hir, b: &Hir) -> bool {
    match (char_ranges(a), char_ranges(b)) {
        (Some(ra), Some(rb)) => ra
            .iter()
            .any(|&(a0, a1)| rb.iter().any(|&(b0, b1)| a0 <= b1 && b0 <= a1)),
        _ => true,
    }
}

/// The set of first characters a node can match, as inclusive ranges.
fn char_ranges(hir: &Hir) -> Option<Vec<(char, char)>> {
    match hir.kind() {
        HirKind::Literal(lit) => {
            let c = std::str::from_utf8(&lit.0).ok()?.chars().next()?;
            Some(vec![(c, c)])
        }
        HirKind::Class(Class::Unicode(cu)) => {
            Some(cu.iter().map(|r| (r.start(), r.end())).collect())
        }
        HirKind::Class(Class::Bytes(cb)) => Some(
            cb.iter()
                .map(|r| (r.start() as char, r.end() as char))
                .collect(),
        ),
        _ => None,
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
