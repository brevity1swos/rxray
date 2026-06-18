//! Attack-string synthesis (Phase 2).
//!
//! For an exponential pattern, generate `pump^n + breaker` candidates and keep
//! only those *verified* to blow up: a backtracking step-counter (modelling a
//! real backtracking engine, since rxray's own NFA simulation is linear) must
//! exceed a catastrophic-step cap on a full-match attempt that fails.
//!
//! This slice covers EDA (exponential) attacks where the vulnerable loop is
//! reachable from the start via the pump itself — the common ReDoS shape.
//! Polynomial-degree attack synthesis and prefix reconstruction are follow-ups.

use std::collections::HashSet;

use regex_syntax::hir::{Class, Hir, HirKind};

use crate::nfa::Nfa;

/// A synthesized input that triggers catastrophic backtracking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttackString {
    /// The attack input.
    pub value: String,
    /// How many pump repetitions it contains.
    pub pumped_n: u32,
}

/// Steps above which a failed full-match attempt is deemed catastrophic.
const STEP_CAP: usize = 1_000_000;

/// Synthesize a verified attack of `n` pump repetitions, or `None` if no
/// candidate provably blows up.
pub(crate) fn synthesize(nfa: &Nfa, hir: &Hir, n: u32) -> Option<AttackString> {
    let alphabet = alphabet(hir);
    // Breakers: characters likely to fall outside the loop, forcing the
    // backtracking failure that triggers the blow-up.
    let breakers = ['\u{0}', '!', '\u{7f}', 'Z', '9'];
    for &pump in &alphabet {
        for &brk in &breakers {
            if brk == pump {
                continue;
            }
            let value: String = std::iter::repeat(pump)
                .take(n as usize)
                .chain(std::iter::once(brk))
                .collect();
            let chars: Vec<char> = value.chars().collect();
            let (matched, steps) = backtrack_steps(nfa, &chars, STEP_CAP);
            if !matched && steps >= STEP_CAP {
                return Some(AttackString { value, pumped_n: n });
            }
        }
    }
    None
}

/// Representative characters drawn from the pattern's literals and classes.
fn alphabet(hir: &Hir) -> Vec<char> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    collect_alphabet(hir, &mut out, &mut seen);
    out
}

fn collect_alphabet(hir: &Hir, out: &mut Vec<char>, seen: &mut HashSet<char>) {
    let mut push = |c: char, out: &mut Vec<char>| {
        if seen.insert(c) {
            out.push(c);
        }
    };
    match hir.kind() {
        HirKind::Literal(lit) => {
            if let Ok(s) = std::str::from_utf8(&lit.0) {
                if let Some(c) = s.chars().next() {
                    push(c, out);
                }
            }
        }
        HirKind::Class(Class::Unicode(cu)) => {
            if let Some(r) = cu.iter().next() {
                push(r.start(), out);
            }
        }
        HirKind::Class(Class::Bytes(cb)) => {
            if let Some(r) = cb.iter().next() {
                push(r.start() as char, out);
            }
        }
        HirKind::Repetition(rep) => collect_alphabet(&rep.sub, out, seen),
        HirKind::Capture(cap) => collect_alphabet(&cap.sub, out, seen),
        HirKind::Concat(subs) | HirKind::Alternation(subs) => {
            for s in subs {
                collect_alphabet(s, out, seen);
            }
        }
        HirKind::Empty | HirKind::Look(_) => {}
    }
}

/// Backtracking full-match step count (saturating at `cap`). Models a real
/// backtracking engine: tries alternatives in order, no memoization. An
/// epsilon-visited set per position prevents epsilon-loops without suppressing
/// the cross-position re-exploration that *is* the catastrophe.
fn backtrack_steps(nfa: &Nfa, input: &[char], cap: usize) -> (bool, usize) {
    let mut steps = 0usize;
    let mut eps_seen = HashSet::new();
    let matched = bt(nfa, nfa.start, 0, input, &mut steps, cap, &mut eps_seen);
    (matched, steps)
}

#[allow(clippy::too_many_arguments)]
fn bt(
    nfa: &Nfa,
    state: usize,
    pos: usize,
    input: &[char],
    steps: &mut usize,
    cap: usize,
    eps_seen: &mut HashSet<(usize, usize)>,
) -> bool {
    if *steps >= cap {
        return false;
    }
    *steps += 1;
    if state == nfa.accept && pos == input.len() {
        return true;
    }
    // Epsilon transitions — guarded against revisiting (state, pos).
    for &t in &nfa.states[state].eps {
        if eps_seen.insert((t, pos)) && bt(nfa, t, pos, input, steps, cap, eps_seen) {
            return true;
        }
        if *steps >= cap {
            return false;
        }
    }
    // Labeled transition — consuming a char clears the epsilon guard.
    if pos < input.len() {
        let c = input[pos];
        for (ranges, t) in &nfa.states[state].moves {
            if ranges.iter().any(|&(lo, hi)| lo <= c && c <= hi) {
                let mut fresh = HashSet::new();
                if bt(nfa, *t, pos + 1, input, steps, cap, &mut fresh) {
                    return true;
                }
                if *steps >= cap {
                    return false;
                }
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nfa::build;

    fn nfa(p: &str) -> Nfa {
        build(&regex_syntax::parse(p).unwrap())
    }

    #[test]
    fn synthesizes_verified_attack_for_eda() {
        let h = regex_syntax::parse("(a+)+$").unwrap();
        let atk = synthesize(&nfa("(a+)+$"), &h, 30).expect("attack");
        assert_eq!(atk.pumped_n, 30);
        // Re-confirm: the synthesized string blows up the backtracking matcher.
        let chars: Vec<char> = atk.value.chars().collect();
        let (matched, steps) = backtrack_steps(&nfa("(a+)+$"), &chars, STEP_CAP);
        assert!(!matched);
        assert!(steps >= STEP_CAP);
    }

    #[test]
    fn benign_input_does_not_blow_up() {
        // A safe pattern's matcher stays cheap on the same kind of input.
        let (_m, steps) = backtrack_steps(&nfa("a+$"), &['a'; 60], STEP_CAP);
        assert!(steps < STEP_CAP);
    }
}
