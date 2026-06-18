//! Attack-string synthesis (Phase 2).
//!
//! For a vulnerable pattern, generate `prefix + pump^n + breaker` candidates and
//! keep only those *verified* to cause super-linear backtracking. A backtracking
//! step-counter (modelling a real backtracking engine — rxray's own NFA
//! simulation is linear) is the oracle:
//! - exponential ⇒ a failing full-match exceeds a step cap;
//! - polynomial ⇒ steps grow super-linearly from `n` to `2n`.
//!
//! The `prefix` is reconstructed by BFS from the start to a pumpable state, so
//! patterns whose vulnerable loop is not at the very start (e.g. `x(a+)+`) are
//! covered.

use std::collections::{HashMap, HashSet, VecDeque};

use regex_syntax::hir::{Class, Hir, HirKind};

use crate::nfa::{eclose, Nfa};

/// A synthesized input that triggers catastrophic backtracking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttackString {
    /// The attack input.
    pub value: String,
    /// How many pump repetitions it contains.
    pub pumped_n: u32,
}

/// Steps above which a failed full-match is deemed catastrophic (exponential).
const STEP_CAP: usize = 2_000_000;
/// Max pumpable states (by shortest prefix) to try, bounding synthesis cost.
const MAX_CANDIDATES: usize = 16;

/// Synthesize a verified attack of `n` pump repetitions, or `None`.
pub(crate) fn synthesize(nfa: &Nfa, hir: &Hir, n: u32) -> Option<AttackString> {
    let alphabet = alphabet(hir);
    let breakers = ['\u{0}', '!', '\u{7f}', 'Z', '9', ' '];
    for prefix in pumpable_prefixes(nfa) {
        for &pump in &alphabet {
            for &brk in &breakers {
                if brk == pump {
                    continue;
                }
                if let Some(atk) = verify(nfa, &prefix, pump, brk, n) {
                    return Some(atk);
                }
            }
        }
    }
    None
}

/// Build `prefix + pump^k + breaker` and return it if it provably blows up
/// (exponential: hits the step cap; or polynomial: super-linear `n`→`2n`).
fn verify(nfa: &Nfa, prefix: &str, pump: char, brk: char, n: u32) -> Option<AttackString> {
    let build = |k: u32| -> Vec<char> {
        prefix
            .chars()
            .chain(std::iter::repeat(pump).take(k as usize))
            .chain(std::iter::once(brk))
            .collect()
    };
    let at_n = build(n);
    let (matched, steps_n) = backtrack_steps(nfa, &at_n, STEP_CAP);
    if matched {
        return None; // a full match means no exhaustive backtrack — not an attack
    }
    let found = |chars: &[char]| {
        Some(AttackString {
            value: chars.iter().collect(),
            pumped_n: n,
        })
    };
    if steps_n >= STEP_CAP {
        return found(&at_n); // exponential
    }
    // Polynomial: super-linear growth from n to 2n.
    let (matched_2n, steps_2n) = backtrack_steps(nfa, &build(2 * n), STEP_CAP);
    if !matched_2n && steps_n > 50 && steps_2n > steps_n.saturating_mul(3) {
        return found(&at_n);
    }
    None
}

/// Shortest input prefixes (by length) that reach a *pumpable* state — one that
/// lies on a cycle consuming ≥1 character.
fn pumpable_prefixes(nfa: &Nfa) -> Vec<String> {
    let prefixes = shortest_prefixes(nfa);
    let mut entries: Vec<(usize, String)> = prefixes
        .into_iter()
        .filter(|(s, _)| is_pumpable(nfa, *s))
        .map(|(_, p)| (p.chars().count(), p))
        .collect();
    entries.sort_by_key(|(len, _)| *len);
    entries.dedup_by(|a, b| a.1 == b.1);
    entries
        .into_iter()
        .take(MAX_CANDIDATES)
        .map(|(_, p)| p)
        .collect()
}

/// Shortest consumed-input prefix to reach each state (BFS over labeled steps,
/// epsilon-closed at each layer).
fn shortest_prefixes(nfa: &Nfa) -> Vec<(usize, String)> {
    let mut best: HashMap<usize, String> = HashMap::new();
    let mut queue: VecDeque<(usize, String)> = VecDeque::new();
    for s in eclose(nfa, nfa.start) {
        if best.insert(s, String::new()).is_none() {
            queue.push_back((s, String::new()));
        }
    }
    while let Some((s, prefix)) = queue.pop_front() {
        for (ranges, t) in &nfa.states[s].moves {
            let Some(&(lo, _)) = ranges.first() else {
                continue;
            };
            let mut next_prefix = prefix.clone();
            next_prefix.push(lo);
            for u in eclose(nfa, *t) {
                if let std::collections::hash_map::Entry::Vacant(e) = best.entry(u) {
                    e.insert(next_prefix.clone());
                    queue.push_back((u, next_prefix.clone()));
                }
            }
        }
    }
    best.into_iter().collect()
}

/// Is `m` on a cycle that consumes ≥1 character?
fn is_pumpable(nfa: &Nfa, m: usize) -> bool {
    let forward = reach(nfa, m);
    let backward = reach_rev(nfa, m);
    for (u, st) in nfa.states.iter().enumerate() {
        if !forward.contains(&u) {
            continue;
        }
        for (_, v) in &st.moves {
            if backward.contains(v) {
                return true; // u (reachable from m) --label--> v (can reach m)
            }
        }
    }
    false
}

/// States reachable from `s` (epsilon + labeled).
fn reach(nfa: &Nfa, s: usize) -> HashSet<usize> {
    let mut seen = HashSet::from([s]);
    let mut queue = VecDeque::from([s]);
    while let Some(x) = queue.pop_front() {
        let next = nfa.states[x]
            .eps
            .iter()
            .copied()
            .chain(nfa.states[x].moves.iter().map(|(_, t)| *t));
        for t in next {
            if seen.insert(t) {
                queue.push_back(t);
            }
        }
    }
    seen
}

/// States that can reach `s` (epsilon + labeled).
fn reach_rev(nfa: &Nfa, s: usize) -> HashSet<usize> {
    let n = nfa.states.len();
    let mut rev: Vec<Vec<usize>> = vec![Vec::new(); n];
    for (a, st) in nfa.states.iter().enumerate() {
        for &t in &st.eps {
            rev[t].push(a);
        }
        for (_, t) in &st.moves {
            rev[*t].push(a);
        }
    }
    let mut seen = HashSet::from([s]);
    let mut queue = VecDeque::from([s]);
    while let Some(x) = queue.pop_front() {
        for &a in &rev[x] {
            if seen.insert(a) {
                queue.push_back(a);
            }
        }
    }
    seen
}

/// Representative characters drawn from the pattern's literals and classes.
fn alphabet(hir: &Hir) -> Vec<char> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    collect_alphabet(hir, &mut out, &mut seen);
    out
}

fn collect_alphabet(hir: &Hir, out: &mut Vec<char>, seen: &mut HashSet<char>) {
    match hir.kind() {
        HirKind::Literal(lit) => {
            if let Ok(s) = std::str::from_utf8(&lit.0) {
                if let Some(c) = s.chars().next() {
                    if seen.insert(c) {
                        out.push(c);
                    }
                }
            }
        }
        HirKind::Class(Class::Unicode(cu)) => {
            if let Some(r) = cu.iter().next() {
                if seen.insert(r.start()) {
                    out.push(r.start());
                }
            }
        }
        HirKind::Class(Class::Bytes(cb)) => {
            if let Some(r) = cb.iter().next() {
                let c = r.start() as char;
                if seen.insert(c) {
                    out.push(c);
                }
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
    for &t in &nfa.states[state].eps {
        if eps_seen.insert((t, pos)) && bt(nfa, t, pos, input, steps, cap, eps_seen) {
            return true;
        }
        if *steps >= cap {
            return false;
        }
    }
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

    fn synth(p: &str, n: u32) -> Option<AttackString> {
        synthesize(&nfa(p), &regex_syntax::parse(p).unwrap(), n)
    }

    #[test]
    fn synthesizes_verified_attack_for_eda() {
        let atk = synth("(a+)+$", 30).expect("attack");
        assert_eq!(atk.pumped_n, 30);
        let chars: Vec<char> = atk.value.chars().collect();
        let (matched, steps) = backtrack_steps(&nfa("(a+)+$"), &chars, STEP_CAP);
        assert!(!matched && steps >= STEP_CAP);
    }

    #[test]
    fn synthesizes_attack_with_prefix() {
        // Vulnerable loop is not at the start — needs a reconstructed prefix.
        let atk = synth("x(a+)+$", 30).expect("attack with prefix");
        assert!(atk.value.starts_with('x'));
    }

    #[test]
    fn synthesizes_attack_for_polynomial() {
        // Quadratic: validated by super-linear growth, not by hitting the cap.
        let atk = synth("a*a*$", 40).expect("polynomial attack");
        assert!(atk.value.contains("aaaa"));
    }

    #[test]
    fn no_attack_for_safe_pattern() {
        assert!(synth("a+$", 40).is_none());
        assert!(synth("abc$", 40).is_none());
    }
}
