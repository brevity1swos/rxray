//! Hand-rolled Thompson NFA over character-labeled transitions.
//!
//! Built from the `regex-syntax` HIR. Used by the sound EDA/IDA analysis: a
//! char-labeled NFA (rather than `regex-automata`'s byte/look internal form)
//! keeps the product-automaton construction in [`crate::eda`] simple.
//!
//! Lookaround/anchors are treated as epsilon (conservative — they do not add
//! backtracking ambiguity in this model); backreferences are not representable
//! in an NFA and are handled upstream.

use std::collections::VecDeque;

use regex_syntax::hir::{Class, Hir, HirKind};

pub(crate) type StateId = usize;

/// An inclusive character range a transition can match.
pub(crate) type Ranges = Vec<(char, char)>;

#[derive(Default)]
pub(crate) struct State {
    /// Epsilon transitions (no input consumed).
    pub eps: Vec<StateId>,
    /// Labeled transitions: match a char in `ranges`, move to the target.
    pub moves: Vec<(Ranges, StateId)>,
}

pub(crate) struct Nfa {
    pub states: Vec<State>,
    pub start: StateId,
    pub accept: StateId,
}

impl Nfa {
    fn new_state(&mut self) -> StateId {
        self.states.push(State::default());
        self.states.len() - 1
    }
}

/// Upper-bound estimate of the NFA state count `build` would produce, so callers
/// can skip patterns whose bounded repetitions (`{1000}`, `.{255}`) would explode
/// the construction. Saturating — never overflows.
pub(crate) fn estimate_states(hir: &Hir) -> usize {
    match hir.kind() {
        HirKind::Empty | HirKind::Look(_) => 1,
        HirKind::Literal(lit) => lit.0.len().saturating_add(1),
        HirKind::Class(_) => 2,
        HirKind::Capture(cap) => estimate_states(&cap.sub),
        HirKind::Concat(subs) => subs
            .iter()
            .fold(1usize, |acc, s| acc.saturating_add(estimate_states(s))),
        HirKind::Alternation(subs) => subs
            .iter()
            .fold(2usize, |acc, s| acc.saturating_add(estimate_states(s))),
        HirKind::Repetition(rep) => {
            let body = estimate_states(&rep.sub);
            let copies = match rep.max {
                Some(m) => m as usize,
                None => rep.min as usize + 1,
            };
            body.saturating_mul(copies.max(1)).saturating_add(2)
        }
    }
}

/// Build a Thompson NFA from a parsed pattern.
pub(crate) fn build(hir: &Hir) -> Nfa {
    let mut nfa = Nfa {
        states: Vec::new(),
        start: 0,
        accept: 0,
    };
    let (start, accept) = nfa.build_frag(hir);
    nfa.start = start;
    nfa.accept = accept;
    nfa
}

impl Nfa {
    /// Build a Thompson fragment for `hir`, returning its `(start, accept)` states.
    fn build_frag(&mut self, hir: &Hir) -> (StateId, StateId) {
        match hir.kind() {
            HirKind::Empty | HirKind::Look(_) => {
                // Look (anchors/lookaround) is modeled as epsilon.
                let s = self.new_state();
                (s, s)
            }
            HirKind::Literal(lit) => self.build_literal(&lit.0),
            HirKind::Capture(cap) => self.build_frag(&cap.sub),
            HirKind::Concat(subs) => {
                let mut iter = subs.iter();
                let Some(first) = iter.next() else {
                    let s = self.new_state();
                    return (s, s);
                };
                let (start, mut acc) = self.build_frag(first);
                for sub in iter {
                    let (s, a) = self.build_frag(sub);
                    self.states[acc].eps.push(s);
                    acc = a;
                }
                (start, acc)
            }
            HirKind::Class(class) => {
                let start = self.new_state();
                let accept = self.new_state();
                self.states[start].moves.push((class_ranges(class), accept));
                (start, accept)
            }
            HirKind::Alternation(subs) => {
                let start = self.new_state();
                let accept = self.new_state();
                for sub in subs {
                    let (s, a) = self.build_frag(sub);
                    self.states[start].eps.push(s);
                    self.states[a].eps.push(accept);
                }
                (start, accept)
            }
            HirKind::Repetition(rep) => {
                let start = self.new_state();
                let mut cur = start;
                // `min` mandatory copies in sequence.
                for _ in 0..rep.min {
                    let (s, a) = self.build_frag(&rep.sub);
                    self.states[cur].eps.push(s);
                    cur = a;
                }
                let accept = self.new_state();
                match rep.max {
                    None => {
                        // Kleene-star tail: enter the loop or skip it.
                        let (s, a) = self.build_frag(&rep.sub);
                        self.states[cur].eps.push(s);
                        self.states[cur].eps.push(accept);
                        self.states[a].eps.push(s);
                        self.states[a].eps.push(accept);
                    }
                    Some(max) => {
                        // `max - min` skippable optional copies.
                        self.states[cur].eps.push(accept);
                        for _ in 0..(max - rep.min) {
                            let (s, a) = self.build_frag(&rep.sub);
                            self.states[cur].eps.push(s);
                            self.states[a].eps.push(accept);
                            cur = a;
                        }
                    }
                }
                (start, accept)
            }
        }
    }

    /// A chain of single-char transitions for a literal's bytes (decoded as UTF-8).
    fn build_literal(&mut self, bytes: &[u8]) -> (StateId, StateId) {
        let chars: Vec<char> = match std::str::from_utf8(bytes) {
            Ok(s) => s.chars().collect(),
            Err(_) => bytes.iter().map(|&b| b as char).collect(),
        };
        let start = self.new_state();
        let mut cur = start;
        for c in chars {
            let next = self.new_state();
            self.states[cur].moves.push((vec![(c, c)], next));
            cur = next;
        }
        (start, cur)
    }
}

/// The inclusive character ranges a character class matches.
fn class_ranges(class: &Class) -> Ranges {
    match class {
        Class::Unicode(cu) => cu.iter().map(|r| (r.start(), r.end())).collect(),
        Class::Bytes(cb) => cb
            .iter()
            .map(|r| (r.start() as char, r.end() as char))
            .collect(),
    }
}

// --- Shared automata helpers (used by the EDA/IDA product analyses) ---

/// Epsilon-closure of a single state. O(states + eps-edges) via a visited bitvec
/// (a `Vec::contains` here would make `epsfree_moves` O(n³)).
pub(crate) fn eclose(nfa: &Nfa, s: StateId) -> Vec<StateId> {
    let mut visited = vec![false; nfa.states.len()];
    let mut stack = vec![s];
    visited[s] = true;
    let mut out = vec![s];
    while let Some(x) = stack.pop() {
        for &t in &nfa.states[x].eps {
            if !visited[t] {
                visited[t] = true;
                out.push(t);
                stack.push(t);
            }
        }
    }
    out
}

/// Epsilon-free labeled moves per state (source-side epsilons folded in).
pub(crate) fn epsfree_moves(nfa: &Nfa) -> Vec<Vec<(Ranges, StateId)>> {
    (0..nfa.states.len())
        .map(|s| {
            let mut mv = Vec::new();
            for u in eclose(nfa, s) {
                for (r, v) in &nfa.states[u].moves {
                    mv.push((r.clone(), *v));
                }
            }
            mv
        })
        .collect()
}

/// Do two range sets share any character?
pub(crate) fn ranges_intersect(a: &Ranges, b: &Ranges) -> bool {
    a.iter()
        .any(|&(a0, a1)| b.iter().any(|&(b0, b1)| a0 <= b1 && b0 <= a1))
}

/// The intersection of two range sets (for three-way common-symbol checks).
pub(crate) fn intersect_ranges(a: &Ranges, b: &Ranges) -> Ranges {
    let mut out = Vec::new();
    for &(a0, a1) in a {
        for &(b0, b1) in b {
            let lo = a0.max(b0);
            let hi = a1.min(b1);
            if lo <= hi {
                out.push((lo, hi));
            }
        }
    }
    out
}

/// States reachable from `from` over epsilon + labeled transitions.
pub(crate) fn reach_forward(nfa: &Nfa, from: StateId) -> Vec<bool> {
    let mut seen = vec![false; nfa.states.len()];
    let mut queue = VecDeque::from([from]);
    seen[from] = true;
    while let Some(s) = queue.pop_front() {
        let targets = nfa.states[s]
            .eps
            .iter()
            .copied()
            .chain(nfa.states[s].moves.iter().map(|(_, t)| *t));
        for t in targets {
            if !seen[t] {
                seen[t] = true;
                queue.push_back(t);
            }
        }
    }
    seen
}

/// States that can reach `to` over epsilon + labeled transitions.
pub(crate) fn reach_backward(nfa: &Nfa, to: StateId) -> Vec<bool> {
    let n = nfa.states.len();
    let mut rev: Vec<Vec<StateId>> = vec![Vec::new(); n];
    for (s, st) in nfa.states.iter().enumerate() {
        for &t in &st.eps {
            rev[t].push(s);
        }
        for (_, t) in &st.moves {
            rev[*t].push(s);
        }
    }
    let mut seen = vec![false; n];
    let mut queue = VecDeque::from([to]);
    seen[to] = true;
    while let Some(s) = queue.pop_front() {
        for &p in &rev[s] {
            if !seen[p] {
                seen[p] = true;
                queue.push_back(p);
            }
        }
    }
    seen
}

#[cfg(test)]
impl Nfa {
    /// Whole-string NFA simulation (epsilon-closure powerset). Test-only.
    fn matches(&self, input: &str) -> bool {
        let mut current = self.epsilon_closure(vec![self.start]);
        for c in input.chars() {
            let mut next = Vec::new();
            for &s in &current {
                for (ranges, target) in &self.states[s].moves {
                    if ranges.iter().any(|&(lo, hi)| lo <= c && c <= hi) {
                        next.push(*target);
                    }
                }
            }
            current = self.epsilon_closure(next);
            if current.is_empty() {
                return false;
            }
        }
        current.contains(&self.accept)
    }

    fn epsilon_closure(&self, seeds: Vec<StateId>) -> Vec<StateId> {
        let mut stack = seeds.clone();
        let mut seen = seeds;
        while let Some(s) = stack.pop() {
            for &t in &self.states[s].eps {
                if !seen.contains(&t) {
                    seen.push(t);
                    stack.push(t);
                }
            }
        }
        seen
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nfa(pattern: &str) -> Nfa {
        build(&regex_syntax::parse(pattern).unwrap())
    }

    #[test]
    fn literal_concat_matches_exactly() {
        let n = nfa("abc");
        assert!(n.matches("abc"));
        assert!(!n.matches("abx"));
        assert!(!n.matches("ab"));
    }

    #[test]
    fn class_matches_any_member() {
        let n = nfa("[a-c]");
        assert!(n.matches("a"));
        assert!(n.matches("c"));
        assert!(!n.matches("d"));
    }

    #[test]
    fn alternation_matches_either_branch() {
        let n = nfa("a|bc");
        assert!(n.matches("a"));
        assert!(n.matches("bc"));
        assert!(!n.matches("b"));
    }

    #[test]
    fn star_matches_zero_or_more() {
        let n = nfa("a*");
        assert!(n.matches(""));
        assert!(n.matches("aaa"));
        assert!(!n.matches("b"));
    }

    #[test]
    fn plus_requires_at_least_one() {
        let n = nfa("a+");
        assert!(!n.matches(""));
        assert!(n.matches("a"));
        assert!(n.matches("aaa"));
    }

    #[test]
    fn optional_matches_zero_or_one() {
        let n = nfa("a?");
        assert!(n.matches(""));
        assert!(n.matches("a"));
        assert!(!n.matches("aa"));
    }

    #[test]
    fn bounded_repetition_respects_range() {
        let n = nfa("a{2,3}");
        assert!(!n.matches("a"));
        assert!(n.matches("aa"));
        assert!(n.matches("aaa"));
        assert!(!n.matches("aaaa"));
    }
}
