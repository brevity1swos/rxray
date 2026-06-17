//! Hand-rolled Thompson NFA over character-labeled transitions.
//!
//! Built from the `regex-syntax` HIR. Used by the sound EDA/IDA analysis: a
//! char-labeled NFA (rather than `regex-automata`'s byte/look internal form)
//! keeps the product-automaton construction in [`crate::eda`] simple.
//!
//! Lookaround/anchors are treated as epsilon (conservative — they do not add
//! backtracking ambiguity in this model); backreferences are not representable
//! in an NFA and are handled upstream.

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
