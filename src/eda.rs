//! Sound EDA (Exponential Degree of Ambiguity) detection via the product NFA.
//!
//! Build the product `A × A` over epsilon-free, character-labeled moves: from a
//! pair `(p, q)` there is an edge to `(p', q')` when both copies can read some
//! common symbol (`p --R1--> p'`, `q --R2--> q'`, `R1 ∩ R2 ≠ ∅`).
//!
//! A pattern has EDA iff, reachable from `(start, start)`, some diagonal state
//! `(m, m)` lies on a cycle that passes through an off-diagonal state `(p, q)`
//! with `p ≠ q` — i.e. two *distinct* paths read the same pumpable string
//! `m → m`. Equivalently: a diagonal node and an off-diagonal node are mutually
//! reachable.

use std::collections::{HashMap, HashSet, VecDeque};

use crate::nfa::{epsfree_moves, ranges_intersect, Nfa};

/// Above this NFA size the product (O(n²) nodes) is too expensive; bail out.
/// Fail-safe (no false positives), documented limit.
const MAX_STATES: usize = 1000;

/// Total node-visit budget across the analysis; exhausting it returns `false`
/// (fail-safe). The per-diagonal reachability is worst-case O(n³); a future
/// SCC pass (EDA iff an SCC mixes a diagonal and an off-diagonal node) removes
/// this bound.
const VISIT_CAP: usize = 5_000_000;

/// Does `nfa` exhibit exponential-degree ambiguity (exponential backtracking)?
pub(crate) fn has_eda(nfa: &Nfa) -> bool {
    let n = nfa.states.len();
    if n == 0 || n > MAX_STATES {
        return false;
    }

    let epsfree = epsfree_moves(nfa);
    let node = |p: usize, q: usize| p * n + q;
    let start = node(nfa.start, nfa.start);
    let mut budget = VISIT_CAP;

    // BFS the product graph from (start, start), recording both directions.
    let mut fwd: HashMap<usize, Vec<usize>> = HashMap::new();
    let mut rev: HashMap<usize, Vec<usize>> = HashMap::new();
    let mut seen: HashSet<usize> = HashSet::from([start]);
    let mut queue: VecDeque<usize> = VecDeque::from([start]);
    while let Some(cur) = queue.pop_front() {
        if budget == 0 {
            return false; // give up safely
        }
        budget -= 1;
        let (p, q) = (cur / n, cur % n);
        for (r1, p2) in &epsfree[p] {
            for (r2, q2) in &epsfree[q] {
                if ranges_intersect(r1, r2) {
                    let next = node(*p2, *q2);
                    fwd.entry(cur).or_default().push(next);
                    rev.entry(next).or_default().push(cur);
                    if seen.insert(next) {
                        queue.push_back(next);
                    }
                }
            }
        }
    }

    // EDA iff a diagonal node lies on a cycle through an off-diagonal node:
    // some off-diagonal node is both reachable from and able to reach (m, m).
    let is_off_diagonal = |x: usize| x / n != x % n;
    for &d in seen.iter().filter(|&&x| x / n == x % n) {
        let forward = reach(&fwd, d, &mut budget);
        let backward = reach(&rev, d, &mut budget);
        if forward.intersection(&backward).any(|&x| is_off_diagonal(x)) {
            return true;
        }
        if budget == 0 {
            return false; // give up safely
        }
    }
    false
}

/// All nodes reachable from `from` via `adj` (inclusive of `from`), decrementing
/// the shared `budget` per node visited (stops early when exhausted).
fn reach(adj: &HashMap<usize, Vec<usize>>, from: usize, budget: &mut usize) -> HashSet<usize> {
    let mut seen: HashSet<usize> = HashSet::from([from]);
    let mut queue: VecDeque<usize> = VecDeque::from([from]);
    while let Some(cur) = queue.pop_front() {
        if *budget == 0 {
            break;
        }
        *budget -= 1;
        if let Some(succs) = adj.get(&cur) {
            for &next in succs {
                if seen.insert(next) {
                    queue.push_back(next);
                }
            }
        }
    }
    seen
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nfa::build;

    fn eda(pattern: &str) -> bool {
        has_eda(&build(&regex_syntax::parse(pattern).unwrap()))
    }

    #[test]
    fn nested_quantifier_has_eda() {
        assert!(eda("(a+)+"));
    }

    #[test]
    fn overlapping_alternation_plus_has_eda() {
        // `(aa|a)+` is exponential (a^n has exponentially many splits) but has
        // NO nested repetition — the structural heuristic misses it; the NFA
        // product catches it.
        assert!(eda("(aa|a)+"));
    }

    #[test]
    fn nested_rep_without_real_ambiguity_is_not_eda() {
        // `(ab+)+` LOOKS like nested unbounded repetition (structural heuristic
        // false-positives → "exponential"), but each outer iteration needs a
        // fresh `a`, so a run of `b`s cannot split — it is not EDA.
        assert!(!eda("(ab+)+"));
    }

    #[test]
    fn plain_star_is_not_eda() {
        assert!(!eda("a*"));
        assert!(!eda("a*a*")); // IDA (polynomial), not EDA
        assert!(!eda("abc"));
    }
}
