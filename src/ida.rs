//! Sound IDA (polynomial / Infinite Degree of Ambiguity) detection via the
//! triple product automaton.
//!
//! IDA of degree ≥ 1 (super-linear / polynomial backtracking) exists iff there
//! are states `p ≠ q` and a non-empty string `v` with
//!   `p →v→ p`,  `p →v→ q`,  `q →v→ q`.
//! In the triple product `A³` this is a non-empty path `(p,p,q) → (p,q,q)`
//! (Allauzen–Mohri–Rastogi; Weideman). We restrict `p` to states reachable from
//! the start and `q` to states that reach an accept, so dead sub-automata cannot
//! produce false positives.
//!
//! Detection only — the *degree* of the polynomial is still estimated
//! structurally (see [`crate::ambiguity`]); sound degree computation is pending.

use std::collections::{HashSet, VecDeque};

use crate::nfa::{epsfree_moves, intersect_ranges, ranges_intersect, Nfa};

/// A safety cap on triple-product exploration (keeps large patterns bounded;
/// hitting it returns `false` — sound, never a false positive).
const VISIT_CAP: usize = 2_000_000;

/// Above this NFA size the triple product (O(n³) nodes) is too expensive; bail
/// out and return `false`. Fail-safe (no false positives), documented limit.
const MAX_STATES: usize = 600;

/// The polynomial degree of ambiguity (matching-time exponent), if `nfa` has IDA.
///
/// `None` ⇒ no super-linear ambiguity (linear). `Some(k)` ⇒ worst-case O(nᵏ),
/// `k ≥ 2`. The degree is `da + 1` where `da` is the longest chain of IDA-pairs
/// (Allauzen–Mohri–Rastogi): a graph edge `p→q` for each IDA-pair `(p,q)`, and
/// `da` = longest path (in edges). Exact within the size/budget bounds; a
/// budget cutout can only *under*-report the degree, never over-report.
pub(crate) fn polynomial_degree(nfa: &Nfa) -> Option<u32> {
    let pairs = ida_pairs(nfa);
    if pairs.is_empty() {
        return None;
    }
    Some(longest_chain(&pairs) + 1)
}

/// All IDA-pairs `(p, q)`: `p ≠ q`, both trim, with `(p,p,q) →⁺ (p,q,q)` in `A³`.
fn ida_pairs(nfa: &Nfa) -> Vec<(usize, usize)> {
    let n = nfa.states.len();
    if n == 0 || n > MAX_STATES {
        return Vec::new();
    }
    let epsfree = epsfree_moves(nfa);
    let from_start = reachable_from_start(nfa);
    let to_accept = reaches_accept(nfa);

    let node = |a: usize, b: usize, c: usize| (a * n + b) * n + c;
    let mut budget = VISIT_CAP;
    let mut pairs = Vec::new();

    for (p, &p_ok) in from_start.iter().enumerate() {
        if !p_ok {
            continue;
        }
        for (q, &q_ok) in to_accept.iter().enumerate() {
            if p == q || !q_ok {
                continue;
            }
            if triple_reaches(
                &epsfree,
                n,
                &node,
                node(p, p, q),
                node(p, q, q),
                &mut budget,
            ) {
                pairs.push((p, q));
            }
        }
    }
    pairs
}

/// Longest path (in edges) in the directed graph whose edges are the IDA-pairs.
/// Memoized DFS; cycles (which would imply EDA, handled upstream) are capped.
fn longest_chain(pairs: &[(usize, usize)]) -> u32 {
    let mut adj: std::collections::HashMap<usize, Vec<usize>> = std::collections::HashMap::new();
    for &(p, q) in pairs {
        adj.entry(p).or_default().push(q);
    }
    let mut memo: std::collections::HashMap<usize, u32> = std::collections::HashMap::new();
    let mut on_stack: HashSet<usize> = HashSet::new();
    let nodes: HashSet<usize> = pairs.iter().flat_map(|&(p, q)| [p, q]).collect();
    nodes
        .iter()
        .map(|&s| longest_from(s, &adj, &mut memo, &mut on_stack))
        .max()
        .unwrap_or(0)
}

fn longest_from(
    s: usize,
    adj: &std::collections::HashMap<usize, Vec<usize>>,
    memo: &mut std::collections::HashMap<usize, u32>,
    on_stack: &mut HashSet<usize>,
) -> u32 {
    if let Some(&v) = memo.get(&s) {
        return v;
    }
    if !on_stack.insert(s) {
        return 0; // cycle guard (anomalous: would mean EDA)
    }
    let best = adj
        .get(&s)
        .into_iter()
        .flatten()
        .map(|&t| 1 + longest_from(t, adj, memo, on_stack))
        .max()
        .unwrap_or(0);
    on_stack.remove(&s);
    memo.insert(s, best);
    best
}

/// Is `target` reachable from `start` (via ≥1 edge) in the triple product?
fn triple_reaches(
    epsfree: &[Vec<(crate::nfa::Ranges, usize)>],
    n: usize,
    node: &impl Fn(usize, usize, usize) -> usize,
    start: usize,
    target: usize,
    budget: &mut usize,
) -> bool {
    let mut seen: HashSet<usize> = HashSet::from([start]);
    let mut queue: VecDeque<usize> = VecDeque::from([start]);
    while let Some(cur) = queue.pop_front() {
        let (a, b, c) = (cur / (n * n), (cur / n) % n, cur % n);
        for (r1, a2) in &epsfree[a] {
            for (r2, b2) in &epsfree[b] {
                if *budget == 0 {
                    return false; // give up safely (bounds inner work)
                }
                *budget -= 1;
                let r12 = intersect_ranges(r1, r2);
                if r12.is_empty() {
                    continue;
                }
                for (r3, c2) in &epsfree[c] {
                    if *budget == 0 {
                        return false;
                    }
                    *budget -= 1;
                    if !ranges_intersect(&r12, r3) {
                        continue; // all three must read a common symbol
                    }
                    let next = node(*a2, *b2, *c2);
                    if next == target {
                        return true;
                    }
                    if seen.insert(next) {
                        queue.push_back(next);
                    }
                }
            }
        }
    }
    false
}

/// States reachable from the start (over epsilon + labeled transitions).
fn reachable_from_start(nfa: &Nfa) -> Vec<bool> {
    let mut seen = vec![false; nfa.states.len()];
    let mut queue = VecDeque::from([nfa.start]);
    seen[nfa.start] = true;
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

/// States that can reach the accept state (over epsilon + labeled transitions).
fn reaches_accept(nfa: &Nfa) -> Vec<bool> {
    let n = nfa.states.len();
    let mut rev: Vec<Vec<usize>> = vec![Vec::new(); n];
    for (s, st) in nfa.states.iter().enumerate() {
        for &t in &st.eps {
            rev[t].push(s);
        }
        for (_, t) in &st.moves {
            rev[*t].push(s);
        }
    }
    let mut seen = vec![false; n];
    let mut queue = VecDeque::from([nfa.accept]);
    seen[nfa.accept] = true;
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
mod tests {
    use super::*;
    use crate::nfa::build;

    fn ida(pattern: &str) -> bool {
        polynomial_degree(&build(&regex_syntax::parse(pattern).unwrap())).is_some()
    }

    fn degree(pattern: &str) -> Option<u32> {
        polynomial_degree(&build(&regex_syntax::parse(pattern).unwrap()))
    }

    #[test]
    fn polynomial_degree_ladder() {
        // k adjacent overlapping stars → O(n^k): the decisive exactness check.
        assert_eq!(degree("a*a*"), Some(2));
        assert_eq!(degree("a*a*a*"), Some(3));
        assert_eq!(degree("a*a*a*a*"), Some(4));
        assert_eq!(degree("a*a*a*a*a*"), Some(5));
    }

    #[test]
    fn linear_has_no_degree() {
        assert_eq!(degree("a*b*"), None);
        assert_eq!(degree("a+"), None);
        assert_eq!(degree("(ab)+"), None);
    }

    #[test]
    fn adjacent_overlapping_stars_have_ida() {
        assert!(ida("a*a*"));
    }

    #[test]
    fn non_adjacent_reps_have_ida() {
        // Separated by `-?` — the structural heuristic misses this; the triple
        // product catches it (a run of digits splits across the two `\d*`).
        assert!(ida(r"\d*-?\d*"));
    }

    #[test]
    fn linear_patterns_have_no_ida() {
        assert!(!ida("a*b*")); // disjoint
        assert!(!ida("a+")); // single loop
        assert!(!ida("abc")); // no loop
        assert!(!ida("(ab)+")); // unambiguous loop
    }
}
