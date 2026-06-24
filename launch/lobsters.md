# Lobste.rs Submission

Requires an invite from an existing member.

## Title

rxray: deterministic ReDoS complexity analysis in Rust

## URL

https://github.com/brevity1swos/rxray

## Tags

`rust`, `security`

## Text (optional)

Static, no-execution classifier for a regex's worst-case backtracking complexity (linear / polynomial / exponential), with verified attack-string synthesis. Single-dependency Rust library + CI gate. Sound *and* complete exponential detection via product automaton; sound polynomial detection with an exact degree via the triple product. Honest about its limits — no backreferences/lookaround (not representable in an NFA).
