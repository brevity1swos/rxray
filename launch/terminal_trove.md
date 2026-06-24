# Terminal Trove Submission

Submit via https://terminaltrove.com/submit (curated form, no hard star bar;
rgx is already listed, so the channel is warm).

| Field | Value |
|-------|-------|
| Tool name | rxray |
| Tagline | Deterministic regex ReDoS complexity analysis for the terminal |
| Repository | https://github.com/brevity1swos/rxray |
| Homepage / docs | https://docs.rs/rxray |
| Install | `cargo install rxray` |
| License | MIT |
| Maintainer | brevity1swos |
| Categories / tags | rust, security, regex, redos, cli, developer-tools |
| Demo | https://raw.githubusercontent.com/brevity1swos/rxray/main/assets/demo.gif |

## Short description

rxray tells you a regex's worst-case match complexity — linear, polynomial, or
exponential — without running it. It detects ReDoS-vulnerable patterns
statically and can synthesize a verified attack string that triggers the
backtracking.

## Longer description

rxray is a pure-Rust CLI and library that classifies the worst-case
backtracking complexity of a regular expression. It builds a Thompson NFA from
the pattern and looks for ambiguity structurally: exponential blowup via the
product automaton (sound *and* complete), and polynomial blowup via the triple
product, with an exact polynomial degree. When a pattern is flagged, rxray can
produce an attack string and verify it actually triggers the backtracking with
a step-counting matcher.

It works as a CI gate with grep-like exit codes (`0` ok / `1` vulnerable / `2`
error) and a `--max-complexity` threshold, has a single dependency
(`regex-syntax`), and ran clean across the 37k-pattern ReDoSHunter corpus.
Backreferences and lookaround aren't analyzed (not representable in an NFA).
