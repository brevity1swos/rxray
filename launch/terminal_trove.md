# Terminal Trove Submission

Submit via https://terminaltrove.com/submit (curated form, no hard star bar;
rgx is already listed, so the channel is warm). Fields below map 1:1 to the
submission form; description fields respect the form's character limits.

## Basic Info

| Field | Value |
|-------|-------|
| Name | rxray |
| Website | https://docs.rs/rxray |
| Repository | https://github.com/brevity1swos/rxray |
| Tagline | Deterministic regex ReDoS complexity analysis for the terminal |

## Description

**What it is** (≤300)

> rxray is a deterministic ReDoS analyzer for the terminal. Given a regex and a target engine, it classifies the pattern's worst-case match complexity under backtracking semantics as linear, polynomial, or exponential — statically, without ever running the pattern. Pure Rust, one dependency, CLI or library.

**Core features** (≤300)

> Core analysis detects exponential blowup via a product automaton (sound and complete) and polynomial blowup via a triple product, with an exact polynomial degree. When a pattern is vulnerable, rxray synthesizes an attack string and verifies it actually triggers the backtracking with a step-counting matcher.

**Other features** (≤300)

> It runs as a CI gate with grep-like exit codes (0 ok, 1 vulnerable, 2 error) and a configurable --max-complexity threshold. A single dependency (regex-syntax), MSRV 1.74, and it ran clean across the full 37,000-pattern ReDoSHunter corpus. Backreferences and lookaround are out of scope (not NFA-representable).

**Who it's for** (≤250)

> rxray is for developers and security engineers who want to catch catastrophic-backtracking regexes before they ship — in code review or CI. Install with `cargo install rxray`; works as a terminal CLI and as an embeddable Rust library on Linux, macOS, and Windows.

## Technical Details — Image Preview

| Field | URL |
|-------|-----|
| PNG | https://raw.githubusercontent.com/brevity1swos/rxray/main/assets/preview.png |
| GIF | https://raw.githubusercontent.com/brevity1swos/rxray/main/assets/demo.gif |

## Categories (select all that apply)

- [x] **Data & Text** — primary fit (regex / text processing)
- [x] **DevOps & Infrastructure** — the CI-gate use case
- [ ] Operating Systems
- [ ] Databases
- [ ] Networking
- [ ] UI & Display
- [ ] General — optional, only if a broader net is wanted

There is no "Security" category in the form (rxray's sharpest angle), so
**Data & Text + DevOps & Infrastructure** is the best available mapping.
