# rxray

Deterministic regex worst-case complexity (ReDoS) analysis. Given a pattern and
a target engine, `rxray` classifies its worst-case match complexity under
backtracking semantics as **linear**, **polynomial**, or **exponential** — no
LLM, no execution required.

> **Status: Phase 1, early.** This is the first working slice of a phased build
> (see the design spec). It currently detects the two canonical ambiguity
> signatures structurally on the `regex-syntax` HIR:
>
> - **EDA** (exponential) — an unbounded repetition nested in another, e.g. `(a+)+`
> - **IDA** (polynomial) — a run of *k* adjacent overlapping unbounded
>   repetitions, e.g. `a*a*` → `O(n²)`
>
> The sound NFA-based analysis and the corpus-validated precision/recall gate are
> the remaining Phase 1 work. Not yet published; API is unstable.

## Example

```rust
use rxray::{analyze, ComplexityClass, Engine};

let report = analyze("(a+)+", Engine::Pcre2).unwrap();
assert_eq!(report.worst, ComplexityClass::Exponential);

// Linear-by-construction engines (Rust regex, Go RE2) are never flagged.
let report = analyze("(a+)+", Engine::RustRegex).unwrap();
assert_eq!(report.worst, ComplexityClass::Linear);
```

## License

MIT — see `LICENSE`.
