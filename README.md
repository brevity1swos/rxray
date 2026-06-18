# rxray

Deterministic regex worst-case complexity (ReDoS) analysis. Given a pattern and
a target engine, `rxray` classifies its worst-case match complexity under
backtracking semantics as **linear**, **polynomial**, or **exponential** — no
LLM, no execution required.

> **Status: Phase 1.** Sound NFA-based ambiguity analysis over a hand-rolled
> Thompson NFA built from the `regex-syntax` HIR:
>
> - **EDA** (exponential) — detected via the product automaton `A×A`: a diagonal
>   state on a cycle through an off-diagonal state. Sound **and** complete for
>   exponential ambiguity. Catches e.g. `(a+)+`, `(aa|a)+`, `(a*)*`.
> - **IDA** (polynomial) — detected via the triple product `A³`
>   (`(p,p,q)→(p,q,q)`). Sound detection; the polynomial *degree* is still a
>   structural estimate (≥2).
>
> Not yet published; API is unstable.

## Known limitations

- **Dialect**: backreferences and lookaround are not representable in an NFA and
  Rust's `regex-syntax` rejects them, so such patterns return
  `AnalyzeError::Parse`. (~8% of a real-world corpus.) Supporting them needs a
  different front end — future work.
- **ASCII analysis**: patterns are parsed in ASCII mode (`unicode(false)`).
  Ambiguity is *structural*, so verdicts are identical to Unicode mode, but the
  analyzed character sets are ASCII.
- **Parser normalization**: analysis reflects `regex-syntax`'s normalization
  (e.g. it collapses `a|a → a`), which can differ from another engine's own
  parser — a pattern exponential on a naive backtracker may be reported safe if
  the parser simplifies the ambiguity away.
- **IDA degree** is an estimate; the vulnerable/safe verdict is sound, the
  `Polynomial(k)` exponent may not be exact.
- **Size**: patterns whose expanded NFA would be huge (large bounded reps like
  `{1000}`) return `AnalyzeError::TooComplex` rather than being analyzed.

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
