# Show HN Post

## Title

Show HN: rxray – deterministic ReDoS complexity analysis in Rust

## URL

https://github.com/brevity1swos/rxray

## Text

I built rxray to answer one question about a regex without running it: is its worst case linear, polynomial, or exponential under a backtracking engine?

It builds a Thompson NFA from the pattern and looks for ambiguity structurally — exponential blowup via the product automaton `A×A` (sound *and* complete), and polynomial blowup via the triple product `A³` with an exact degree. When it flags a pattern it can also synthesize an attack string and verify it actually triggers the backtracking with a step-counting matcher.

It's pure Rust with a single dependency (`regex-syntax`), works as a library or a CLI gate with exit codes (`0` ok / `1` vulnerable / `2` error), and ran clean across the 37k-pattern ReDoSHunter corpus.

It's deliberately narrow: backreferences and lookaround aren't representable in an NFA, so those patterns aren't analyzed (~8% of a real-world corpus). If you're in the JS ecosystem, recheck is more mature and does hybrid static+fuzzing. rxray's niche is being native, deterministic, and embeddable. Feedback welcome.

## Likely questions to prep

- **vs recheck?** recheck is hybrid (automaton + fuzzing), JS/Scala, the most mature option for the JS ecosystem. rxray is native Rust, fully deterministic, single-dependency, embeddable as a library, with exact polynomial degree.
- **vs regexploit?** regexploit (Python) is heuristic and great at attack generation; rxray's exponential detection is sound *and* complete and it runs as a library/CI gate.
- **Why no backrefs/lookaround?** Not representable in an NFA; `regex-syntax` rejects them. Supporting them needs a different front end (future work).
- **False positives?** A budget cutout can only *under*-report (lower degree / miss), never over-report — there are no false positives by construction.
