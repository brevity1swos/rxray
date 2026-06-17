//! rxray — deterministic regex worst-case complexity (ReDoS) analysis.
//!
//! Classifies a regex pattern's worst-case match complexity under *backtracking*
//! semantics as [`ComplexityClass::Linear`], [`ComplexityClass::Polynomial`], or
//! [`ComplexityClass::Exponential`], parameterized by the target [`Engine`].
//!
//! Phase 1 (current): structural ambiguity analysis on the `regex-syntax` HIR.
//! This is the first slice; the sound NFA-based EDA/IDA analysis (and the
//! corpus-validated precision/recall gate) is the remaining Phase 1 work.

mod ambiguity;
mod eda;
mod engine;
mod nfa;

pub use engine::Engine;

/// Worst-case match complexity of a pattern under backtracking semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComplexityClass {
    /// O(n) — no catastrophic backtracking possible.
    Linear,
    /// O(n^k) — `k` chained ambiguous structures (Infinite Degree of Ambiguity).
    Polynomial(u32),
    /// O(2^n) — nested ambiguity (Exponential Degree of Ambiguity).
    Exponential,
}

/// The kind of ambiguity a [`Finding`] identifies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmbiguityKind {
    /// Exponential Degree of Ambiguity (e.g. `(a+)+`).
    Eda,
    /// Infinite Degree of Ambiguity → polynomial (e.g. `a*a*`).
    Ida,
}

/// A single source of backtracking blowup located within a pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub class: ComplexityClass,
    pub kind: AmbiguityKind,
    pub explanation: String,
}

/// The result of [`analyze`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub engine: Engine,
    /// Worst complexity across all findings (`Linear` if none).
    pub worst: ComplexityClass,
    pub findings: Vec<Finding>,
}

/// Why [`analyze`] could not produce a report.
#[derive(Debug)]
pub enum AnalyzeError {
    /// The pattern did not parse as a regex. Boxed — `regex_syntax::Error` is large.
    Parse(Box<regex_syntax::Error>),
}

impl std::fmt::Display for AnalyzeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AnalyzeError::Parse(e) => write!(f, "pattern failed to parse: {e}"),
        }
    }
}

impl std::error::Error for AnalyzeError {}

/// Statically analyze `pattern`'s worst-case complexity for `engine`.
///
/// Pure and static: never executes the regex.
pub fn analyze(pattern: &str, engine: Engine) -> Result<Report, AnalyzeError> {
    let hir = regex_syntax::parse(pattern).map_err(|e| AnalyzeError::Parse(Box::new(e)))?;

    // Linear-by-construction engines (Rust regex, Go RE2) cannot backtrack —
    // no pattern is ReDoS-vulnerable on them (design invariant).
    if !engine.caps().backtracks {
        return Ok(Report {
            engine,
            worst: ComplexityClass::Linear,
            findings: Vec::new(),
        });
    }

    // Exponential ambiguity: sound product-automaton analysis.
    // Polynomial ambiguity: structural IDA heuristic (NFA-based IDA is pending).
    let nfa = nfa::build(&hir);
    let is_eda = eda::has_eda(&nfa) || ambiguity::has_empty_loop_eda(&hir);
    let findings = if is_eda {
        vec![Finding {
            class: ComplexityClass::Exponential,
            kind: AmbiguityKind::Eda,
            explanation: "two distinct match paths read the same pumpable input \
                (exponential backtracking)"
                .to_string(),
        }]
    } else {
        ambiguity::ida_findings(&hir)
    };
    let worst = ambiguity::worst(&findings);
    Ok(Report {
        engine,
        worst,
        findings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_quantifier_is_exponential() {
        let report = analyze("(a+)+", Engine::Pcre2).unwrap();
        assert_eq!(report.worst, ComplexityClass::Exponential);
    }

    #[test]
    fn adjacent_overlapping_stars_are_polynomial() {
        let report = analyze("a*a*", Engine::Pcre2).unwrap();
        assert_eq!(report.worst, ComplexityClass::Polynomial(2));
    }

    #[test]
    fn linear_engine_never_reports_redos() {
        // Rust regex / Go RE2 are linear by construction — even `(a+)+` is safe.
        let report = analyze("(a+)+", Engine::RustRegex).unwrap();
        assert_eq!(report.worst, ComplexityClass::Linear);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn eda_pattern_reports_an_eda_finding() {
        let report = analyze("(a+)+", Engine::Pcre2).unwrap();
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].kind, AmbiguityKind::Eda);
        assert_eq!(report.findings[0].class, ComplexityClass::Exponential);
    }

    #[test]
    fn ida_pattern_reports_an_ida_finding() {
        let report = analyze("a*a*", Engine::Pcre2).unwrap();
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].kind, AmbiguityKind::Ida);
    }

    // Precision guards: safe patterns must NOT be flagged (no false positives).

    #[test]
    fn plain_literal_is_linear() {
        let report = analyze("abc", Engine::Pcre2).unwrap();
        assert_eq!(report.worst, ComplexityClass::Linear);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn single_quantifier_is_linear() {
        assert_eq!(
            analyze("a+", Engine::Pcre2).unwrap().worst,
            ComplexityClass::Linear
        );
    }

    #[test]
    fn adjacent_disjoint_stars_are_linear() {
        // `a*b*` — adjacent but non-overlapping bodies: no IDA.
        assert_eq!(
            analyze("a*b*", Engine::Pcre2).unwrap().worst,
            ComplexityClass::Linear
        );
    }

    #[test]
    fn higher_degree_ida_counts_the_chain() {
        assert_eq!(
            analyze("a*a*a*", Engine::Pcre2).unwrap().worst,
            ComplexityClass::Polynomial(3)
        );
    }

    #[test]
    fn invalid_pattern_is_a_parse_error() {
        assert!(matches!(
            analyze("(", Engine::Pcre2),
            Err(AnalyzeError::Parse(_))
        ));
    }

    // Sound NFA-based EDA improves on the structural heuristic in both directions.

    #[test]
    fn overlapping_alternation_is_exponential() {
        // `(aa|a)+` — exponential but no nested repetition; structural missed it.
        let report = analyze("(aa|a)+", Engine::Pcre2).unwrap();
        assert_eq!(report.worst, ComplexityClass::Exponential);
        assert_eq!(report.findings[0].kind, AmbiguityKind::Eda);
    }

    #[test]
    fn nested_rep_needing_a_separator_is_not_exponential() {
        // `(ab+)+` — looks nested, but each outer iteration needs a fresh `a`,
        // so it is NOT exponential. Structural heuristic false-positived here.
        let report = analyze("(ab+)+", Engine::Pcre2).unwrap();
        assert_eq!(report.worst, ComplexityClass::Linear);
    }
}
