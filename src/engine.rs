//! Target regex engine model.
//!
//! The analysis runs on pattern structure under backtracking semantics; the
//! [`Engine`] selects (a) whether the engine backtracks at all, and (b) which
//! mitigations (atomic groups, possessive quantifiers) are available as repair
//! primitives. Engines that do not backtrack are linear by construction.

/// A regex engine rxray can analyze a pattern for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Engine {
    /// Rust `regex` crate — finite automata, linear time, no catastrophic backtracking.
    RustRegex,
    /// `fancy-regex` — backtracking; lookaround + backreferences.
    FancyRegex,
    /// PCRE2 — backtracking (default); atomic groups, possessive quantifiers.
    Pcre2,
    /// JavaScript `RegExp` — backtracking.
    JavaScript,
    /// Python `re` — backtracking.
    Python,
    /// Java `java.util.regex` — backtracking.
    Java,
    /// .NET `Regex` — backtracking by default (has an opt-in nonbacktracking mode).
    DotNet,
    /// PHP PCRE — backtracking.
    Php,
    /// Ruby `Onigmo` — backtracking.
    Ruby,
    /// Go `regexp` (RE2) — finite automata, linear time.
    Go,
}

/// What a given engine supports — gates analysis short-circuits and (later) repair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EngineCaps {
    /// If false, the engine is linear by construction → report `Linear`, skip analysis.
    pub backtracks: bool,
    /// `(?>...)` available as a repair primitive.
    pub atomic_groups: bool,
    /// `a++` (possessive) available as a repair primitive.
    pub possessive: bool,
    /// Backreferences supported → language may be non-regular → equivalence undecidable.
    pub backrefs: bool,
}

impl Engine {
    /// Capabilities for this engine.
    pub fn caps(self) -> EngineCaps {
        use Engine::*;
        match self {
            RustRegex | Go => EngineCaps {
                backtracks: false,
                atomic_groups: false,
                possessive: false,
                backrefs: false,
            },
            Pcre2 | Php => EngineCaps {
                backtracks: true,
                atomic_groups: true,
                possessive: true,
                backrefs: true,
            },
            FancyRegex => EngineCaps {
                backtracks: true,
                atomic_groups: true,
                possessive: true,
                backrefs: true,
            },
            JavaScript => EngineCaps {
                backtracks: true,
                atomic_groups: false,
                possessive: false,
                backrefs: true,
            },
            Python | Java | Ruby => EngineCaps {
                backtracks: true,
                atomic_groups: true,
                possessive: true,
                backrefs: true,
            },
            DotNet => EngineCaps {
                backtracks: true,
                atomic_groups: true,
                possessive: false,
                backrefs: true,
            },
        }
    }
}
