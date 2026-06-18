//! `rxray` — command-line ReDoS complexity gate.
//!
//! ```text
//! rxray [--engine E] [--max-complexity LEVEL] [--attack [N]] <PATTERN>
//! ```
//!
//! `--max-complexity` (default `linear`): `linear` | `poly` | `poly:K` | `exp`.
//! Exit codes: 0 = within budget, 1 = exceeds (vulnerable), 2 = error/usage.
//! Reads `<PATTERN>` from the argument, or stdin if omitted.

use std::io::Read;
use std::process::ExitCode;

use rxray::{analyze, attack, AnalyzeError, ComplexityClass, Engine};

/// The maximum complexity allowed before exit code 1.
enum Threshold {
    Linear,
    Poly(u32), // allow up to O(n^k); None-degree poly allowed if k == u32::MAX
    Exp,
}

impl Threshold {
    fn exceeded_by(&self, c: ComplexityClass) -> bool {
        match (self, c) {
            (Threshold::Linear, ComplexityClass::Linear) => false,
            (Threshold::Linear, _) => true,
            (Threshold::Poly(_), ComplexityClass::Linear) => false,
            (Threshold::Poly(k), ComplexityClass::Polynomial(d)) => d > *k,
            (Threshold::Poly(_), ComplexityClass::Exponential) => true,
            (Threshold::Exp, _) => false,
        }
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(msg) => {
            eprintln!("rxray: {msg}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<ExitCode, String> {
    let mut engine = Engine::Pcre2;
    let mut threshold = Threshold::Linear;
    let mut want_attack: Option<u32> = None;
    let mut pattern: Option<String> = None;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--engine" | "-e" => {
                let v = args.next().ok_or("--engine needs a value")?;
                engine = parse_engine(&v)?;
            }
            "--max-complexity" | "-m" => {
                let v = args.next().ok_or("--max-complexity needs a value")?;
                threshold = parse_threshold(&v)?;
            }
            "--attack" | "-a" => {
                // Optional numeric argument; default 30.
                want_attack = Some(30);
            }
            "-h" | "--help" => {
                println!("usage: rxray [--engine E] [--max-complexity linear|poly|poly:K|exp] [--attack] <PATTERN>");
                return Ok(ExitCode::SUCCESS);
            }
            other if other.starts_with('-') => {
                return Err(format!("unknown option: {other}"));
            }
            other => {
                if pattern.is_some() {
                    return Err("multiple patterns given".into());
                }
                pattern = Some(other.to_string());
            }
        }
    }

    let pattern = match pattern {
        Some(p) => p,
        None => {
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .map_err(|e| e.to_string())?;
            let trimmed = buf.trim_end_matches('\n').to_string();
            if trimmed.is_empty() {
                return Err("no pattern (give an argument or pipe via stdin)".into());
            }
            trimmed
        }
    };

    match analyze(&pattern, engine) {
        Ok(report) => {
            println!("{:?}\t{}", report.worst, pattern);
            for f in &report.findings {
                println!("  - {}", f.explanation);
            }
            if let Some(an) = want_attack {
                if report.worst != ComplexityClass::Linear {
                    match attack(&pattern, engine, an) {
                        Some(a) => println!("  attack ({}x): {:?}", a.pumped_n, a.value),
                        None => println!("  attack: (none synthesized)"),
                    }
                }
            }
            if threshold.exceeded_by(report.worst) {
                Ok(ExitCode::from(1))
            } else {
                Ok(ExitCode::SUCCESS)
            }
        }
        Err(AnalyzeError::Parse(e)) => Err(format!("parse error: {e}")),
        Err(AnalyzeError::TooComplex { estimated_states }) => {
            Err(format!("too complex (~{estimated_states} states)"))
        }
    }
}

fn parse_engine(s: &str) -> Result<Engine, String> {
    Ok(match s.to_ascii_lowercase().as_str() {
        "rust" => Engine::RustRegex,
        "fancy" => Engine::FancyRegex,
        "pcre2" | "pcre" => Engine::Pcre2,
        "js" | "javascript" => Engine::JavaScript,
        "python" | "py" => Engine::Python,
        "java" => Engine::Java,
        "dotnet" | ".net" => Engine::DotNet,
        "php" => Engine::Php,
        "ruby" => Engine::Ruby,
        "go" => Engine::Go,
        other => return Err(format!("unknown engine: {other}")),
    })
}

fn parse_threshold(s: &str) -> Result<Threshold, String> {
    let s = s.to_ascii_lowercase();
    if s == "linear" || s == "lin" {
        Ok(Threshold::Linear)
    } else if s == "exp" || s == "exponential" {
        Ok(Threshold::Exp)
    } else if s == "poly" || s == "polynomial" {
        Ok(Threshold::Poly(u32::MAX))
    } else if let Some(k) = s.strip_prefix("poly:").or_else(|| s.strip_prefix("poly")) {
        k.parse::<u32>()
            .map(Threshold::Poly)
            .map_err(|_| format!("bad poly degree: {k}"))
    } else {
        Err(format!("bad --max-complexity: {s}"))
    }
}
