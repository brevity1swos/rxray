//! External-corpus harness (ignored by default — needs a downloaded dataset).
//!
//! Run against a real corpus (one regex per line), e.g. ReDoSHunter's
//! `data/paper_dataset/regexlib.txt`:
//!
//! ```sh
//! RXRAY_CORPUS=/path/to/regexlib.txt \
//!   cargo test --test external_corpus -- --ignored --nocapture
//! ```
//!
//! These corpora are UNLABELED, so this reports parse-rate and flag-rate rather
//! than precision/recall — a scale smoke test over real-world patterns. Many
//! patterns use lookaround/backrefs that Rust's `regex-syntax` cannot parse;
//! those are counted separately (a dialect limitation, not a bug).

use rxray::{analyze, ComplexityClass, Engine};

fn html_unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

#[test]
#[ignore = "needs RXRAY_CORPUS pointing at a downloaded dataset"]
fn report_over_external_corpus() {
    let Ok(path) = std::env::var("RXRAY_CORPUS") else {
        eprintln!("RXRAY_CORPUS not set — skipping");
        return;
    };
    let text = std::fs::read_to_string(&path).expect("read corpus");
    let limit: usize = std::env::var("RXRAY_LIMIT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(usize::MAX);

    let (mut total, mut parsed, mut parse_err) = (0usize, 0usize, 0usize);
    let (mut exp, mut poly, mut lin) = (0usize, 0usize, 0usize);

    for line in text.lines().take(limit) {
        let pat = html_unescape(line.trim());
        if pat.is_empty() {
            continue;
        }
        total += 1;
        match analyze(&pat, Engine::Pcre2) {
            Ok(r) => {
                parsed += 1;
                match r.worst {
                    ComplexityClass::Exponential => exp += 1,
                    ComplexityClass::Polynomial(_) => poly += 1,
                    ComplexityClass::Linear => lin += 1,
                }
            }
            Err(_) => parse_err += 1,
        }
    }

    let pct = |x: usize, d: usize| {
        if d == 0 {
            0.0
        } else {
            100.0 * x as f64 / d as f64
        }
    };
    eprintln!("=== rxray over {path} ===");
    eprintln!("patterns:      {total}");
    eprintln!("parsed:        {parsed} ({:.1}%)", pct(parsed, total));
    eprintln!(
        "parse errors:  {parse_err} ({:.1}%) — unsupported dialect (lookaround/backrefs)",
        pct(parse_err, total)
    );
    eprintln!("--- of parsed ---");
    eprintln!("exponential:   {exp} ({:.1}%)", pct(exp, parsed));
    eprintln!("polynomial:    {poly} ({:.1}%)", pct(poly, parsed));
    eprintln!("linear:        {lin} ({:.1}%)", pct(lin, parsed));
    eprintln!(
        "flagged vulnerable: {} ({:.1}% of parsed)",
        exp + poly,
        pct(exp + poly, parsed)
    );
}
