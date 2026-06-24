# rxray Launch Playbook

Step-by-step guidance for launching rxray — a deterministic ReDoS complexity
analyzer. rxray's framing is **security + Rust**, which sidesteps the
AI-content policies that close some channels to AI-built projects.

---

## Status (Updated 2026-06-24)

| Channel | Status | Notes |
|---------|--------|-------|
| crates.io | **Published** | `rxray` v0.1.0 |
| GitHub release | **Cut** | v0.1.0 with notes + demo GIF |
| CI + release-plz | **Live & green** | 3-OS test matrix + lint + MSRV; releases automated |
| Show HN | **Draft ready** | `show_hn.md` — post manually (best US weekday AM ET) |
| Lobste.rs | **Draft ready** | `lobsters.md` — needs an invite from a member |
| Terminal Trove | **Draft ready** | `terminal_trove.md` — submit via terminaltrove.com/submit |
| awesome-rust | **Deferred** | `awesome_rust_draft.md` — gated on >50★ OR >2000 dl bar |
| awesome-ratatui | **N/A** | rxray has no TUI; does not belong there |
| r/rust | **Closed** | AI-generated-projects policy — do not attempt |
| r/commandline | **Closed** | AI disclosure rules — do not attempt |

**Current metrics (2026-06-24):** 0 stars, 33 downloads, v0.1.0.

---

## Immediate Next Actions

### 1. Post Show HN
Use `show_hn.md`. ReDoS is a recurring HN topic; the deterministic +
verified-attack angle is the hook. Be ready to answer "how is this different
from recheck?" (recheck is hybrid static+fuzzing, JS-ecosystem; rxray is
native Rust, deterministic, embeddable).

### 2. Submit to Terminal Trove
Use `terminal_trove.md`. Curated form, no hard star bar; rgx is already listed
there, so the channel is warm.

### 3. Lobste.rs (if you have an invite)
Use `lobsters.md`, tags `rust` + `security`.

### 4. awesome-rust — WAIT for the bar
Do **not** submit until rxray clears **>50 stars OR >2000 downloads** (the
list's explicit CONTRIBUTING bar). Entry is pre-drafted in
`awesome_rust_draft.md`. Sync the stale brevity1swos/awesome-rust fork before
opening the PR.

---

## Positioning

rxray's niche is being **native, deterministic, and embeddable**: a
single-dependency Rust library + CLI with no JVM/Node/Python runtime, sound
*and* complete exponential detection, an exact polynomial degree, and verified
attack-string synthesis. Honest framing beats overclaiming on HN/lobste.rs —
point JS users to recheck; lead with the algorithmic novelty and the CI-gate
ergonomics (exit codes 0/1/2).

---

## Monitoring

```bash
# Stars
gh api repos/brevity1swos/rxray --jq '.stargazers_count'

# crates.io downloads
curl -s https://crates.io/api/v1/crates/rxray | jq '.crate | {downloads, recent_downloads}'

# Traffic referrers (requires auth)
gh api repos/brevity1swos/rxray/traffic/popular/referrers

# Open PRs and issues
gh pr list --repo brevity1swos/rxray
gh issue list --repo brevity1swos/rxray
```
