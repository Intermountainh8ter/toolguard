//! Model-free malformed-call repair-policy run.
//!
//! Synthetic shell-and-filesystem calls are valid or near-valid in one of four
//! ways. A strict policy rejects every malformed call, an author-written
//! permissive repair policy coerces, drops or defaults its way to execution,
//! and a retry-once-then-strict policy resends once (deterministic
//! malformations cannot change) and then rejects. No model is called.

use rand::{Rng, SeedableRng};
use rand_pcg::Pcg64Mcg;
use serde_json::{json, Value};

pub const KINDS: [&str; 4] =
    ["string_for_integer", "extra_unknown_arg", "missing_required_arg", "wrong_case_tool_name"];
pub const VALID_SHARE: f64 = 0.2;
/// Share of string-for-integer values that parse as an integer and so can be coerced.
pub const COERCIBLE_P: f64 = 0.7;

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Call {
    Valid,
    Malformed { kind: usize, coercible: bool },
}

pub fn gen_calls(n: usize, seed: u64) -> Vec<Call> {
    let mut rng = Pcg64Mcg::seed_from_u64(seed);
    (0..n)
        .map(|_| {
            if rng.gen_bool(VALID_SHARE) {
                Call::Valid
            } else {
                Call::Malformed { kind: rng.gen_range(0..4), coercible: rng.gen_bool(COERCIBLE_P) }
            }
        })
        .collect()
}

pub fn strict_executes(c: Call) -> bool {
    c == Call::Valid
}

pub fn permissive_executes(c: Call) -> bool {
    match c {
        Call::Valid => true,
        Call::Malformed { kind: 0, coercible } => coercible,
        Call::Malformed { .. } => true,
    }
}

pub fn retry_then_strict_executes(c: Call) -> bool {
    strict_executes(c)
}

pub fn run(n: usize, seed: u64) -> Value {
    let calls = gen_calls(n, seed);
    let valid = calls.iter().filter(|c| **c == Call::Valid).count();
    let malformed = n - valid;
    let rate = |k: usize, d: usize| if d == 0 { 0.0 } else { k as f64 / d as f64 };
    let policies: [(&str, fn(Call) -> bool); 3] = [
        ("strict", strict_executes),
        ("permissive", permissive_executes),
        ("retry_then_strict", retry_then_strict_executes),
    ];
    let mut out = serde_json::Map::new();
    for (name, f) in policies {
        let exec_mal = calls.iter().filter(|c| **c != Call::Valid && f(**c)).count();
        let rec_valid = calls.iter().filter(|c| **c == Call::Valid && f(**c)).count();
        let mut by_kind = serde_json::Map::new();
        for (k, kn) in KINDS.iter().enumerate() {
            let tot = calls.iter().filter(|c| matches!(c, Call::Malformed { kind, .. } if *kind == k)).count();
            let ex = calls
                .iter()
                .filter(|c| matches!(c, Call::Malformed { kind, .. } if *kind == k) && f(**c))
                .count();
            by_kind.insert(kn.to_string(), json!({"malformed": tot, "executed": ex, "executed_rate": rate(ex, tot)}));
        }
        out.insert(
            name.to_string(),
            json!({
                "executed_malformed": exec_mal,
                "executed_malformed_rate": rate(exec_mal, malformed),
                "valid_executed": rec_valid,
                "valid_false_reject_rate": 1.0 - rate(rec_valid, valid),
                "by_kind": by_kind,
            }),
        );
    }
    json!({
        "schema": "toolguard.repairpolicy/1",
        "n": n,
        "valid": valid,
        "malformed": malformed,
        "valid_share": VALID_SHARE,
        "coercible_probability": COERCIBLE_P,
        "policies": out,
    })
}

pub fn write_report(n: usize, seed: u64, out: &std::path::Path) -> anyhow::Result<()> {
    let started_at = crate::scanner::utc_now();
    let t0 = std::time::Instant::now();
    let mut report = run(n, seed);
    report["provenance"] = json!({
        "started_at": started_at,
        "seeds": [seed],
        "command": format!("cargo run --locked -q --release -- repairpolicy --seed {seed} --n {n} --out {}", out.display()),
        "hardware": format!("{} {} cpu, no gpu", std::env::consts::OS, std::env::consts::ARCH),
        "wall_s": t0.elapsed().as_secs_f64(),
        "data_sources": [{"url": "synthetic: seeded generator, author-written malformations", "license": "MIT"}],
    });
    if let Some(dir) = out.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(out, serde_json::to_string_pretty(&report)? + "\n")?;
    println!("wrote {}", out.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_executes_no_malformed_and_rejects_no_valid() {
        let r = run(2000, 7);
        assert_eq!(r["policies"]["strict"]["executed_malformed"], 0);
        assert_eq!(r["policies"]["strict"]["valid_false_reject_rate"], 0.0);
    }

    #[test]
    fn permissive_executes_malformed() {
        let r = run(2000, 7);
        assert!(r["policies"]["permissive"]["executed_malformed_rate"].as_f64().unwrap() >= 0.5);
        assert_eq!(r["policies"]["retry_then_strict"]["executed_malformed"], 0);
    }

    #[test]
    fn seeded_repeatable() {
        assert_eq!(run(300, 7), run(300, 7));
    }
}
