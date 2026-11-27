//! Model-free retry-policy floor.
//!
//! Synthetic tool calls fail with one injected error. Deterministic schema
//! errors repeat on every identical resend; a transient timeout clears with a
//! fixed probability per attempt. A never-retry policy and a bounded
//! identical-resend policy are scored on recovery rate per error type. No
//! model is called.

use rand::{Rng, SeedableRng};
use rand_pcg::Pcg64Mcg;
use serde_json::{json, Value};

pub const ERROR_TYPES: [&str; 4] =
    ["missing_required_arg", "wrong_arg_type", "unknown_tool", "transient_timeout"];
pub const TRANSIENT_CLEAR_P: f64 = 0.5;
pub const MAX_RETRIES: usize = 3;

fn is_transient(t: usize) -> bool {
    ERROR_TYPES[t] == "transient_timeout"
}

/// Bounded identical-resend: true when some resend succeeds.
pub fn bounded_resend(t: usize, rng: &mut Pcg64Mcg) -> bool {
    (0..MAX_RETRIES).any(|_| is_transient(t) && rng.gen_bool(TRANSIENT_CLEAR_P))
}

pub fn run(n: usize, seed: u64) -> Value {
    let mut rng = Pcg64Mcg::seed_from_u64(seed);
    let mut count = [0usize; 4];
    let mut rec = [0usize; 4];
    for _ in 0..n {
        let t = rng.gen_range(0..4);
        count[t] += 1;
        if bounded_resend(t, &mut rng) {
            rec[t] += 1;
        }
    }
    let r = |k: usize, d: usize| if d == 0 { 0.0 } else { k as f64 / d as f64 };
    let mut by_type = serde_json::Map::new();
    for (i, name) in ERROR_TYPES.iter().enumerate() {
        by_type.insert(
            name.to_string(),
            json!({
                "injected": count[i],
                "never_retry_recovered": 0,
                "bounded_recovered": rec[i],
                "bounded_recovery_rate": r(rec[i], count[i]),
            }),
        );
    }
    let total_rec: usize = rec.iter().sum();
    let det_rec: usize = (0..4).filter(|&i| !is_transient(i)).map(|i| rec[i]).sum();
    json!({
        "schema": "toolguard.retryfloor/1",
        "n": n,
        "max_retries": MAX_RETRIES,
        "transient_clear_probability": TRANSIENT_CLEAR_P,
        "retry_floor": {
            "recovery_rate_never_retry": 0.0,
            "recovery_rate_bounded": r(total_rec, n),
            "deterministic_recovered": det_rec,
            "by_type": by_type,
        },
    })
}

pub fn write_report(n: usize, seed: u64, out: &std::path::Path) -> anyhow::Result<()> {
    let started_at = crate::scanner::utc_now();
    let t0 = std::time::Instant::now();
    let mut report = run(n, seed);
    report["provenance"] = json!({
        "started_at": started_at,
        "seeds": [seed],
        "command": format!("cargo run --locked -q --release -- retryfloor --seed {seed} --n {n} --out {}", out.display()),
        "hardware": format!("{} {} cpu, no gpu", std::env::consts::OS, std::env::consts::ARCH),
        "wall_s": t0.elapsed().as_secs_f64(),
        "data_sources": [{"url": "synthetic: seeded generator, author-written errors", "license": "MIT"}],
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
    fn deterministic_errors_never_recover() {
        let r = run(2000, 7);
        assert_eq!(r["retry_floor"]["deterministic_recovered"], 0);
    }

    #[test]
    fn bounded_beats_never() {
        let r = run(2000, 7);
        assert!(r["retry_floor"]["recovery_rate_bounded"].as_f64().unwrap() > 0.0);
        assert_eq!(r["retry_floor"]["recovery_rate_never_retry"], 0.0);
    }

    #[test]
    fn seeded_repeatable() {
        assert_eq!(run(300, 7), run(300, 7));
    }
}
