//! Model-free empty-argument run. A seeded degenerate caller emits a swept
//! share of Dangerous-tier calls with an empty argument. A gate with no
//! required argument passes them; a gate that requires one string argument
//! rejects them. The outcome follows from the gate definitions, so this
//! bounds the harness, not any deployed gate.

use rand::{Rng, SeedableRng};
use rand_pcg::Pcg64Mcg;
use serde_json::{json, Value};

pub const SHARES: [f64; 5] = [0.1, 0.25, 0.5, 0.75, 0.9];
pub const HEADLINE_SHARE: f64 = 0.5;

fn wilson(k: usize, n: usize) -> [f64; 2] {
    if n == 0 {
        return [0.0, 1.0];
    }
    let z = 1.96f64;
    let (n, p) = (n as f64, k as f64 / n as f64);
    let d = 1.0 + z * z / n;
    let c = (p + z * z / (2.0 * n)) / d;
    let h = z * (p * (1.0 - p) / n + z * z / (4.0 * n * n)).sqrt() / d;
    [(c - h).max(0.0), (c + h).min(1.0)]
}

fn point(seed: u64, idx: usize, s: f64, n: usize) -> Value {
    let mut rng = Pcg64Mcg::seed_from_u64(seed.wrapping_add(idx as u64));
    // Required-argument gate rejects every empty call (pass 0) and accepts every
    // well-formed call (false-block 0) by definition; the no-requirement gate
    // passes every call to the schema check.
    let (mut empty, mut wf) = (0usize, 0usize);
    for _ in 0..n {
        if rng.gen_bool(s) {
            empty += 1;
        } else {
            wf += 1;
        }
    }
    let (pass_none, pass_req, fb) = (empty, 0usize, 0usize);
    let nn = n.max(1) as f64;
    json!({
        "share": s, "n": n, "empty_calls": empty, "well_formed_calls": wf,
        "pass_rate_without_required_arg": pass_none as f64 / nn,
        "pass_rate_without_required_arg_wilson95": wilson(pass_none, n),
        "pass_rate_with_required_arg": pass_req as f64 / nn,
        "pass_rate_with_required_arg_wilson95": wilson(pass_req, n),
        "required_arg_false_block_rate": fb as f64 / wf.max(1) as f64,
    })
}

pub fn run(n: usize, seed: u64) -> Value {
    let mut sweep = Vec::new();
    let mut head = Value::Null;
    for (i, s) in SHARES.iter().enumerate() {
        let p = point(seed, i, *s, n);
        if *s == HEADLINE_SHARE {
            head = p.clone();
        }
        sweep.push(p);
    }
    json!({
        "sweep": sweep,
        "violation": {
            "headline_share": HEADLINE_SHARE,
            "pass_rate_without_required_arg": head["pass_rate_without_required_arg"],
            "pass_rate_with_required_arg": head["pass_rate_with_required_arg"],
            "required_arg_false_block_rate": head["required_arg_false_block_rate"],
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
        "command": format!("cargo run --locked -q -- emptyarg --seed {seed} --n {n} --out {}", out.display()),
        "hardware": format!("{} {} cpu, no gpu", std::env::consts::OS, std::env::consts::ARCH),
        "wall_s": t0.elapsed().as_secs_f64(),
        "data_sources": [{"url": "synthetic: seeded generator, no external data", "license": "MIT"}],
    });
    if let Some(dir) = out.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(out, serde_json::to_string_pretty(&report)? + "\n")?;
    println!("wrote {}", out.display());
    Ok(())
}
