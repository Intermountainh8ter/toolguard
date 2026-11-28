//! Model-free malformed-argument run. A well-formed call to a two-argument
//! schema (required string `path`, optional integer `count` in 0..=10) is
//! corrupted in one of five fixed classes. Three validators judge the result:
//! strict (full schema), lenient (required-key presence and null only) and
//! accept-everything. The outcome follows from the validator definitions, so
//! this bounds the harness, not any deployed server.

use rand::{Rng, SeedableRng};
use rand_pcg::Pcg64Mcg;
use serde_json::{json, Map, Value};

pub const CLASSES: [&str; 5] = ["missing_required", "wrong_type", "null", "extra_key", "out_of_range"];

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

fn well_formed(rng: &mut Pcg64Mcg) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("path".into(), json!(format!("/tmp/f{}", rng.gen_range(0..1000))));
    m.insert("count".into(), json!(rng.gen_range(0..=10)));
    m
}

pub fn corrupt(class: usize, rng: &mut Pcg64Mcg) -> Map<String, Value> {
    let mut m = well_formed(rng);
    match class {
        0 => {
            m.remove("path");
        }
        1 => {
            m.insert("count".into(), json!("seven"));
        }
        2 => {
            m.insert("path".into(), Value::Null);
        }
        3 => {
            m.insert("unexpected".into(), json!(true));
        }
        _ => {
            m.insert("count".into(), json!(rng.gen_range(11..1000)));
        }
    }
    m
}

/// True when the validator rejects the call.
pub fn strict_rejects(m: &Map<String, Value>) -> bool {
    match m.get("path") {
        Some(Value::String(_)) => {}
        _ => return true,
    }
    if let Some(c) = m.get("count") {
        match c.as_i64() {
            Some(v) if (0..=10).contains(&v) => {}
            _ => return true,
        }
    }
    m.keys().any(|k| k != "path" && k != "count")
}

pub fn lenient_rejects(m: &Map<String, Value>) -> bool {
    !matches!(m.get("path"), Some(v) if !v.is_null()) || m.values().any(|v| v.is_null())
}

pub fn accept_all_rejects(_m: &Map<String, Value>) -> bool {
    false
}

pub fn run(n: usize, seed: u64) -> Value {
    let mut by_class = Map::new();
    let (mut s_tot, mut l_tot, mut a_tot) = (0usize, 0usize, 0usize);
    for (ci, name) in CLASSES.iter().enumerate() {
        let mut rng = Pcg64Mcg::seed_from_u64(seed.wrapping_add(ci as u64));
        let (mut s, mut l, mut a) = (0, 0, 0);
        for _ in 0..n {
            let m = corrupt(ci, &mut rng);
            s += strict_rejects(&m) as usize;
            l += lenient_rejects(&m) as usize;
            a += accept_all_rejects(&m) as usize;
        }
        s_tot += s;
        l_tot += l;
        a_tot += a;
        let nn = n.max(1) as f64;
        by_class.insert(
            name.to_string(),
            json!({
                "n": n,
                "strict_rate": s as f64 / nn, "strict_wilson95": wilson(s, n),
                "lenient_rate": l as f64 / nn, "lenient_wilson95": wilson(l, n),
                "accept_all_rate": a as f64 / nn, "accept_all_wilson95": wilson(a, n),
            }),
        );
    }
    let mut rng = Pcg64Mcg::seed_from_u64(seed.wrapping_add(100));
    let (mut fr_s, mut fr_l) = (0usize, 0usize);
    for _ in 0..n {
        let m = well_formed(&mut rng);
        fr_s += strict_rejects(&m) as usize;
        fr_l += lenient_rejects(&m) as usize;
    }
    let tot = (n * CLASSES.len()).max(1);
    let t = tot as f64;
    json!({
        "by_class": by_class,
        "clean_rejection": {
            "n_total": n * CLASSES.len(),
            "strict_rate_uniform_mix": s_tot as f64 / t,
            "lenient_rate_uniform_mix": l_tot as f64 / t,
            "lenient_wilson95": wilson(l_tot, tot),
            "accept_all_rate_uniform_mix": a_tot as f64 / t,
        },
        "well_formed": {
            "n": n,
            "strict_false_reject_rate": fr_s as f64 / n.max(1) as f64,
            "lenient_false_reject_rate": fr_l as f64 / n.max(1) as f64,
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
        "command": format!("cargo run --locked -q -- malformedarg --seed {seed} --n {n} --out {}", out.display()),
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
