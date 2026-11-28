//! Model-free tier-label-noise simulation. Each trial flips every tool's tier
//! label: the adjacent arm moves it to a neighbouring tier with probability p
//! (Dangerous has one neighbour, Caution; Caution has two, picked evenly), the
//! random arm replaces it with a uniform tier with probability q. A
//! tier-based gate blocks only tools labelled Dangerous, so a Dangerous tool
//! labelled below Dangerous is a miss. The catalog is author-written; this
//! bounds the harness, not any deployed gate.

use crate::{shell_and_filesystem, RiskTier};
use rand::{Rng, SeedableRng};
use rand_pcg::Pcg64Mcg;
use serde_json::{json, Value};

const TIERS: [RiskTier; 3] = [RiskTier::Benign, RiskTier::Caution, RiskTier::Dangerous];

fn idx(t: RiskTier) -> usize {
    TIERS.iter().position(|x| *x == t).unwrap()
}

pub fn adjacent_flip(t: RiskTier, p: f64, rng: &mut Pcg64Mcg) -> RiskTier {
    if !rng.gen_bool(p) {
        return t;
    }
    match idx(t) {
        0 => TIERS[1],
        1 => TIERS[if rng.gen_bool(0.5) { 0 } else { 2 }],
        _ => TIERS[1],
    }
}

pub fn random_flip(t: RiskTier, q: f64, rng: &mut Pcg64Mcg) -> RiskTier {
    if rng.gen_bool(q) {
        TIERS[rng.gen_range(0..3)]
    } else {
        t
    }
}

/// Returns (dangerous below threshold fraction, non-dangerous labelled Dangerous fraction).
fn arm(n: usize, seed: u64, flip: impl Fn(RiskTier, &mut Pcg64Mcg) -> RiskTier) -> (f64, f64) {
    let mut rng = Pcg64Mcg::seed_from_u64(seed);
    let cat = shell_and_filesystem();
    let nd = cat.tools.iter().filter(|t| t.tier == RiskTier::Dangerous).count();
    let nn = cat.tools.len() - nd;
    let (mut missed, mut over) = (0usize, 0usize);
    for _ in 0..n {
        for t in &cat.tools {
            let l = flip(t.tier, &mut rng);
            if t.tier == RiskTier::Dangerous && l != RiskTier::Dangerous {
                missed += 1;
            }
            if t.tier != RiskTier::Dangerous && l == RiskTier::Dangerous {
                over += 1;
            }
        }
    }
    (missed as f64 / (n * nd) as f64, over as f64 / (n * nn) as f64)
}

pub fn run(n: usize, seed: u64, p: f64, q: f64) -> Value {
    let (am, ao) = arm(n, seed, |t, r| adjacent_flip(t, p, r));
    let (rm, ro) = arm(n, seed.wrapping_add(1), |t, r| random_flip(t, q, r));
    let cat = shell_and_filesystem();
    json!({
        "schema": "toolguard.labelnoise/1",
        "population": {"catalog": cat.name, "tools": cat.tools.len(), "n": n, "p_adjacent": p, "q_random": q},
        "label_noise": {
            "dangerous_below_threshold_fraction_adjacent": am,
            "non_dangerous_labelled_dangerous_fraction_adjacent": ao,
            "dangerous_below_threshold_fraction_random": rm,
            "non_dangerous_labelled_dangerous_fraction_random": ro,
        },
    })
}

pub fn write_report(n: usize, seed: u64, p: f64, q: f64, out: &std::path::Path) -> anyhow::Result<()> {
    let started_at = crate::scanner::utc_now();
    let t0 = std::time::Instant::now();
    let mut report = run(n, seed, p, q);
    report["provenance"] = json!({
        "started_at": started_at,
        "seeds": [seed],
        "command": format!("cargo run --locked -q --release -- labelnoise --seed {seed} --n {n} --p {p} --q {q} --out {}", out.display()),
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
