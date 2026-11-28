//! Model-free pin-on-first-approval scanner simulation. A synthetic MCP
//! server population is clean, poisoned from first listing, or poisoned at a
//! later update. The scanner pins the schema hash at first approval and
//! flags any later schema change. Updates to from-start poisoned servers keep
//! the pinned (already poisoned) schema, so a pin can never differ from it.
//! Poisoned counts are fixed by rounding; only update draws are random. The
//! population is author-written, so this bounds the harness, not any
//! deployed scanner.

use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};
use rand_pcg::Pcg64Mcg;
use serde_json::{json, Value};

pub const POISONED_SHARE: f64 = 0.3;
pub const PERIODS: usize = 8;
pub const HEADLINE_FROM_START: f64 = 0.5;
pub const HEADLINE_UPDATE_P: f64 = 0.5;
const FROM_START_SWEEP: [f64; 5] = [0.0, 0.25, 0.5, 0.75, 1.0];
const UPDATE_SWEEP: [f64; 4] = [0.1, 0.25, 0.5, 0.75];

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Clean,
    FromStart,
    Late,
}

#[derive(Debug, PartialEq)]
pub struct Cell {
    pub poisoned: usize,
    pub from_start: usize,
    pub from_start_flagged: usize,
    pub late: usize,
    pub late_flagged: usize,
    pub clean_unchanged: usize,
    pub clean_unchanged_flagged: usize,
    pub clean_changed: usize,
    pub clean_changed_flagged: usize,
}

fn ratio(k: usize, d: usize) -> f64 {
    if d == 0 { 0.0 } else { k as f64 / d as f64 }
}

/// Run one (from-start share, update probability) cell.
pub fn run_cell(n: usize, from_start_share: f64, update_p: f64, seed: u64) -> Cell {
    let mut rng = Pcg64Mcg::seed_from_u64(seed);
    let poisoned = (POISONED_SHARE * n as f64).round() as usize;
    let from_start = (from_start_share * poisoned as f64).round() as usize;
    let mut kinds: Vec<Kind> = (0..n)
        .map(|i| {
            if i < from_start {
                Kind::FromStart
            } else if i < poisoned {
                Kind::Late
            } else {
                Kind::Clean
            }
        })
        .collect();
    kinds.shuffle(&mut rng);
    let mut c = Cell {
        poisoned,
        from_start,
        from_start_flagged: 0,
        late: poisoned - from_start,
        late_flagged: 0,
        clean_unchanged: 0,
        clean_unchanged_flagged: 0,
        clean_changed: 0,
        clean_changed_flagged: 0,
    };
    for k in kinds {
        let updated = (0..PERIODS).any(|_| rng.gen_bool(update_p));
        match k {
            // schema never differs from the pin taken at first approval
            Kind::FromStart => {}
            // the poison arrives with the first update; no update, no change
            Kind::Late => c.late_flagged += usize::from(updated),
            // a benign update changes the schema and is flagged
            Kind::Clean => {
                if updated {
                    c.clean_changed += 1;
                    c.clean_changed_flagged += 1;
                } else {
                    c.clean_unchanged += 1;
                }
            }
        }
    }
    c
}

fn cell_json(c: &Cell) -> Value {
    let undetected = c.from_start - c.from_start_flagged + c.late - c.late_flagged;
    json!({
        "poisoned": c.poisoned,
        "from_start": c.from_start,
        "late": c.late,
        "undetectable_fraction": ratio(undetected, c.poisoned),
        "from_start_detection_rate": ratio(c.from_start_flagged, c.from_start),
        "late_detection_rate": ratio(c.late_flagged, c.late),
        "false_flag_rate_unchanged_clean": ratio(c.clean_unchanged_flagged, c.clean_unchanged),
        "flag_rate_changed_clean": ratio(c.clean_changed_flagged, c.clean_changed),
    })
}

pub fn run(n: usize, seed: u64) -> Value {
    let head = run_cell(n, HEADLINE_FROM_START, HEADLINE_UPDATE_P, seed);
    let hj = cell_json(&head);
    let mut sweep = Vec::new();
    for fs in FROM_START_SWEEP {
        for up in UPDATE_SWEEP {
            let mut j = cell_json(&run_cell(n, fs, up, seed));
            j["from_start_share"] = json!(fs);
            j["update_p"] = json!(up);
            sweep.push(j);
        }
    }
    json!({
        "schema": "toolguard.pinsim/1",
        "population": {"n": n, "poisoned_share": POISONED_SHARE, "periods": PERIODS,
                       "from_start_share": HEADLINE_FROM_START, "update_p": HEADLINE_UPDATE_P},
        "pin_scanner": {
            "undetectable_fraction_at_half_poisoned_from_start": hj["undetectable_fraction"],
            "from_start_detection_rate": hj["from_start_detection_rate"],
            "late_detection_rate": hj["late_detection_rate"],
            "false_flag_rate_unchanged_clean": hj["false_flag_rate_unchanged_clean"],
            "flag_rate_changed_clean": hj["flag_rate_changed_clean"],
        },
        "sweep": sweep,
    })
}

pub fn write_report(n: usize, seed: u64, out: &std::path::Path) -> anyhow::Result<()> {
    let started_at = crate::scanner::utc_now();
    let t0 = std::time::Instant::now();
    let mut report = run(n, seed);
    report["provenance"] = json!({
        "started_at": started_at,
        "seeds": [seed],
        "command": format!("cargo run --locked -q --release -- pinsim --seed {seed} --n {n} --out {}", out.display()),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_start_never_flagged_and_unchanged_clean_never_flagged() {
        let r = run(1000, 7);
        assert_eq!(r["pin_scanner"]["from_start_detection_rate"], 0.0);
        assert_eq!(r["pin_scanner"]["false_flag_rate_unchanged_clean"], 0.0);
    }

    #[test]
    fn all_from_start_is_fully_undetectable() {
        let c = run_cell(1000, 1.0, 0.5, 7);
        assert_eq!(c.late, 0);
        assert_eq!(cell_json(&c)["undetectable_fraction"], 1.0);
    }

    #[test]
    fn no_from_start_is_nearly_detectable_at_high_update_rate() {
        let c = run_cell(1000, 0.0, 0.75, 7);
        assert!(cell_json(&c)["undetectable_fraction"].as_f64().unwrap() < 0.01);
    }

    #[test]
    fn deterministic() {
        assert_eq!(run(200, 3), run(200, 3));
    }
}
