//! Model-free scanner precision-versus-prevalence simulation. A synthetic
//! server population is poisoned with a swept prevalence; a scanner with
//! fixed sensitivity and false-positive rate alerts independently. Reports
//! positive predictive value and alerts per true finding. The scanner
//! parameters are author-written, so this bounds the harness, not any
//! deployed scanner.

use rand::{Rng, SeedableRng};
use rand_pcg::Pcg64Mcg;
use serde_json::{json, Value};

pub const SENSITIVITY: f64 = 0.8;
pub const FALSE_POSITIVE_RATE: f64 = 0.1;
const PREVALENCES: [f64; 7] = [0.01, 0.02, 0.05, 0.1, 0.2, 0.3, 0.5];

#[derive(Debug, PartialEq)]
pub struct Cell {
    pub poisoned: usize,
    pub true_alerts: usize,
    pub false_alerts: usize,
}

pub fn run_cell(n: usize, prevalence: f64, seed: u64) -> Cell {
    let mut rng = Pcg64Mcg::seed_from_u64(seed);
    let mut c = Cell { poisoned: 0, true_alerts: 0, false_alerts: 0 };
    for _ in 0..n {
        let poisoned = rng.gen_bool(prevalence);
        if poisoned {
            c.poisoned += 1;
            if rng.gen_bool(SENSITIVITY) {
                c.true_alerts += 1;
            }
        } else if rng.gen_bool(FALSE_POSITIVE_RATE) {
            c.false_alerts += 1;
        }
    }
    c
}

fn cell_json(prevalence: f64, n: usize, c: &Cell) -> Value {
    let alerts = c.true_alerts + c.false_alerts;
    let ppv = if alerts == 0 { 0.0 } else { c.true_alerts as f64 / alerts as f64 };
    let per_true = if c.true_alerts == 0 { Value::Null } else { json!(alerts as f64 / c.true_alerts as f64) };
    json!({
        "prevalence": prevalence,
        "n": n,
        "poisoned": c.poisoned,
        "true_alerts": c.true_alerts,
        "false_alerts": c.false_alerts,
        "ppv": ppv,
        "alerts_per_true_finding": per_true,
        "analytic_ppv": SENSITIVITY * prevalence
            / (SENSITIVITY * prevalence + FALSE_POSITIVE_RATE * (1.0 - prevalence)),
    })
}

pub fn run(n: usize, seed: u64) -> Value {
    let cells: Vec<Value> = PREVALENCES
        .iter()
        .enumerate()
        .map(|(i, &p)| cell_json(p, n, &run_cell(n, p, seed.wrapping_add(i as u64))))
        .collect();
    let first_half = cells
        .iter()
        .find(|c| c["ppv"].as_f64().unwrap_or(0.0) >= 0.5)
        .map(|c| c["prevalence"].clone())
        .unwrap_or(Value::Null);
    json!({
        "scanner": {"sensitivity": SENSITIVITY, "false_positive_rate": FALSE_POSITIVE_RATE},
        "ppv_by_prevalence": cells,
        "first_swept_prevalence_with_ppv_at_least_half": first_half,
        "analytic_break_even_prevalence": FALSE_POSITIVE_RATE / (SENSITIVITY + FALSE_POSITIVE_RATE),
    })
}

pub fn write_report(n: usize, seed: u64, out: &std::path::Path) -> anyhow::Result<()> {
    let started_at = crate::scanner::utc_now();
    let t0 = std::time::Instant::now();
    let mut report = run(n, seed);
    report["provenance"] = json!({
        "started_at": started_at,
        "seeds": [seed],
        "command": format!("cargo run --locked -q --release -- ppvsweep --seed {seed} --n {n} --out {}", out.display()),
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
    fn ppv_rises_with_prevalence() {
        let r = run(20000, 7);
        let v = r["ppv_by_prevalence"].as_array().unwrap();
        for w in v.windows(2) {
            assert!(w[0]["ppv"].as_f64().unwrap() < w[1]["ppv"].as_f64().unwrap());
        }
    }

    #[test]
    fn ppv_tracks_analytic_value() {
        let r = run(100000, 7);
        let c = &r["ppv_by_prevalence"][2];
        let d = (c["ppv"].as_f64().unwrap() - c["analytic_ppv"].as_f64().unwrap()).abs();
        assert!(d < 0.03);
    }

    #[test]
    fn deterministic() {
        assert_eq!(run(500, 3), run(500, 3));
    }

}
