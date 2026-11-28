//! Model-free compounding run. A per-episode breach probability `p` is applied
//! over `episodes` episodes, either independently or with a shared per-fleet
//! latent propensity drawn from a Beta with mean `p` and intra-fleet
//! correlation `rho`. Reports P(at least one breach). Parameters come from the
//! caller; this bounds the harness, not any deployed gate.

use rand::{Rng, SeedableRng};
use rand_pcg::Pcg64Mcg;
use serde_json::{json, Value};

fn std_normal(rng: &mut Pcg64Mcg) -> f64 {
    let u1: f64 = 1.0 - rng.gen::<f64>();
    let u2: f64 = rng.gen();
    (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos()
}

/// Marsaglia-Tsang gamma(shape, 1) sampler, with the shape<1 boost.
fn gamma(rng: &mut Pcg64Mcg, shape: f64) -> f64 {
    if shape < 1.0 {
        let u: f64 = rng.gen();
        return gamma(rng, shape + 1.0) * u.powf(1.0 / shape);
    }
    let d = shape - 1.0 / 3.0;
    let c = 1.0 / (9.0 * d).sqrt();
    loop {
        let x = std_normal(rng);
        let v = (1.0 + c * x).powi(3);
        if v <= 0.0 {
            continue;
        }
        let u: f64 = rng.gen();
        if u.ln() < 0.5 * x * x + d - d * v + d * v.ln() {
            return d * v;
        }
    }
}

pub fn beta(rng: &mut Pcg64Mcg, a: f64, b: f64) -> f64 {
    let x = gamma(rng, a);
    let y = gamma(rng, b);
    if x + y > 0.0 {
        x / (x + y)
    } else {
        0.0
    }
}

/// Simulate `trials` fleets of `episodes` episodes. `rho` None = independent.
pub fn arm(seed: u64, salt: u64, episodes: usize, p: f64, rho: Option<f64>, trials: usize) -> Value {
    let mut rng = Pcg64Mcg::seed_from_u64(seed.wrapping_add(salt));
    let (mut any, mut breaches) = (0usize, 0usize);
    for _ in 0..trials {
        let q = match rho {
            None => p,
            Some(r) => {
                let k = 1.0 / r - 1.0;
                beta(&mut rng, p * k, (1.0 - p) * k)
            }
        };
        let mut hit = 0usize;
        for _ in 0..episodes {
            if rng.gen::<f64>() < q {
                hit += 1;
            }
        }
        breaches += hit;
        if hit > 0 {
            any += 1;
        }
    }
    json!({
        "rho": rho,
        "trials": trials,
        "p_at_least_one": any as f64 / trials.max(1) as f64,
        "mean_breaches_per_fleet": breaches as f64 / trials.max(1) as f64,
        "marginal_episode_rate": breaches as f64 / (trials.max(1) * episodes.max(1)) as f64,
    })
}

pub fn run(seed: u64, episodes: usize, p: f64, trials: usize) -> Value {
    json!({
        "params": {"episodes": episodes, "p": p, "trials": trials},
        "analytic_independent_p_at_least_one": 1.0 - (1.0 - p).powi(episodes as i32),
        "arms": {
            "independent": arm(seed, 0, episodes, p, None, trials),
            "correlated_rho0.05": arm(seed, 1, episodes, p, Some(0.05), trials),
            "correlated_rho0.2": arm(seed, 2, episodes, p, Some(0.2), trials),
        },
    })
}

pub fn write_report(seed: u64, episodes: usize, p: f64, trials: usize, out: &std::path::Path) -> anyhow::Result<()> {
    let started_at = crate::scanner::utc_now();
    let t0 = std::time::Instant::now();
    let mut report = run(seed, episodes, p, trials);
    report["provenance"] = json!({
        "started_at": started_at,
        "seeds": [seed],
        "command": format!("cargo run --locked -q --release -- compound --seed {seed} --episodes {episodes} --p {p} --trials {trials} --out {}", out.display()),
        "hardware": format!("{} {} cpu, no gpu", std::env::consts::OS, std::env::consts::ARCH),
        "wall_s": t0.elapsed().as_secs_f64(),
        "data_sources": [{"url": "https://arxiv.org/abs/2609.39050", "license": "arXiv abstract, parameters 0.009 and 105 quoted only; no data used"}],
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
    fn deterministic() {
        assert_eq!(run(7, 105, 0.009, 500), run(7, 105, 0.009, 500));
    }

    #[test]
    fn independent_matches_analytic() {
        let v = run(7, 105, 0.009, 4000);
        let got = v["arms"]["independent"]["p_at_least_one"].as_f64().unwrap();
        assert!((got - v["analytic_independent_p_at_least_one"].as_f64().unwrap()).abs() < 0.04);
    }

    #[test]
    fn correlation_lowers_any_breach() {
        let v = run(7, 105, 0.009, 4000);
        let a = v["arms"]["independent"]["p_at_least_one"].as_f64().unwrap();
        let b = v["arms"]["correlated_rho0.2"]["p_at_least_one"].as_f64().unwrap();
        assert!(b < a);
    }

    #[test]
    fn beta_mean() {
        let mut rng = Pcg64Mcg::seed_from_u64(1);
        let m: f64 = (0..20000).map(|_| beta(&mut rng, 2.0, 6.0)).sum::<f64>() / 20000.0;
        assert!((m - 0.25).abs() < 0.01);
    }
}
