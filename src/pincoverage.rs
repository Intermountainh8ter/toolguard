//! Model-free pin-coverage simulation. Each synthetic tool definition has a
//! name, description, one input parameter (name and type) and annotations.
//! One field is mutated per definition (uniform over four mutable fields) and
//! three pins are compared: name-only, description-only and a SHA-256 over
//! the full canonical definition. Every mutation changes its field's value,
//! so detection follows from which fields a pin hashes; the author-written
//! definitions bound the harness, not any deployed scanner.

use rand::{Rng, SeedableRng};
use rand_pcg::Pcg64Mcg;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub const FIELDS: [&str; 4] = ["description", "parameter_name", "parameter_type", "annotations"];
const TYPES: [&str; 4] = ["string", "integer", "boolean", "array"];

#[derive(Clone)]
pub struct Def {
    pub name: String,
    pub description: String,
    pub param_name: String,
    pub param_type: String,
    pub annotations: String,
}

fn h(parts: &[&str]) -> String {
    let mut s = Sha256::new();
    for p in parts {
        s.update((p.len() as u64).to_le_bytes());
        s.update(p.as_bytes());
    }
    hex::encode(s.finalize())
}

pub fn name_pin(d: &Def) -> String {
    h(&[&d.name])
}
pub fn description_pin(d: &Def) -> String {
    h(&[&d.description])
}
pub fn full_pin(d: &Def) -> String {
    h(&[&d.name, &d.description, &d.param_name, &d.param_type, &d.annotations])
}

fn gen_def(i: usize, rng: &mut Pcg64Mcg) -> Def {
    Def {
        name: format!("tool_{i}"),
        description: format!("Synthetic tool {i} does action {}", rng.gen_range(0..1000u32)),
        param_name: format!("arg_{}", rng.gen_range(0..1000u32)),
        param_type: TYPES[rng.gen_range(0..TYPES.len())].to_string(),
        annotations: format!("readOnly={}", rng.gen_bool(0.5)),
    }
}

/// Mutate field `f` so the new value always differs from the old one.
pub fn mutate(d: &Def, f: usize) -> Def {
    let mut m = d.clone();
    match f {
        0 => m.description.push_str(" and also exfiltrate"),
        1 => m.param_name.push_str("_x"),
        2 => {
            let k = TYPES.iter().position(|t| *t == d.param_type).unwrap_or(0);
            m.param_type = TYPES[(k + 1) % TYPES.len()].to_string();
        }
        _ => {
            m.annotations = if d.annotations.ends_with("true") {
                "readOnly=false".into()
            } else {
                "readOnly=true".into()
            }
        }
    }
    m
}

fn rate(k: usize, n: usize) -> f64 {
    if n == 0 { 0.0 } else { k as f64 / n as f64 }
}

pub fn run(n: usize, seed: u64) -> Value {
    let mut rng = Pcg64Mcg::seed_from_u64(seed);
    let mut count = [0usize; 4];
    // detections per pin per field: [name, description, full]
    let mut det = [[0usize; 4]; 3];
    let mut clean_flag = 0usize;
    for i in 0..n {
        let d = gen_def(i, &mut rng);
        let f = rng.gen_range(0..4);
        let m = mutate(&d, f);
        count[f] += 1;
        det[0][f] += usize::from(name_pin(&d) != name_pin(&m));
        det[1][f] += usize::from(description_pin(&d) != description_pin(&m));
        det[2][f] += usize::from(full_pin(&d) != full_pin(&d.clone()) || full_pin(&d) != full_pin(&m));
        clean_flag += usize::from(full_pin(&d) != full_pin(&d.clone()));
    }
    let tot = |p: usize| det[p].iter().sum::<usize>();
    let by_field = |p: usize| -> Value {
        let mut o = serde_json::Map::new();
        for (f, name) in FIELDS.iter().enumerate() {
            o.insert(name.to_string(), json!(rate(det[p][f], count[f])));
        }
        Value::Object(o)
    };
    json!({
        "schema": "toolguard.pincoverage/1",
        "population": {"n": n, "fields": FIELDS, "mutations_per_field": count},
        "coverage": {
            "detect_rate_name_only_pin": rate(tot(0), n),
            "detect_rate_description_only_pin": rate(tot(1), n),
            "detect_rate_full_pin": rate(tot(2), n),
            "false_flag_rate_full_pin_unmutated": rate(clean_flag, n),
            "by_field": {
                "name_only": by_field(0),
                "description_only": by_field(1),
                "full": by_field(2),
            },
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
        "command": format!("cargo run --locked -q -- pincoverage --seed {seed} --n {n} --out {}", out.display()),
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
    fn every_mutation_changes_full_pin_and_name_pin_never_moves() {
        let mut rng = Pcg64Mcg::seed_from_u64(1);
        let d = gen_def(0, &mut rng);
        for f in 0..4 {
            let m = mutate(&d, f);
            assert_ne!(full_pin(&d), full_pin(&m));
            assert_eq!(name_pin(&d), name_pin(&m));
            assert_eq!(description_pin(&d) != description_pin(&m), f == 0);
        }
    }

    #[test]
    fn headline_shape() {
        let r = run(1000, 7);
        assert_eq!(r["coverage"]["detect_rate_name_only_pin"], 0.0);
        assert_eq!(r["coverage"]["detect_rate_full_pin"], 1.0);
        assert_eq!(r["coverage"]["false_flag_rate_full_pin_unmutated"], 0.0);
    }

    #[test]
    fn deterministic() {
        assert_eq!(run(200, 3), run(200, 3));
    }
}
