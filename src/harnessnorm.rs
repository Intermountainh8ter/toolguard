//! Model-free harness-normalisation measurement.
//!
//! Synthetic calls carry one string argument. An author-written
//! unescape-and-trim normaliser rewrites it before execution; a strict
//! pass-through harness does not. A call's semantics change when the string
//! the tool receives differs from the string the caller sent. The change is
//! silent when the normaliser reports no warning. No model is called.

use crate::{Catalog, RiskTier};
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};
use rand_pcg::Pcg64Mcg;
use serde_json::{json, Value};

/// Author-written argument templates; the first group contains backslashes.
pub const WITH_BACKSLASH: &[&str] = &[
    "C:\\\\tmp\\\\build",
    "/tmp/my\\ file.txt",
    "line1\\nline2",
    "col1\\tcol2",
    "  /var/log/app\\\\old  ",
    "/srv/data\\q",
    "/home/user/a\\.b",
];
pub const WITHOUT_BACKSLASH: &[&str] = &["/tmp/build", "/var/log/app", "data.txt", "/srv/data"];

/// Probability that a generated argument contains a backslash.
pub const BACKSLASH_RATE: f64 = 0.7;

/// Strict harness: arguments reach the tool unchanged, no warnings.
pub fn passthrough(arg: &str) -> (String, bool) {
    (arg.to_string(), false)
}

/// Unescape `\\ \n \t \<space>`, trim outer whitespace. Unknown escapes drop
/// the backslash and report a warning; a known escape reports nothing.
pub fn normalise(arg: &str) -> (String, bool) {
    let mut out = String::new();
    let mut warned = false;
    let mut it = arg.trim().chars();
    while let Some(c) = it.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match it.next() {
            Some('\\') => out.push('\\'),
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some(' ') => out.push(' '),
            Some(o) => {
                out.push(o);
                warned = true;
            }
            None => warned = true,
        }
    }
    (out, warned)
}

pub fn run(cat: &Catalog, n: usize, seed: u64) -> Value {
    let mut rng = Pcg64Mcg::seed_from_u64(seed);
    let dangerous: Vec<&str> = cat
        .tools
        .iter()
        .filter(|t| t.tier == RiskTier::Dangerous)
        .map(|t| t.tool.as_str())
        .collect();
    let (mut total, mut changed, mut silent) = (0usize, 0usize, 0usize);
    let mut pt_changed = 0usize;
    for _ in 0..n {
        if dangerous.choose(&mut rng).is_none() {
            break;
        }
        let pool = if rng.gen_bool(BACKSLASH_RATE) { WITH_BACKSLASH } else { WITHOUT_BACKSLASH };
        let arg = *pool.choose(&mut rng).unwrap();
        total += 1;
        let (out, warned) = normalise(arg);
        if out != arg {
            changed += 1;
            silent += usize::from(!warned);
        }
        if passthrough(arg).0 != arg {
            pt_changed += 1;
        }
    }
    let r = |k: usize, d: usize| if d == 0 { 0.0 } else { k as f64 / d as f64 };
    json!({
        "schema": "toolguard.harnessnorm/1",
        "catalog": cat.name,
        "catalog_sha256": crate::catalog_sha256(cat),
        "n": total,
        "backslash_rate": BACKSLASH_RATE,
        "transform": {
            "changed_calls": changed,
            "changed_rate": r(changed, total),
            "silent_changed_calls": silent,
            "silent_semantic_change_rate": r(silent, changed),
        },
        "passthrough": {"changed_calls": pt_changed, "semantic_change_rate": r(pt_changed, total)},
    })
}

pub fn write_report(cat: &Catalog, n: usize, seed: u64, out: &std::path::Path) -> anyhow::Result<()> {
    let started_at = crate::scanner::utc_now();
    let t0 = std::time::Instant::now();
    let mut report = run(cat, n, seed);
    report["provenance"] = json!({
        "started_at": started_at,
        "seeds": [seed],
        "command": format!("cargo run --locked -q --release -- harnessnorm --seed {seed} --n {n} --out {}", out.display()),
        "hardware": format!("{} {} cpu, no gpu", std::env::consts::OS, std::env::consts::ARCH),
        "wall_s": t0.elapsed().as_secs_f64(),
        "data_sources": [{"url": "synthetic: seeded generator, author-written calls", "license": "MIT"}],
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
    use crate::shell_and_filesystem;

    #[test]
    fn normalise_unescapes_and_trims() {
        assert_eq!(normalise("a\\\\b"), ("a\\b".to_string(), false));
        assert_eq!(normalise("  x  "), ("x".to_string(), false));
        assert_eq!(normalise("a\\q"), ("aq".to_string(), true));
        assert_eq!(normalise("plain").0, "plain");
    }

    #[test]
    fn passthrough_never_changes() {
        let r = run(&shell_and_filesystem(), 500, 7);
        assert_eq!(r["passthrough"]["semantic_change_rate"], 0.0);
    }

    #[test]
    fn deterministic() {
        let c = shell_and_filesystem();
        assert_eq!(run(&c, 200, 7), run(&c, 200, 7));
    }
}
