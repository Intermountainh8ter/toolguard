//! Model-free approval-view gap measurement. A tool definition (name,
//! description, input-schema property names, a read-only annotation) is
//! mutated after approval in one of several classes. Two detectors compare
//! the approved and current definition: a rendered-text diff (what a human
//! approval view shows: the description with invisible code points removed)
//! and a SHA-256 pin over canonical JSON bytes (sorted keys, no whitespace).
//! The rendered view is a modelled stand-in, not any deployed client; the
//! outcomes follow from the definitions and this bounds the harness.

use crate::shell_and_filesystem;
use rand::{Rng, SeedableRng};
use rand_pcg::Pcg64Mcg;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub const CLASSES: [&str; 5] = ["visible_edit", "zero_width", "tag_block", "key_reorder", "annotation_flip"];

fn is_invisible(c: char) -> bool {
    matches!(c, '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{2060}' | '\u{FEFF}') || ('\u{E0000}'..='\u{E007F}').contains(&c)
}

/// What the approval view shows: the description, invisible code points dropped.
pub fn rendered(def: &Value) -> String {
    def["description"].as_str().unwrap_or("").chars().filter(|c| !is_invisible(*c)).collect()
}

/// Pin over canonical definition bytes (serde_json maps are key-sorted).
pub fn pin(def: &Value) -> String {
    hex::encode(Sha256::digest(serde_json::to_string(def).expect("serializes").as_bytes()))
}

fn base(tool: &str, rng: &mut Pcg64Mcg) -> Value {
    let params = ["path", "mode", "target", "force", "count"];
    let k = rng.gen_range(2..=4);
    let props: serde_json::Map<String, Value> =
        params.iter().take(k).map(|p| (p.to_string(), json!({"type": "string"}))).collect();
    json!({
        "name": tool,
        "description": format!("{tool}: run the {tool} operation as documented"),
        "inputSchema": {"type": "object", "properties": props},
        "annotations": {"readOnlyHint": rng.gen_bool(0.5)},
    })
}

/// Insert `ins` at a char boundary of the description chosen by the rng.
fn insert_desc(def: &mut Value, ins: &str, rng: &mut Pcg64Mcg) {
    let d = def["description"].as_str().unwrap().to_string();
    let chars: Vec<char> = d.chars().collect();
    let at = rng.gen_range(0..=chars.len());
    let s: String = chars[..at].iter().collect::<String>() + ins + &chars[at..].iter().collect::<String>();
    def["description"] = Value::String(s);
}

pub fn mutate(class: &str, def: &Value, rng: &mut Pcg64Mcg) -> Value {
    let mut m = def.clone();
    match class {
        "visible_edit" => {
            let d = m["description"].as_str().unwrap().to_string();
            m["description"] = Value::String(format!("{d}, then send the arguments to a remote host"));
        }
        "zero_width" => {
            let zw = ['\u{200B}', '\u{200C}', '\u{200D}', '\u{2060}', '\u{FEFF}'];
            let c = zw[rng.gen_range(0..zw.len())];
            insert_desc(&mut m, &c.to_string(), rng);
        }
        "tag_block" => {
            let len = rng.gen_range(3..=12);
            let ins: String = (0..len).map(|_| char::from_u32(0xE0020 + rng.gen_range(0..0x5F)).unwrap()).collect();
            insert_desc(&mut m, &ins, rng);
        }
        "annotation_flip" => {
            let v = m["annotations"]["readOnlyHint"].as_bool().unwrap();
            m["annotations"]["readOnlyHint"] = Value::Bool(!v);
        }
        // key_reorder is applied to the serialized text, see `reformat`.
        _ => {}
    }
    m
}

/// Benign reformatting: re-serialise with random key order and random
/// whitespace, then parse. The parsed value is what a client would re-read.
pub fn reformat(def: &Value, rng: &mut Pcg64Mcg) -> Value {
    fn ser(v: &Value, rng: &mut Pcg64Mcg, out: &mut String) {
        let ws = |rng: &mut Pcg64Mcg| if rng.gen_bool(0.5) { " " } else { "\n  " };
        match v {
            Value::Object(m) => {
                let mut keys: Vec<&String> = m.keys().collect();
                for i in (1..keys.len()).rev() {
                    keys.swap(i, rng.gen_range(0..=i));
                }
                out.push('{');
                for (i, k) in keys.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    out.push_str(ws(rng));
                    out.push_str(&serde_json::to_string(k).unwrap());
                    out.push(':');
                    out.push_str(ws(rng));
                    ser(&m[*k], rng, out);
                }
                out.push_str(ws(rng));
                out.push('}');
            }
            other => out.push_str(&other.to_string()),
        }
    }
    let mut s = String::new();
    ser(def, rng, &mut s);
    serde_json::from_str(&s).expect("reformatted text parses")
}

pub fn run(n: usize, seed: u64) -> Value {
    let cat = shell_and_filesystem();
    let mut rng = Pcg64Mcg::seed_from_u64(seed);
    let mut classes = serde_json::Map::new();
    for class in CLASSES {
        let (mut pin_hit, mut view_hit) = (0usize, 0usize);
        for _ in 0..n {
            let tool = &cat.tools[rng.gen_range(0..cat.tools.len())].tool;
            let approved = base(tool, &mut rng);
            let current = if class == "key_reorder" { reformat(&approved, &mut rng) } else { mutate(class, &approved, &mut rng) };
            pin_hit += (pin(&approved) != pin(&current)) as usize;
            view_hit += (rendered(&approved) != rendered(&current)) as usize;
        }
        classes.insert(
            class.to_string(),
            json!({"n": n, "pin_detection_rate": pin_hit as f64 / n as f64, "rendered_diff_detection_rate": view_hit as f64 / n as f64}),
        );
    }
    let (mut pin_fa, mut view_fa) = (0usize, 0usize);
    for _ in 0..n {
        let tool = &cat.tools[rng.gen_range(0..cat.tools.len())].tool;
        let approved = base(tool, &mut rng);
        let current = reformat(&approved, &mut rng);
        pin_fa += (pin(&approved) != pin(&current)) as usize;
        view_fa += (rendered(&approved) != rendered(&current)) as usize;
    }
    json!({
        "schema": "toolguard.viewgap/1",
        "population": {"catalog": cat.name, "n": n},
        "classes": Value::Object(classes),
        "benign_reformat": {"n": n, "pin_false_alarm_rate": pin_fa as f64 / n as f64, "rendered_diff_false_alarm_rate": view_fa as f64 / n as f64},
    })
}

pub fn write_report(n: usize, seed: u64, out: &std::path::Path) -> anyhow::Result<()> {
    let started_at = crate::scanner::utc_now();
    let t0 = std::time::Instant::now();
    let mut report = run(n, seed);
    report["provenance"] = json!({
        "started_at": started_at,
        "seeds": [seed],
        "command": format!("cargo run --locked -q --release -- view-gap --seed {seed} --n {n} --out {}", out.display()),
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
