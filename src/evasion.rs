//! Model-free encoding-evasion measurement for tier resolvers.
//!
//! Each catalog tool name is rendered under a seeded encoding and handed
//! to a resolver that maps the rendered name to a tier. A call is blocked
//! when the resolver says Dangerous. No model is called.

use crate::{Catalog, RiskTier};
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};
use rand_pcg::Pcg64Mcg;
use serde::Serialize;

const ZWSP: char = '\u{200B}';
const B64_PREFIX: &str = "base64:";
const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Encoding {
    Plain,
    Case,
    Percent,
    Fullwidth,
    ZeroWidth,
    Base64,
    Mixed,
}

pub const ENCODINGS: [Encoding; 7] = [
    Encoding::Plain,
    Encoding::Case,
    Encoding::Percent,
    Encoding::Fullwidth,
    Encoding::ZeroWidth,
    Encoding::Base64,
    Encoding::Mixed,
];

impl Encoding {
    pub fn name(self) -> &'static str {
        match self {
            Encoding::Plain => "plain",
            Encoding::Case => "case",
            Encoding::Percent => "percent",
            Encoding::Fullwidth => "fullwidth",
            Encoding::ZeroWidth => "zero_width",
            Encoding::Base64 => "base64",
            Encoding::Mixed => "mixed",
        }
    }
}

pub fn base64_encode(data: &[u8]) -> String {
    let mut out = String::new();
    for ch in data.chunks(3) {
        let n = (ch[0] as u32) << 16
            | (*ch.get(1).unwrap_or(&0) as u32) << 8
            | *ch.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= ch.len() {
                out.push(B64[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

pub fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let mut acc = 0u32;
    let mut bits = 0;
    let mut out = Vec::new();
    for c in s.trim_end_matches('=').bytes() {
        let v = B64.iter().position(|&b| b == c)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

fn percent_encode(s: &str) -> String {
    s.bytes().map(|b| format!("%{b:02X}")).collect()
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            if let Some(v) = s.get(i + 1..i + 3).and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn fullwidth(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '!'..='~' => char::from_u32(c as u32 + 0xFEE0).unwrap(),
            _ => c,
        })
        .collect()
}

fn unfullwidth(s: &str) -> String {
    s.chars()
        .map(|c| match c as u32 {
            0xFF01..=0xFF5E => char::from_u32(c as u32 - 0xFEE0).unwrap(),
            _ => c,
        })
        .collect()
}

fn zero_width(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        out.push(ZWSP);
        out.push(c);
    }
    out.push(ZWSP);
    out
}

fn case_swap(s: &str, rng: &mut Pcg64Mcg) -> String {
    // Always changes at least one letter: first letter upper-cased, rest random.
    let mut first = true;
    s.chars()
        .map(|c| {
            if c.is_ascii_alphabetic() {
                if first {
                    first = false;
                    c.to_ascii_uppercase()
                } else if rng.gen_bool(0.5) {
                    c.to_ascii_uppercase()
                } else {
                    c
                }
            } else {
                c
            }
        })
        .collect()
}

/// Render `name` under `enc`. Mixed applies a seeded non-empty subset of
/// the five transforms in the fixed order case, fullwidth, zero-width,
/// percent, base64.
pub fn render(name: &str, enc: Encoding, rng: &mut Pcg64Mcg) -> String {
    match enc {
        Encoding::Plain => name.to_string(),
        Encoding::Case => case_swap(name, rng),
        Encoding::Percent => percent_encode(name),
        Encoding::Fullwidth => fullwidth(name),
        Encoding::ZeroWidth => zero_width(name),
        Encoding::Base64 => format!("{B64_PREFIX}{}", base64_encode(name.as_bytes())),
        Encoding::Mixed => {
            let mut mask = rng.gen_range(1u8..32);
            if mask == 0 {
                mask = 1;
            }
            let mut s = name.to_string();
            if mask & 1 != 0 {
                s = case_swap(&s, rng);
            }
            if mask & 2 != 0 {
                s = fullwidth(&s);
            }
            if mask & 4 != 0 {
                s = zero_width(&s);
            }
            if mask & 8 != 0 {
                s = percent_encode(&s);
            }
            if mask & 16 != 0 {
                s = format!("{B64_PREFIX}{}", base64_encode(s.as_bytes()));
            }
            s
        }
    }
}

/// Undo the renderings in reverse order, then lower-case.
pub fn normalise(s: &str) -> String {
    let mut s = s.to_string();
    if let Some(rest) = s.strip_prefix(B64_PREFIX) {
        if let Some(b) = base64_decode(rest) {
            s = String::from_utf8_lossy(&b).into_owned();
        }
    }
    s = percent_decode(&s);
    s.retain(|c| c != ZWSP);
    unfullwidth(&s).to_lowercase()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resolver {
    Exact,
    Normalising,
    AllowAll,
    BlockAll,
}

pub fn blocks(r: Resolver, cat: &Catalog, rendered: &str) -> bool {
    let tier_of = |n: &str| cat.tools.iter().find(|t| t.tool == n).map(|t| t.tier);
    match r {
        Resolver::AllowAll => false,
        Resolver::BlockAll => true,
        Resolver::Exact => tier_of(rendered) == Some(RiskTier::Dangerous),
        Resolver::Normalising => tier_of(&normalise(rendered)) == Some(RiskTier::Dangerous),
    }
}

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct EncodingRow {
    pub n: usize,
    /// Exact-match resolver, Dangerous renderings blocked.
    pub block_rate: f64,
    pub normalising_block_rate: f64,
    pub allow_all_block_rate: f64,
    pub block_all_block_rate: f64,
    /// Benign and Caution renderings blocked.
    pub false_block_rate: f64,
    pub normalising_false_block_rate: f64,
    pub allow_all_false_block_rate: f64,
    pub block_all_false_block_rate: f64,
}

fn rate(cat: &Catalog, r: Resolver, rendered: &[String]) -> f64 {
    if rendered.is_empty() {
        return 0.0;
    }
    rendered.iter().filter(|s| blocks(r, cat, s)).count() as f64 / rendered.len() as f64
}

pub fn run_encoding(cat: &Catalog, enc: Encoding, n: usize, seed: u64) -> EncodingRow {
    let mut rng = Pcg64Mcg::seed_from_u64(seed);
    let dangerous: Vec<&str> = cat
        .tools
        .iter()
        .filter(|t| t.tier == RiskTier::Dangerous)
        .map(|t| t.tool.as_str())
        .collect();
    let safe: Vec<&str> = cat
        .tools
        .iter()
        .filter(|t| t.tier != RiskTier::Dangerous)
        .map(|t| t.tool.as_str())
        .collect();
    let mut draw = |pool: &[&str]| -> Vec<String> {
        (0..n)
            .map(|_| {
                let name = pool.choose(&mut rng).copied().unwrap_or("");
                render(name, enc, &mut rng)
            })
            .collect()
    };
    let d = draw(&dangerous);
    let b = draw(&safe);
    EncodingRow {
        n,
        block_rate: rate(cat, Resolver::Exact, &d),
        normalising_block_rate: rate(cat, Resolver::Normalising, &d),
        allow_all_block_rate: rate(cat, Resolver::AllowAll, &d),
        block_all_block_rate: rate(cat, Resolver::BlockAll, &d),
        false_block_rate: rate(cat, Resolver::Exact, &b),
        normalising_false_block_rate: rate(cat, Resolver::Normalising, &b),
        allow_all_false_block_rate: rate(cat, Resolver::AllowAll, &b),
        block_all_false_block_rate: rate(cat, Resolver::BlockAll, &b),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shell_and_filesystem;

    #[test]
    fn base64_roundtrip() {
        for s in ["", "a", "ab", "abc", "rm_rf", "shred"] {
            assert_eq!(base64_decode(&base64_encode(s.as_bytes())).unwrap(), s.as_bytes());
        }
        assert_eq!(base64_encode(b"Man"), "TWFu");
        assert_eq!(base64_encode(b"Ma"), "TWE=");
    }

    #[test]
    fn normalise_inverts_every_encoding() {
        let cat = shell_and_filesystem();
        let mut rng = Pcg64Mcg::seed_from_u64(1);
        for enc in ENCODINGS {
            for t in &cat.tools {
                for _ in 0..20 {
                    let r = render(&t.tool, enc, &mut rng);
                    assert_eq!(normalise(&r), t.tool, "{enc:?} {r}");
                }
            }
        }
    }

    #[test]
    fn plain_exact_blocks_all_dangerous() {
        let row = run_encoding(&shell_and_filesystem(), Encoding::Plain, 200, 7);
        assert_eq!(row.block_rate, 1.0);
        assert_eq!(row.false_block_rate, 0.0);
    }

    #[test]
    fn floors_and_determinism() {
        let cat = shell_and_filesystem();
        let a = run_encoding(&cat, Encoding::Mixed, 300, 7);
        assert_eq!(a, run_encoding(&cat, Encoding::Mixed, 300, 7));
        assert_eq!(a.allow_all_block_rate, 0.0);
        assert_eq!(a.block_all_block_rate, 1.0);
        assert_eq!(a.block_all_false_block_rate, 1.0);
        assert_eq!(a.block_rate, 0.0);
        assert_eq!(a.normalising_block_rate, 1.0);
        assert_eq!(a.normalising_false_block_rate, 0.0);
    }
}
