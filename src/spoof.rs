//! Model-free tool-name spoofing measurement for registry resolvers.
//!
//! A second server registers a Benign-tier tool under a Dangerous tool's
//! name. The resolver picks one registration for the call; a Dangerous
//! call that resolves to a non-Dangerous tier gets through. No model is
//! called.

use crate::{Catalog, RiskTier};
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};
use rand_pcg::Pcg64Mcg;
use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Policy {
    FirstMatch,
    LastMatch,
    RejectOnCollision,
    AllowAll,
    BlockAll,
}

pub const POLICIES: [Policy; 5] = [
    Policy::FirstMatch,
    Policy::LastMatch,
    Policy::RejectOnCollision,
    Policy::AllowAll,
    Policy::BlockAll,
];

impl Policy {
    pub fn name(self) -> &'static str {
        match self {
            Policy::FirstMatch => "first_match",
            Policy::LastMatch => "last_match",
            Policy::RejectOnCollision => "reject_on_collision",
            Policy::AllowAll => "allow_all",
            Policy::BlockAll => "block_all",
        }
    }
}

/// True when the gate blocks a call whose name has been registered with
/// `tiers` (in registration order).
pub fn blocks(p: Policy, tiers: &[RiskTier]) -> bool {
    match p {
        Policy::AllowAll => false,
        Policy::BlockAll => true,
        Policy::FirstMatch => tiers.first() == Some(&RiskTier::Dangerous),
        Policy::LastMatch => tiers.last() == Some(&RiskTier::Dangerous),
        Policy::RejectOnCollision => tiers.len() > 1 || tiers.first() == Some(&RiskTier::Dangerous),
    }
}

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct PolicyRow {
    pub n: usize,
    /// Spoofed Dangerous calls that were not blocked.
    pub spoof_success_rate: f64,
    /// Benign same-tier duplicate registrations that were blocked.
    pub false_block_rate: f64,
}

pub fn run_policy(cat: &Catalog, p: Policy, n: usize, seed: u64) -> PolicyRow {
    let mut rng = Pcg64Mcg::seed_from_u64(seed);
    let dangerous: Vec<&str> = cat
        .tools
        .iter()
        .filter(|t| t.tier == RiskTier::Dangerous)
        .map(|t| t.tool.as_str())
        .collect();
    let benign: Vec<&str> = cat
        .tools
        .iter()
        .filter(|t| t.tier == RiskTier::Benign)
        .map(|t| t.tool.as_str())
        .collect();
    let mut passed = 0usize;
    let mut false_blocked = 0usize;
    for _ in 0..n {
        // The tool name only selects the scenario; the resolver sees tiers.
        let _name = dangerous.choose(&mut rng);
        let spoof_first = rng.gen_bool(0.5);
        let tiers = if spoof_first {
            [RiskTier::Benign, RiskTier::Dangerous]
        } else {
            [RiskTier::Dangerous, RiskTier::Benign]
        };
        if !blocks(p, &tiers) {
            passed += 1;
        }
        let _dup = benign.choose(&mut rng);
        if blocks(p, &[RiskTier::Benign, RiskTier::Benign]) {
            false_blocked += 1;
        }
    }
    let r = |k: usize| if n == 0 { 0.0 } else { k as f64 / n as f64 };
    PolicyRow {
        n,
        spoof_success_rate: r(passed),
        false_block_rate: r(false_blocked),
    }
}

/// Client resolution rules for same-name tools from two servers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rule {
    FirstRegisteredWins,
    ServerPrefixExact,
    PrefixStrip,
}

pub const RULES: [Rule; 3] = [
    Rule::FirstRegisteredWins,
    Rule::ServerPrefixExact,
    Rule::PrefixStrip,
];

impl Rule {
    pub fn name(self) -> &'static str {
        match self {
            Rule::FirstRegisteredWins => "first_registered_wins",
            Rule::ServerPrefixExact => "server_prefix_exact",
            Rule::PrefixStrip => "prefix_strip",
        }
    }
}

/// Tier the gate assigns to a call. `genuine_first` is registration order
/// (bare-name rule only); `from_genuine` says which server made the call.
/// The catalog is keyed by bare name; the genuine tool is Dangerous and the
/// spoofing server's tool of the same name is Benign. An exact lookup of a
/// prefixed name misses and fails open as Benign.
pub fn assigned_tier(r: Rule, genuine_first: bool, from_genuine: bool) -> RiskTier {
    match r {
        Rule::FirstRegisteredWins => {
            if genuine_first {
                RiskTier::Dangerous
            } else {
                RiskTier::Benign
            }
        }
        Rule::ServerPrefixExact => RiskTier::Benign,
        Rule::PrefixStrip => {
            let _ = from_genuine;
            RiskTier::Dangerous
        }
    }
}

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct RuleRow {
    pub n: usize,
    /// Genuine Dangerous calls assigned a non-Dangerous tier.
    pub misresolved_share: f64,
    /// Spoofing server's Benign calls assigned Dangerous.
    pub false_block_rate: f64,
}

pub fn run_rule(cat: &Catalog, r: Rule, n: usize, seed: u64) -> RuleRow {
    let mut rng = Pcg64Mcg::seed_from_u64(seed);
    let dangerous: Vec<&str> = cat
        .tools
        .iter()
        .filter(|t| t.tier == RiskTier::Dangerous)
        .map(|t| t.tool.as_str())
        .collect();
    let (mut wrong, mut fb) = (0usize, 0usize);
    for _ in 0..n {
        let _name = dangerous.choose(&mut rng);
        let genuine_first = rng.gen_bool(0.5);
        if assigned_tier(r, genuine_first, true) != RiskTier::Dangerous {
            wrong += 1;
        }
        // Spoofer's own Benign call; for the bare-name rule the shared name
        // resolves by order, so it is blocked only when genuine was first.
        if assigned_tier(r, genuine_first, false) == RiskTier::Dangerous {
            fb += 1;
        }
    }
    let f = |k: usize| if n == 0 { 0.0 } else { k as f64 / n as f64 };
    RuleRow {
        n,
        misresolved_share: f(wrong),
        false_block_rate: f(fb),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shell_and_filesystem;

    #[test]
    fn resolution_rules() {
        use RiskTier::*;
        assert!(!blocks(Policy::FirstMatch, &[Benign, Dangerous]));
        assert!(blocks(Policy::FirstMatch, &[Dangerous, Benign]));
        assert!(blocks(Policy::LastMatch, &[Benign, Dangerous]));
        assert!(blocks(Policy::RejectOnCollision, &[Benign, Dangerous]));
        assert!(blocks(Policy::RejectOnCollision, &[Benign, Benign]));
        assert!(!blocks(Policy::RejectOnCollision, &[Benign]));
    }

    #[test]
    fn floors_and_determinism() {
        let cat = shell_and_filesystem();
        let a = run_policy(&cat, Policy::FirstMatch, 500, 7);
        assert_eq!(a, run_policy(&cat, Policy::FirstMatch, 500, 7));
        assert_eq!(run_policy(&cat, Policy::AllowAll, 100, 7).spoof_success_rate, 1.0);
        assert_eq!(run_policy(&cat, Policy::BlockAll, 100, 7).spoof_success_rate, 0.0);
        let rej = run_policy(&cat, Policy::RejectOnCollision, 100, 7);
        assert_eq!(rej.spoof_success_rate, 0.0);
        assert_eq!(rej.false_block_rate, 1.0);
        assert_eq!(a.false_block_rate, 0.0);
    }

    #[test]
    fn rule_rows() {
        let cat = shell_and_filesystem();
        let a = run_rule(&cat, Rule::FirstRegisteredWins, 1000, 7);
        assert_eq!(a, run_rule(&cat, Rule::FirstRegisteredWins, 1000, 7));
        assert!(a.misresolved_share > 0.4 && a.misresolved_share < 0.6);
        let e = run_rule(&cat, Rule::ServerPrefixExact, 100, 7);
        assert_eq!(e.misresolved_share, 1.0);
        assert_eq!(e.false_block_rate, 0.0);
        let s = run_rule(&cat, Rule::PrefixStrip, 100, 7);
        assert_eq!(s.misresolved_share, 0.0);
        assert_eq!(s.false_block_rate, 1.0);
    }
}
