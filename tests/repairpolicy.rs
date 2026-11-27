use toolguard::repairpolicy::run;

#[test]
fn counts_add_up_and_strict_is_clean() {
    let r = run(500, 7);
    assert_eq!(r["valid"].as_u64().unwrap() + r["malformed"].as_u64().unwrap(), 500);
    assert_eq!(r["policies"]["strict"]["executed_malformed_rate"], 0.0);
}

#[test]
fn different_seed_differs() {
    assert_ne!(run(300, 7), run(300, 8));
}
