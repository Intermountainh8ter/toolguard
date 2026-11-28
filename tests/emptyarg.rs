use toolguard::emptyarg::run;

#[test]
fn no_required_arg_passes_share_and_required_arg_blocks() {
    let r = run(1000, 7);
    let p = r["violation"]["pass_rate_without_required_arg"].as_f64().unwrap();
    assert!((0.45..=0.55).contains(&p));
    assert_eq!(r["violation"]["pass_rate_with_required_arg"], 0.0);
    assert_eq!(r["violation"]["required_arg_false_block_rate"], 0.0);
}

#[test]
fn deterministic() {
    assert_eq!(run(100, 7), run(100, 7));
}
