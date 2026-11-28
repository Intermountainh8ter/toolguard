use toolguard::malformedarg::run;

#[test]
fn validators_follow_definitions() {
    let r = run(200, 7);
    let c = &r["clean_rejection"];
    assert_eq!(c["strict_rate_uniform_mix"], 1.0);
    assert_eq!(c["accept_all_rate_uniform_mix"], 0.0);
    let l = c["lenient_rate_uniform_mix"].as_f64().unwrap();
    assert!((0.35..=0.45).contains(&l));
    assert_eq!(r["well_formed"]["strict_false_reject_rate"], 0.0);
}

#[test]
fn deterministic() {
    assert_eq!(run(50, 7), run(50, 7));
}
