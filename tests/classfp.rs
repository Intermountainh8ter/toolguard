use toolguard::classfp::run;

#[test]
fn classes_differ_and_phrase_free_class_is_clean() {
    let r = run(1000, 7);
    assert_eq!(r["classes"]["send_credentials"]["false_positive_rate"], 0.0);
    assert!(r["per_class"]["spread"].as_f64().unwrap() >= 0.25);
}

#[test]
fn deterministic() {
    assert_eq!(run(100, 7), run(100, 7));
}
