use toolguard::labelnoise::run;

#[test]
fn zero_noise_has_no_misses() {
    let r = run(200, 7, 0.0, 0.0);
    assert_eq!(r["label_noise"]["dangerous_below_threshold_fraction_adjacent"], 0.0);
    assert_eq!(r["label_noise"]["dangerous_below_threshold_fraction_random"], 0.0);
}

#[test]
fn full_adjacent_flip_demotes_every_dangerous_tool() {
    let r = run(200, 7, 1.0, 0.0);
    assert_eq!(r["label_noise"]["dangerous_below_threshold_fraction_adjacent"], 1.0);
}

#[test]
fn deterministic_and_seed_sensitive() {
    assert_eq!(run(300, 7, 0.4, 0.1), run(300, 7, 0.4, 0.1));
    assert_ne!(run(300, 7, 0.4, 0.1), run(300, 8, 0.4, 0.1));
}
