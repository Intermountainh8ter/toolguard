use toolguard::viewgap::run;

#[test]
fn invisible_insertions_evade_view_but_not_pin() {
    let r = run(300, 7);
    for c in ["tag_block", "zero_width"] {
        assert_eq!(r["classes"][c]["pin_detection_rate"], 1.0);
        assert_eq!(r["classes"][c]["rendered_diff_detection_rate"], 0.0);
    }
}

#[test]
fn visible_edit_caught_by_both() {
    let r = run(300, 7);
    assert_eq!(r["classes"]["visible_edit"]["pin_detection_rate"], 1.0);
    assert_eq!(r["classes"]["visible_edit"]["rendered_diff_detection_rate"], 1.0);
}

#[test]
fn reformat_is_not_a_pin_alarm() {
    let r = run(300, 7);
    assert_eq!(r["benign_reformat"]["pin_false_alarm_rate"], 0.0);
    assert_eq!(r["classes"]["key_reorder"]["pin_detection_rate"], 0.0);
}

#[test]
fn deterministic_and_seed_sensitive_mutations() {
    use rand::SeedableRng;
    use toolguard::viewgap::{mutate, rendered};
    let def = serde_json::json!({"name": "rm", "description": "rm: run the rm operation as documented"});
    let mut a = rand_pcg::Pcg64Mcg::seed_from_u64(7);
    let mut b = rand_pcg::Pcg64Mcg::seed_from_u64(7);
    assert_eq!(mutate("tag_block", &def, &mut a), mutate("tag_block", &def, &mut b));
    assert_eq!(run(100, 7), run(100, 7));
    let m = mutate("tag_block", &def, &mut a);
    assert_ne!(m, def);
    assert_eq!(rendered(&m), rendered(&def));
}
