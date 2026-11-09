mod support;

use serde_json::{Value, json};

#[test]
fn historical_snapshot_keys_ignore_only_object_insertion_order() {
    let original: Vec<Value> =
        serde_json::from_str(r#"[{"z":{"b":2,"a":1},"a":[{"d":4,"c":3},false]}]"#).unwrap();
    let reordered: Vec<Value> =
        serde_json::from_str(r#"[{"a":[{"c":3,"d":4},false],"z":{"a":1,"b":2}}]"#).unwrap();
    let before = serde_json::to_string(&original).unwrap();
    let expected = support::snapshot_path("fixture", &original);
    assert_eq!(expected, support::snapshot_path("fixture", &reordered));
    assert_eq!(before, serde_json::to_string(&original).unwrap());

    let mut changed_value = original.clone();
    changed_value[0]["z"]["b"] = json!(3);
    assert_ne!(expected, support::snapshot_path("fixture", &changed_value));
    let mut changed_order = original.clone();
    changed_order[0]["a"].as_array_mut().unwrap().reverse();
    assert_ne!(expected, support::snapshot_path("fixture", &changed_order));
    let mut changed_type = original.clone();
    changed_type[0]["z"]["b"] = json!("2");
    assert_ne!(expected, support::snapshot_path("fixture", &changed_type));
}

#[test]
fn different_cases_cannot_reuse_or_regenerate_recorded_answers() {
    let cases = vec![json!({"source":"plain"}), json!({"source":"'single'"})];
    // Different input must fail closed instead of falling back to an answer
    // for another case list or generating an answer from the current code.
    assert!(!support::snapshot_path("tag_scalar", &cases).exists());
    assert!(std::panic::catch_unwind(|| support::oracle("tag_scalar", &cases)).is_err());
}
