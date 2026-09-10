use auditor::{Amount, ReleaseRate};
use std::time::Duration;

#[test]
fn deserialization_cannot_bypass_the_nonzero_window_invariant() {
    let invalid = r#"{"max_amount":"50","window":{"secs":0,"nanos":0}}"#;
    let err = serde_json::from_str::<ReleaseRate>(invalid).unwrap_err();
    assert!(err
        .to_string()
        .contains("release rate window must be non-zero"));
}

#[test]
fn positive_and_subsecond_rate_json_remain_compatible() {
    for window in [Duration::from_secs(60), Duration::from_nanos(1)] {
        let rate = ReleaseRate::new(Amount::from_base_units(50), window).unwrap();
        let json = serde_json::to_string(&rate).unwrap();
        let decoded: ReleaseRate = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, rate);
        assert_eq!(
            decoded.max_released_within(window),
            Amount::from_base_units(50)
        );
    }
}
