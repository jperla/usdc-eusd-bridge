use auditor::{
    Amount, AuditPolicy, BoundParams, Bytes32, DepositEvent, EthAddress, FreezeDecision,
    FreezeReason, MatchPolicy, ReleaseRate, ReleaseRecord,
};
use e2e::{evaluate, evaluate_json, AuditRequest, AuditResponse};
use std::time::Duration;

fn request() -> AuditRequest {
    let amount = Amount::from_base_units(50_000_000);
    AuditRequest {
        deposits: vec![DepositEvent {
            deposit_id: 0,
            depositor: EthAddress([1; 20]),
            amount,
            mob_destination: Bytes32([3; 32]),
            block_number: 1,
            log_index: 0,
            timestamp: 100,
        }],
        releases: vec![ReleaseRecord {
            release_id: Bytes32([4; 32]),
            claimed_deposit_id: Some(0),
            amount,
            mob_destination: Bytes32([3; 32]),
            block_index: 2,
            timestamp: 101,
        }],
        policy: AuditPolicy {
            matching: MatchPolicy::default(),
            bound: BoundParams {
                remaining_balance: amount,
                rho: ReleaseRate::per_second(amount),
                delta_eff: Duration::from_secs(1),
                recall_horizon: Duration::ZERO,
            },
            freeze_on_anomaly: true,
        },
        now: 102,
    }
}

#[test]
fn matching_release_continues_without_a_freeze_reason() {
    let input = serde_json::to_string(&request()).unwrap();
    let response: AuditResponse = serde_json::from_str(&evaluate_json(&input).unwrap()).unwrap();
    match response.decision {
        FreezeDecision::Continue { stats } => assert_eq!(stats.matched, 1),
        _ => panic!("matching release froze"),
    }
    assert_eq!(response.escrow_reason, None);
}

#[test]
fn rogue_and_double_releases_return_the_real_auditors_exact_reason() {
    let mut rogue = request();
    rogue.releases[0].claimed_deposit_id = None;
    let mut double = request();
    let mut second = double.releases[0];
    second.release_id = Bytes32([5; 32]);
    second.block_index += 1;
    double.releases.push(second);
    for (input, expected) in [
        (rogue, FreezeReason::UnbackedRelease),
        (double, FreezeReason::DoubleRelease),
    ] {
        let response = evaluate(input).unwrap();
        assert_eq!(response.decision.reason(), Some(expected));
        assert_eq!(response.escrow_reason, response.decision.escrow_reason());
        assert!(response
            .escrow_reason
            .unwrap()
            .starts_with(&format!("auditor/{} ", expected.slug())));
    }
}

#[test]
fn conflicting_records_are_errors_not_clean_audits() {
    let mut input = request();
    let mut conflicting = input.deposits[0];
    conflicting.amount = Amount::from_base_units(1);
    input.deposits.push(conflicting);
    assert!(evaluate(input).unwrap_err().contains("conflicting deposit"));
    let mut input = request();
    let mut conflicting = input.releases[0];
    conflicting.amount = Amount::from_base_units(1);
    input.releases.push(conflicting);
    assert!(evaluate(input).unwrap_err().contains("conflicting release"));
}

#[test]
fn decimal_amounts_above_javascript_precision_are_preserved() {
    let mut input = request();
    let amount = Amount::from_base_units((1u128 << 100) + 7);
    input.deposits[0].amount = amount;
    input.releases[0].amount = amount;
    let json = serde_json::to_string(&input).unwrap();
    assert!(json.contains(&format!("\"amount\":\"{amount}\"")));
    let parsed: AuditRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.deposits[0].amount, amount);
    assert!(!evaluate(parsed).unwrap().decision.is_freeze());
}

#[test]
fn malformed_input_never_produces_a_decision() {
    let original = serde_json::to_value(request()).unwrap();
    let mut numeric_amount = original.clone();
    numeric_amount["deposits"][0]["amount"] = serde_json::json!(50_000_000);
    let mut short_key = original.clone();
    short_key["releases"][0]["release_id"] = serde_json::json!("0x01");
    let mut unknown = original.clone();
    unknown["ignore_audit"] = serde_json::json!(true);
    let mut zero_window = original;
    zero_window["policy"]["bound"]["rho"]["window"] = serde_json::json!({"secs":0,"nanos":0});
    for value in [numeric_amount, short_key, unknown, zero_window] {
        assert!(evaluate_json(&value.to_string()).is_err());
    }
    assert!(evaluate_json("{}").is_err());
    assert!(evaluate_json("not JSON").is_err());
}

#[test]
fn cli_errors_exit_nonzero_without_printing_a_continue_decision() {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut child = Command::new(env!("CARGO_BIN_EXE_auditor-decision"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"not JSON").unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8(output.stderr)
        .unwrap()
        .contains("invalid audit input"));
}
