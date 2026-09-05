//! Executable auditor decision handoff, exercised by scripts/auditor-handoff.mjs.
//!
//! This is a component integration, not a complete bridge: decoded Ethereum
//! logs and supplied MobileCoin release records enter the real auditor, and
//! its freeze reason is submitted to real Escrow bytecode by the Node test.
//! No live feed, attestation authentication, transaction inclusion, or MobileCoin
//! issuance is implemented here. Malformed/conflicting input returns an error;
//! callers must never interpret failure to audit as permission to continue.

use auditor::{audit, AuditPolicy, DepositEvent, FreezeDecision, Ledger, ReleaseRecord};
use serde::{Deserialize, Serialize};

/// A complete, already-decoded observation and explicit auditor policy.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditRequest {
    /// Ethereum deposit logs, with their containing block metadata.
    pub deposits: Vec<DepositEvent>,
    /// MobileCoin release attestations; the feed is trusted at this boundary.
    pub releases: Vec<ReleaseRecord>,
    /// Matching rules and declared exposure parameters.
    pub policy: AuditPolicy,
    /// Observation time in Unix seconds.
    pub now: u64,
}

/// The real auditor's decision and its exact on-chain reason, if any.
#[derive(Debug, Deserialize, Serialize)]
pub struct AuditResponse {
    /// Full decision, including either clean-run statistics or freeze evidence.
    pub decision: FreezeDecision,
    /// Calldata string produced by FreezeDecision::escrow_reason.
    pub escrow_reason: Option<String>,
}

/// Ingest without overwriting contradictory records and execute the real audit.
pub fn evaluate(request: AuditRequest) -> Result<AuditResponse, String> {
    let mut ledger = Ledger::new();
    for deposit in request.deposits {
        ledger.ingest_deposit(deposit).map_err(|e| e.to_string())?;
    }
    for release in request.releases {
        ledger.ingest_release(release).map_err(|e| e.to_string())?;
    }
    let decision = audit(&ledger, &request.policy, request.now);
    let escrow_reason = decision.escrow_reason();
    Ok(AuditResponse {
        decision,
        escrow_reason,
    })
}

/// Parse one JSON document; malformed input is an error, never Continue.
pub fn evaluate_json(input: &str) -> Result<String, String> {
    let request = serde_json::from_str(input).map_err(|e| format!("invalid audit input: {e}"))?;
    serde_json::to_string(&evaluate(request)?).map_err(|e| e.to_string())
}
