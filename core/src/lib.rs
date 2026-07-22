use serde::{Serialize, Deserialize};
use serde_json::json;

// Core IDMEFv2 model used by both plugins.
// This crate is intentionally simple: it provides a minimal Rust representation
// of an IDMEFv2 message and a conversion function from a raw EVE JSON line.
// The goal is to keep mapping logic isolated so it can be unit-tested and
// re-used by multiple outputs (file, HTTP, etc.).

/// Primary IDMEFv2 message structure (JSON representation).
/// Fields are chosen to be simple and explanatory for prototyping.
#[derive(Serialize, Deserialize, Debug)]
pub struct IdmefMessage {
    /// Version of the IDMEFv2 schema used. Helpful for receivers to know
    /// which schema/patch level the message conforms to.
    pub schema_version: String,

    /// Event generation time (copied from Suricata EVE `timestamp` when present).
    pub create_time: String,

    /// Minimal Analyzer block (who produced the message).
    pub analyzer: Analyzer,

    /// Classification block: for simplicity we embed the Suricata `alert` JSON
    /// object directly. In a more formal implementation this would be mapped
    /// to typed fields from the draft.
    pub classification: serde_json::Value,

    /// Optional source address (ip + optional port), if present in EVE.
    pub source: Option<Address>,

    /// Optional target address (ip + optional port), if present in EVE.
    pub target: Option<Address>,

    /// The original EVE JSON object retained for traceability and debugging.
    /// Keeping the original event inline simplifies debugging and allows the
    /// receiver to inspect raw fields if needed.
    pub original: serde_json::Value,
}

/// Simple Analyzer information.
#[derive(Serialize, Deserialize, Debug)]
pub struct Analyzer {
    /// Human readable analyzer name (example: "suricata-node-01").
    pub name: String,

    /// IP of the analyzer (useful when multiple sensors send to same manager).
    pub ip: String,
}

/// Address structure (IP + optional port).
#[derive(Serialize, Deserialize, Debug)]
pub struct Address {
    pub ip: String,
    pub port: Option<u16>,
}

/// Convert raw EVE JSON string into an IDMEFv2 JSON line (NDJSON).
///
/// - `eve_line`: single line JSON produced by Suricata EVE (one event per line)
/// - `analyzer_name` / `analyzer_ip`: metadata to include in the IDMEF message
///
/// Returns Some(json_line) on success or None if parsing/serialization failed.
pub fn convert_eve_to_idmef(eve_line: &str, analyzer_name: &str, analyzer_ip: &str) -> Option<String> {
    // Parse the incoming EVE JSON safely.
    let v: serde_json::Value = match serde_json::from_str(eve_line) {
        Ok(j) => j,
        Err(_) => return None, // invalid JSON line -> drop (caller may log)
    };

    // Extract a timestamp if present; fallback to empty string.
    let create_time = v.get("timestamp").and_then(|t| t.as_str()).unwrap_or("").to_string();

    // Keep Suricata `alert` object as classification. If missing, inject JSON null.
    let alert = v.get("alert").cloned().unwrap_or(json!(null));

    // Extract common network fields (suricata top-level naming conventions)
    let src_ip = v.get("src_ip").and_then(|s| s.as_str()).map(|s| s.to_string());
    let src_port = v.get("src_port").and_then(|p| p.as_u64()).map(|p| p as u16);
    let dst_ip = v.get("dest_ip").and_then(|s| s.as_str()).map(|s| s.to_string());
    let dst_port = v.get("dest_port").and_then(|p| p.as_u64()).map(|p| p as u16);

    // Construct optional Address structs when IPs are available.
    let source = src_ip.map(|ip| Address { ip, port: src_port });
    let target = dst_ip.map(|ip| Address { ip, port: dst_port });

    // Assemble the IDMEF message.
    let msg = IdmefMessage {
        schema_version: "idmefv2-08".to_string(),
        create_time: create_time,
        analyzer: Analyzer { name: analyzer_name.to_string(), ip: analyzer_ip.to_string() },
        classification: alert,
        source,
        target,
        original: v,
    };

    // Serialize to compact JSON (one line). Return None on serialization error.
    match serde_json::to_string(&msg) {
        Ok(s) => Some(s),
        Err(_) => None,
    }
}
