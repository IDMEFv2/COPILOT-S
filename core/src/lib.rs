use serde::{Serialize, Deserialize};
use serde_json::json;

#[derive(Serialize, Deserialize, Debug)]
pub struct IdmefMessage {
    pub schema_version: String,
    pub create_time: String,
    pub analyzer: Analyzer,
    pub classification: serde_json::Value,
    pub source: Option<Address>,
    pub target: Option<Address>,
    pub original: serde_json::Value,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Analyzer {
    pub name: String,
    pub ip: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Address {
    pub ip: String,
    pub port: Option<u16>,
}

/// Convert raw EVE JSON string into IDMEFv2 JSON string (NDJSON line)
pub fn convert_eve_to_idmef(eve_line: &str, analyzer_name: &str, analyzer_ip: &str) -> Option<String> {
    let v: serde_json::Value = match serde_json::from_str(eve_line) {
        Ok(j) => j,
        Err(_) => return None,
    };
    let create_time = v.get("timestamp").and_then(|t| t.as_str()).unwrap_or("").to_string();

    let alert = v.get("alert").cloned().unwrap_or(json!(null));

    let src_ip = v.get("src_ip").and_then(|s| s.as_str()).map(|s| s.to_string());
    let src_port = v.get("src_port").and_then(|p| p.as_u64()).map(|p| p as u16);
    let dst_ip = v.get("dest_ip").and_then(|s| s.as_str()).map(|s| s.to_string());
    let dst_port = v.get("dest_port").and_then(|p| p.as_u64()).map(|p| p as u16);

    let source = src_ip.map(|ip| Address { ip, port: src_port });
    let target = dst_ip.map(|ip| Address { ip, port: dst_port });

    let msg = IdmefMessage {
        schema_version: "idmefv2-08".to_string(),
        create_time: create_time,
        analyzer: Analyzer { name: analyzer_name.to_string(), ip: analyzer_ip.to_string() },
        classification: alert,
        source,
        target,
        original: v,
    };

    match serde_json::to_string(&msg) {
        Ok(s) => Some(s),
        Err(_) => None,
    }
}
