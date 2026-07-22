use serde::{Serialize, Deserialize};
use serde_json::json;

// IDMEFv2 core model (aligned to draft-lehmann-idmefv2-08)
// This representation focuses on the elements defined by the draft used as the
// normative source of truth: schema_version, create_time, analyzer,
// classification, sources, targets, assessment, observables, evidence.
// The goal is strict conformity: fields are named to match the draft and the
// conversion function produces a JSON object that validates against the
// provided JSON Schema (idmefv2-08.schema.json).

#[derive(Serialize, Deserialize, Debug)]
pub struct Idmefv2Message {
    /// Draft version identifier
    pub schema_version: String,

    /// Time the event was created (ISO 8601)
    pub create_time: String,

    /// Analyzer (the sensor producing the IDMEF message)
    pub analyzer: Analyzer,

    /// Classification block (what was detected)
    pub classification: Classification,

    /// One or more source endpoints observed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sources: Option<Vec<Node>>,

    /// One or more target endpoints observed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub targets: Option<Vec<Node>>,

    /// Assessment (impact / confidence)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assessment: Option<Assessment>,

    /// Observables: protocol-specific structured data (http, dns, tls, flow...)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observables: Option<Vec<Observable>>,

    /// Evidence / attachments: where necessary to include original logs
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<Vec<Evidence>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Analyzer {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Classification {
    pub text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub references: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Node {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub addresses: Option<Vec<Address>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<Service>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<Host>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Address {
    pub address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Service {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Host {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Assessment {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub impact: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type", content = "data")]
pub enum Observable {
    #[serde(rename = "http-transaction")]
    HttpTransaction(HttpTransaction),
    #[serde(rename = "dns")]
    Dns(DnsObservable),
    #[serde(rename = "network-flow")]
    NetworkFlow(FlowObservable),
    #[serde(rename = "tls-handshake")]
    TlsHandshake(TlsObservable),
    #[serde(other)]
    Other(serde_json::Value),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct HttpTransaction {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<HttpMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<HttpMessage>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct HttpMessage {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_len: Option<u64>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DnsObservable {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qtype: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub answers: Option<serde_json::Value>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct FlowObservable {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pkts_to_server: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pkts_to_client: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TlsObservable {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ja3: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_issuer: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Evidence {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

// Convert raw EVE JSON line into an Idmefv2Message strictly following the
// draft structure above. If a Suricata field has no direct place in the
// draft, we put it into the evidence array (format="suricata/eve-json").
pub fn convert_eve_to_idmef(eve_line: &str, analyzer_name: &str, analyzer_ip: &str) -> Option<Idmefv2Message> {
    let v: serde_json::Value = match serde_json::from_str(eve_line) {
        Ok(j) => j,
        Err(_) => return None,
    };

    // create_time
    let create_time = v.get("timestamp").and_then(|t| t.as_str()).unwrap_or("").to_string();

    // classification
    let alert = v.get("alert");
    let mut classification = Classification {
        text: String::from(""),
        references: None,
        category: None,
    };
    if let Some(alert_obj) = alert {
        if let Some(sig) = alert_obj.get("signature").and_then(|s| s.as_str()) {
            classification.text = sig.to_string();
        }
        // build references from gid/sid/rev if present
        let mut refs: Vec<String> = Vec::new();
        if let Some(gid) = alert_obj.get("gid").and_then(|x| x.as_u64()) {
            if let Some(sid) = alert_obj.get("signature_id").and_then(|x| x.as_u64()) {
                let rev = alert_obj.get("revision").and_then(|x| x.as_u64()).unwrap_or(0);
                refs.push(format!("gid:{} sid:{} rev:{}", gid, sid, rev));
            }
        } else if let Some(sid) = alert_obj.get("signature_id").and_then(|x| x.as_u64()) {
            let rev = alert_obj.get("revision").and_then(|x| x.as_u64()).unwrap_or(0);
            refs.push(format!("sid:{} rev:{}", sid, rev));
        }
        if !refs.is_empty() { classification.references = Some(refs); }
        if let Some(cat) = alert_obj.get("category").and_then(|c| c.as_str()) {
            // mapping to IDMEFv2 category will be done externally via categories.yaml
            classification.category = Some(cat.to_string());
        }
    }

    // sources and targets
    let mut sources: Vec<Node> = Vec::new();
    let mut targets: Vec<Node> = Vec::new();

    if let Some(src_ip) = v.get("src_ip").and_then(|s| s.as_str()) {
        let mut addr = Address { address: src_ip.to_string(), r#type: Some(String::from("ipv4")) };
        let mut svc = Service { name: None, port: None, protocol: None };
        if let Some(src_port) = v.get("src_port").and_then(|p| p.as_u64()) {
            svc.port = Some(src_port as u16);
        }
        if let Some(proto) = v.get("proto").and_then(|p| p.as_str()) {
            svc.protocol = Some(proto.to_string());
        }
        sources.push(Node { addresses: Some(vec![addr]), service: Some(svc), host: None });
    }
    if let Some(dst_ip) = v.get("dest_ip").and_then(|s| s.as_str()) {
        let mut addr = Address { address: dst_ip.to_string(), r#type: Some(String::from("ipv4")) };
        let mut svc = Service { name: None, port: None, protocol: None };
        if let Some(dst_port) = v.get("dest_port").and_then(|p| p.as_u64()) {
            svc.port = Some(dst_port as u16);
        }
        if let Some(proto) = v.get("proto").and_then(|p| p.as_str()) {
            svc.protocol = Some(proto.to_string());
        }
        targets.push(Node { addresses: Some(vec![addr]), service: Some(svc), host: None });
    }

    let sources_opt = if sources.is_empty() { None } else { Some(sources) };
    let targets_opt = if targets.is_empty() { None } else { Some(targets) };

    // assessment: map severity if present
    let mut assessment: Option<Assessment> = None;
    if let Some(alert_obj) = alert {
        if let Some(sev) = alert_obj.get("severity").and_then(|s| s.as_u64()) {
            let impact = match sev {
                0 => 0u8,
                1 => 3u8,
                2 => 6u8,
                3 => 9u8,
                _ => 5u8,
            };
            assessment = Some(Assessment { impact: Some(impact), confidence: Some(50) });
        }
    }

    // observables: try to detect protocol specific blocks and build observables
    let mut observables: Vec<Observable> = Vec::new();

    if let Some(http) = v.get("http") {
        // Build an http-transaction observable from common fields
        let mut req = HttpMessage { method: None, url: None, user_agent: None, status: None, body_len: None };
        let mut resp = HttpMessage { method: None, url: None, user_agent: None, status: None, body_len: None };
        if let Some(m) = http.get("http_method").and_then(|m| m.as_str()) { req.method = Some(m.to_string()); }
        if let Some(u) = http.get("url").and_then(|u| u.as_str()) { req.url = Some(u.to_string()); }
        if let Some(ua) = http.get("http_user_agent").and_then(|ua| ua.as_str()) { req.user_agent = Some(ua.to_string()); }
        if let Some(status) = http.get("status").and_then(|s| s.as_u64()) { resp.status = Some(status as u16); }
        if req.method.is_some() || req.url.is_some() || resp.status.is_some() || req.user_agent.is_some() {
            observables.push(Observable::HttpTransaction(HttpTransaction { request: Some(req), response: Some(resp) }));
        }
    }

    if let Some(dns) = v.get("dns") {
        let mut d = DnsObservable { qname: None, qtype: None, answers: None };
        if let Some(q) = dns.get("rrname").and_then(|r| r.as_str()) { d.qname = Some(q.to_string()); }
        if let Some(t) = dns.get("rrtype").and_then(|t| t.as_str()) { d.qtype = Some(t.to_string()); }
        if d.qname.is_some() || d.qtype.is_some() {
            observables.push(Observable::Dns(d));
        }
    }

    if let Some(flow) = v.get("flow") {
        let mut f = FlowObservable { id: None, duration_ms: None, pkts_to_server: None, pkts_to_client: None, bytes: None };
        if let Some(id) = flow.get("flow_id").and_then(|i| i.as_u64()) { f.id = Some(id); }
        if let Some(dur) = flow.get("duration_ms").and_then(|d| d.as_u64()) { f.duration_ms = Some(dur); }
        if f.id.is_some() || f.duration_ms.is_some() { observables.push(Observable::NetworkFlow(f)); }
    }

    if let Some(tls) = v.get("tls") {
        let mut t = TlsObservable { sni: None, ja3: None, cert_subject: None, cert_issuer: None };
        if let Some(sni) = tls.get("sni").and_then(|s| s.as_str()) { t.sni = Some(sni.to_string()); }
        if let Some(ja3) = tls.get("ja3").and_then(|j| j.as_str()) { t.ja3 = Some(ja3.to_string()); }
        if t.sni.is_some() || t.ja3.is_some() { observables.push(Observable::TlsHandshake(t)); }
    }

    // Build evidence: place the full original EVE JSON as evidence of format suricata/eve-json
    let evidence = Evidence { format: Some(String::from("suricata/eve-json")), data: Some(v.clone()) };

    let msg = Idmefv2Message {
        schema_version: String::from("idmefv2-08"),
        create_time,
        analyzer: Analyzer { name: analyzer_name.to_string(), ip: Some(analyzer_ip.to_string()) },
        classification,
        sources: sources_opt,
        targets: targets_opt,
        assessment,
        observables: if observables.is_empty() { None } else { Some(observables) },
        evidence: Some(vec![evidence]),
    };

    Some(msg)
}
