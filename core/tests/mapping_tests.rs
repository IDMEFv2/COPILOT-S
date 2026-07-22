use idmefv2_core::convert_eve_to_idmef;

#[test]
fn convert_basic_alert_has_required_fields() {
    // Minimal EVE alert sample (string). This unit test verifies the converter
    // produces an object with mandatory fields and that the schema_version is set.
    let eve = r#"{
        "timestamp":"2026-07-22T12:00:00.000000+0000",
        "event_type":"alert",
        "alert":{ "signature":"Test Sig", "signature_id":1001, "category":"Policy Violation", "severity":2 },
        "src_ip":"1.2.3.4",
        "src_port":12345,
        "dest_ip":"5.6.7.8",
        "dest_port":80,
        "proto":"TCP"
    }"#;

    let msg = convert_eve_to_idmef(eve, "suricata-node-01", "10.0.0.1").expect("conversion");
    assert_eq!(msg.schema_version, "idmefv2-08");
    assert_eq!(msg.analyzer.name, "suricata-node-01");
    assert!(msg.classification.text.len() > 0);
    // severity 2 -> impact 6 per mapping
    assert!(msg.assessment.is_some());
    let asmt = msg.assessment.unwrap();
    assert_eq!(asmt.impact.unwrap(), 6);
}
