# COPILOT-S: IDMEFv2 Suricata plugins prototype

This repository contains a prototype implementation (Option A) of two Suricata plugins for IDMEFv2 support:

- idmefv2-output: converts Suricata EVE JSON -> IDMEFv2 JSON and writes NDJSON to a file (safe default)
- idmefv2-http: optional plugin that sends IDMEFv2 JSON over HTTPS (POST) to a configurable endpoint

Design choices (defaults):
- IDMEFv2 representation: JSON (application/idmef+json)
- Schema version field: "schema_version": "idmefv2-08"
- Plugins are Rust cdylib filetype plugins for Suricata 8.x (FFI follows filetype pattern)
- idmefv2-output is safe-by-default and non-blocking (bounded queue + worker)
- idmefv2-http is optional (disabled by default), non-blocking, single sender thread with simple retry/backoff

Quickstart (build & test locally)
1) Install Rust toolchain (stable) and build tools.

2) Build the workspace (release):
   cargo build --release

   This produces shared libraries under target/release:
   - target/release/libidmefv2_output.so
   - target/release/libidmefv2_http.so

3) Install into your Suricata host (example):
   sudo cp target/release/libidmefv2_output.so /usr/lib/suricata/plugins/
   sudo cp target/release/libidmefv2_http.so /usr/lib/suricata/plugins/

4) Edit /etc/suricata/suricata.yaml and add filetype blocks (example in examples/suricata_snippet.yaml).

5) Start Suricata 8.0.6 configured to load plugins and generate EVE events. Check /var/log/suricata/idmefv2.json for NDJSON lines.

Testing the HTTP plugin
- Start a mock HTTP receiver (curl -v -X POST ...) or run the included small mock server (not included in prototype) that prints incoming JSON.
- Enable idmefv2-http in suricata.yaml with endpoint set to your mock receiver and restart Suricata.

Notes & next steps
- This prototype implements a working end-to-end conversion and a safe HTTP sender (in-memory queue + retry). It intentionally omits persistent spool for the prototype version; that will be added in the production variant.
- The code is provided as-is as a reference implementation to experiment and test with Suricata 8.0.6. For an upstream PR we will add CI, benchmarks, extended tests and packaging.

