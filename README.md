# COPILOT-S (IDMEFv2) — README update

This repository now uses the draft-lehmann-idmefv2-08 as the normative
specification for IDMEFv2. The core crate produces messages conforming to
that draft. A JSON Schema is provided in schema/idmefv2-08.schema.json for
basic validation.

See mappings/idmefv2_mapping.md for an exhaustive field-by-field mapping
and mappings/categories.yaml for the canonical category table.

Important: fields from Suricata EVE that do not have strict places in the
IDMEFv2 draft are placed into the "evidence" array with format
"suricata/eve-json". This choice preserves traceability without violating
the draft structure. The README documents recommended handling for each
non-mappable field (indispensable / optional / leave-on-sensor).
