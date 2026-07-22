#!/usr/bin/env bash
# build_and_install.sh - build workspace and print next steps
set -e
cargo build --release
echo "Built. Release libraries are in target/release/"
ls -l target/release/libidmefv2* || true
cat <<'EOF'
Next steps (example):
sudo cp target/release/libidmefv2_output.so /usr/lib/suricata/plugins/
sudo cp target/release/libidmefv2_http.so /usr/lib/suricata/plugins/
# edit /etc/suricata/suricata.yaml to add the filetype blocks from examples/suricata_snippet.yaml
# for testing the HTTP plugin, export IDMEFV2_HTTP_ENDPOINT environment variable before starting Suricata:
# export IDMEFV2_HTTP_ENDPOINT="http://localhost:8080/idmef"
# Then start Suricata 8.0.6 and generate some events; check /var/log/suricata/idmefv2.json
EOF
