# Mapping IDMEFv2 (draft-lehmann-idmefv2-08) <- Suricata EVE

Ce document décrit le mapping strict entre les champs Suricata EVE et la
représentation JSON d'IDMEFv2 telle que définie dans le draft lehmann-idmefv2-08.

Principe : respecter mot-à-mot les noms du draft pour les champs obligatoires
et optionnels. Les champs Suricata qui n'ont pas d'équivalent direct sont
mentionnés explicitement et placés, quand pertinent, dans la section "evidence"
avec format="suricata/eve-json".

Fichier JSON Schema utilisé pour valider la sortie : schema/idmefv2-08.schema.json

Mapping principal (Suricata -> IDMEFv2 JSON)

- timestamp -> create_time
  - format : string (ISO 8601)
  - recommandation : obligatoire si disponible

- alert.signature -> classification.text
- alert.signature_id / gid / sid / rev -> classification.references (liste de strings, ex: "gid:1 sid:2010811 rev:1")
- alert.category -> classification.category (valeur normalisée via mappings/categories.yaml)
- alert.severity -> assessment.impact (mapper 0..3 -> 0..10), assessment.confidence default 50

- src_ip/src_port -> sources[].addresses[].address & sources[].service.port
- dest_ip/dest_port -> targets[].addresses[].address & targets[].service.port
- proto -> sources[].service.protocol / targets[].service.protocol

- http.* -> observables[] type="http-transaction" (request/response sub-objects)
- dns.* -> observables[] type="dns"
- tls.* -> observables[] type="tls-handshake"
- flow.* -> observables[] type="network-flow"

Champs non-mappables directement (recommandations)
- pcap_cnt / raw packet bytes : placer dans evidence format "suricata/eve-json" si nécessaire
- suricata specific metadata (thread_id, sensor_id, pcap info) : evidence
- full packet payloads : ne pas transporter par IDMEFv2 (trop volumineux) ; laisser sur la sonde ou dans un spool sécurisé

Exemples d'utilisation de "evidence" :
- evidence[0] = { "format": "suricata/eve-json", "data": <full EVE JSON object> }

Voir mappings/categories.yaml pour la table de correspondance des catégories.
