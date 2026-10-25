# ZeroWatch SOC Dashboard Preview

This dashboard project provides a premium security operation center (SOC) user interface, styled after the ZeroWatch design.

## Preview Setup
The dashboard is currently running entirely in static design preview mode. It loads real static snapshot alerts derived from actual adversarial harness evaluation runs (`harness/results/autoencoder_v2_baseline_v2.csv`) mapped to [sampleData.js](file:///d:/downloads/zero-day/dashboard/sampleData.js). It displays them inside the interactive timeline chart, metric summary counts, and the real-time threat feed table.

## Wire up Real API / WebSocket
To connect this user interface to a live threat alert stream:
1. Whoever develops the alerts API should substitute the reference to `sampleData.js` in [index.html](file:///d:/downloads/zero-day/dashboard/index.html) with a live connection.
2. Ensure payloads sent over fetch/WebSocket adhere to the standard payload shape outlined in [/schemas/scored_alert.json](file:///d:/downloads/zero-day/schemas/scored_alert.json).
3. If payload attributes align with `ScoredAlert` properties, no other changes will be required to feed charts, metrics, and details drawer elements.

## Week 6 alert detail fields

The alert drawer accepts the grouped `pillar_scores` object (`network`,
`identity`, `host`) and the legacy top-level `network_score`, `identity_score`,
and `host_score` fields. The top-level values take precedence when both forms
are present. It also displays optional `host_attack_mappings`,
`host_mapping_status`, `host_explanation`, and privacy-minimized
`host_shap_features`. The drawer uses text nodes for these dynamic details; do
not put raw host identifiers, command lines, or sensitive paths in the payload.

The dashboard remains in static preview mode and does not load a real API or
WebSocket yet. Its rendering of these fields is not a substitute for validating
the live API pipeline.
