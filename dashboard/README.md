# ZeroWatch SOC Dashboard Preview

This dashboard project provides a premium security operation center (SOC) user interface, styled after the ZeroWatch design.

## Preview Setup
The dashboard is currently running entirely in static design preview mode. It loads real static snapshot alerts derived from actual adversarial harness evaluation runs (`harness/results/autoencoder_v2_baseline_v2.csv`) mapped to [sampleData.js](file:///d:/downloads/zero-day/dashboard/sampleData.js). It displays them inside the interactive timeline chart, metric summary counts, and the real-time threat feed table.

## Wire up Real API / WebSocket
To connect this user interface to a live threat alert stream:
1. Whoever develops the alerts API should substitute the reference to `sampleData.js` in [index.html](file:///d:/downloads/zero-day/dashboard/index.html) with a live connection.
2. Ensure payloads sent over fetch/WebSocket adhere to the standard payload shape outlined in [/schemas/scored_alert.json](file:///d:/downloads/zero-day/schemas/scored_alert.json).
3. If payload attributes align with `ScoredAlert` properties, no other changes will be required to feed charts, metrics, and details drawer elements.

