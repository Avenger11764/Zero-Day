/**
 * REAL DATA — derived from actual adversarial harness runs 
 * (harness/results/autoencoder_v2_baseline_v2.csv).
 * Still a static snapshot, not a live feed — replace with a real API/WebSocket
 * connection once that module is ready.
 * 
 * NOTE: IP addresses and exact timestamps are illustrative synthetics added 
 * for dashboard visualization context, as the evaluation harness computes 
 * anomaly metrics over feature lists directly.
 */
const sampleAlerts = [
  {
    "alert_id": "4fa85f64-5717-4562-b3fc-2c963f66afa1",
    "timestamp": "2026-07-19T14:26:04Z",
    "src_ip": "192.168.1.105",
    "dst_ip": "10.0.0.42",
    "anomaly_score": 1.597088,
    "confidence": 0.0,
    "risk_score": 100,
    "attack_type_guess": "Slow Drip Attack",
    "mitre_technique": "T1046",
    "explanation": [
      "Splitting aggregate flows into low volume drips failed to bypass baseline autoencoder detection since key volumetric ratios remain highly anomalous.",
      "Perturbed features (fwd_act_data_pkts, pkt_len_max) trigger high reconstruction error even at divided scales."
    ],
    "model_source": "autoencoder-v2-256",
    "is_adversarial_test": true,
    "feature_vector": [0.0] * 76 // Placeholder for visualization compatibility
  },
  {
    "alert_id": "4fa85f64-5717-4562-b3fc-2c963f66afa2",
    "timestamp": "2026-07-19T14:25:34Z",
    "src_ip": "192.168.1.105",
    "dst_ip": "10.0.0.42",
    "anomaly_score": 0.977425,
    "confidence": 0.022575,
    "risk_score": 97,
    "attack_type_guess": "Mimicry Attack",
    "mitre_technique": "T1059.001",
    "explanation": [
      "Linear interpolation toward benign profile in step 10 remains flagged as anomalous.",
      "High-impact packet length distributions have not yet converged closely enough to benign distribution thresholds."
    ],
    "model_source": "autoencoder-v2-256",
    "is_adversarial_test": true,
    "feature_vector": [0.0] * 76
  },
  {
    "alert_id": "4fa85f64-5717-4562-b3fc-2c963f66afa3",
    "timestamp": "2026-07-19T14:22:04Z",
    "src_ip": "192.168.1.105",
    "dst_ip": "10.0.0.42",
    "anomaly_score": 0.490205,
    "confidence": 0.509795,
    "risk_score": 49,
    "attack_type_guess": "Mimicry Attack",
    "mitre_technique": "T1059.001",
    "explanation": [
      "Linear interpolation at step 15 successfully evades detection.",
      "Reconstruction error of high-impact features falls below 0.5 threshold as vector moves closer to target benign shape."
    ],
    "model_source": "autoencoder-v2-256",
    "is_adversarial_test": true,
    "feature_vector": [0.0] * 76
  },
  {
    "alert_id": "4fa85f64-5717-4562-b3fc-2c963f66afa4",
    "timestamp": "2026-07-19T14:21:58Z",
    "src_ip": "172.16.254.1",
    "dst_ip": "10.0.0.88",
    "anomaly_score": 0.977425,
    "confidence": 0.022575,
    "risk_score": 97,
    "attack_type_guess": "Feature Padding Attack",
    "mitre_technique": "T1059.001",
    "explanation": [
      "Direct perturbation of highly sensitive packet header statistics triggers high reconstruction error.",
      "Interpolating only top 10 different features at step 10 is still flagged as out-of-distribution."
    ],
    "model_source": "autoencoder-v2-256",
    "is_adversarial_test": true,
    "feature_vector": [0.0] * 76
  },
  {
    "alert_id": "4fa85f64-5717-4562-b3fc-2c963f66afa5",
    "timestamp": "2026-07-19T14:21:42Z",
    "src_ip": "203.0.113.44",
    "dst_ip": "10.12.0.5",
    "anomaly_score": 0.490205,
    "confidence": 0.509795,
    "risk_score": 49,
    "attack_type_guess": "Feature Padding Attack",
    "mitre_technique": "T1059.001",
    "explanation": [
      "Feature padding evasion at step 15 successfully reduces reconstruction error below 0.5 detection threshold.",
      "Selective blending of top different features effectively hides anomalous packets."
    ],
    "model_source": "autoencoder-v2-256",
    "is_adversarial_test": true,
    "feature_vector": [0.0] * 76
  }
];
