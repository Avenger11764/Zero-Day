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
    "timestamp": "2026-09-04T10:15:00Z",
    "src_ip": "192.168.1.105",
    "dst_ip": "10.0.0.42",
    "anomaly_score": 0.965,
    "confidence": 0.98,
    "risk_score": 98,
    "attack_type_guess": "Execution - Payload Dropper",
    "mitre_technique": "T1204.002",
    "explanation": [
      "Process 'invoice_oct.sh' spawned via clone and execve locally.",
      "No network activity or identity shift, but host syscall sequence matches malicious script dropper behavior."
    ],
    "model_source": "ensembler-3-pillar",
    "is_adversarial_test": false,
    "network_score": 0.05,
    "identity_score": 0.12,
    "host_score": 0.94
  },
  {
    "alert_id": "4fa85f64-5717-4562-b3fc-2c963f66afa2",
    "timestamp": "2026-09-04T10:16:12Z",
    "src_ip": "192.168.1.105",
    "dst_ip": "10.0.0.42",
    "anomaly_score": 0.985,
    "confidence": 0.99,
    "risk_score": 99,
    "attack_type_guess": "Privilege Escalation - Process Injection",
    "mitre_technique": "T1055.008",
    "explanation": [
      "Process 'invoice_oct.sh' executed PTRACE_ATTACH and multiple PTRACE_POKETEXT operations targeting 'sssd'.",
      "Network flow is zero. Identity monitor is blind. Detected purely via Pillar 3 syscall anomaly."
    ],
    "model_source": "ensembler-3-pillar",
    "is_adversarial_test": true,
    "network_score": 0.00,
    "identity_score": 0.00,
    "host_score": 0.99
  },
  {
    "alert_id": "4fa85f64-5717-4562-b3fc-2c963f66afa3",
    "timestamp": "2026-09-04T10:17:25Z",
    "src_ip": "192.168.1.105",
    "dst_ip": "10.0.0.42",
    "anomaly_score": 0.895,
    "confidence": 0.92,
    "risk_score": 92,
    "attack_type_guess": "Persistence - Kernel Module",
    "mitre_technique": "T1547.006",
    "explanation": [
      "Compromised 'sssd' process performed tmpfs mount and init_module 'stealth_mod.ko'.",
      "Strong anomaly signal from host features. Identity pillar detects minor token anomaly."
    ],
    "model_source": "ensembler-3-pillar",
    "is_adversarial_test": true,
    "network_score": 0.00,
    "identity_score": 0.45,
    "host_score": 0.96
  },
  {
    "alert_id": "4fa85f64-5717-4562-b3fc-2c963f66afa4",
    "timestamp": "2026-09-04T10:18:35Z",
    "src_ip": "192.168.1.105",
    "dst_ip": "198.51.100.42",
    "anomaly_score": 0.995,
    "confidence": 0.99,
    "risk_score": 100,
    "attack_type_guess": "Command & Control / Exfiltration",
    "mitre_technique": "T1071.001",
    "explanation": [
      "Compromised process initiated encrypted C2 connection (AF_INET connect to 198.51.100.42:443).",
      "Network flow shape was highly evasive (mimicking CDN telemetry), but multi-modal correlation triggers critical alert."
    ],
    "model_source": "ensembler-3-pillar",
    "is_adversarial_test": true,
    "network_score": 0.35,
    "identity_score": 0.65,
    "host_score": 0.88
  }
];
