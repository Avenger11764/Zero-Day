/**
 * ZERO-DAY FYP SOC DASHBOARD DATA SNAPSHOT
 * Status: snapshot, not live
 * 
 * Generated automatically by harness/build_dashboard_snapshot.py
 * Source evaluation files:
 *   - harness/results/host_attack_story_summary.json (Kill-chain stages)
 *   - harness/results/m5b_evasion.csv (Real GNN relational evasion results)
 *   - harness/results/autoencoder_v2_baseline_v2.csv (Real flow baseline evaluations)
 * 
 * DATA INTEGRITY & MEASUREMENT TRANSPARENCY:
 * - Network (P1) scores for network evasion entries are REAL MEASURED values from M5b/M5a.
 * - Host (P3) scores for kill-chain entries are STAGED/SIMULATED pending Person B's 128-D
 *   model delivery (see docs/REQUEST_TO_PERSON_B.md). Syscall traces are verified via Person A.
 * - Identity (P2) scores are STAGED/SIMULATED (pending UEBA integration).
 * - No live backend, no Alert API, no fetch(), no WebSockets.
 */

const sampleAlerts = [
  {
    "alert_id": "4fa85f64-5717-4562-b3fc-2c963f66afa1",
    "timestamp": "2026-10-01T10:15:00Z",
    "src_ip": "192.168.1.105",
    "dst_ip": "10.0.0.42",
    "anomaly_score": 0.94,
    "confidence": 0.98,
    "risk_score": 98,
    "attack_type_guess": "Execution - Payload Dropper [STAGED PREVIEW]",
    "mitre_technique": "T1204.002",
    "explanation": [
      "[STAGED PREVIEW] Host score simulated: awaiting Person B 128-D model. Syscall trace verified with Person A extractor.",
      "Process 'invoice_oct.sh' spawned via clone and execve locally.",
      "P1 & P2 quiet. Detected via Pillar 3 syscall execution anomaly."
    ],
    "model_source": "ensembler-3-pillar (snapshot preview)",
    "is_adversarial_test": true,
    "badge_text": "STAGED_HOST",
    "data_source_status": {
      "network": "measured (M5b/M5a baseline)",
      "identity": "staged / simulated (pending UEBA integration)",
      "host": "staged (pending Person B 128-D HostAutoencoder)"
    },
    "network_score": 0.05,
    "identity_score": 0.12,
    "host_score": 0.94,
    "pillar_scores": {
      "network": 0.05,
      "identity": 0.12,
      "host": 0.94
    },
    "host_mapping_status": "candidate",
    "host_attack_mappings": [
      {
        "technique_id": "T1204.002",
        "mitre_technique": "User Execution: Malicious File",
        "mitre_tactic": "Execution",
        "severity": "HIGH",
        "evidence": [
          "execve of unsigned script from user temp directory",
          "clone event from Thunderbird context"
        ],
        "evidence_complete": true
      }
    ],
    "host_explanation": [
      "Candidate mapping based on evidence in attack_mappers/host_syscall_attack_mapper.json."
    ],
    "host_shap_features": [
      {
        "feature": "ctx_is_root",
        "shap_value": 0.0412,
        "direction": "increases_anomaly"
      },
      {
        "feature": "time_mean_delta",
        "shap_value": 0.0385,
        "direction": "increases_anomaly"
      },
      {
        "feature": "ret_success_rate",
        "shap_value": -0.012,
        "direction": "decreases_anomaly"
      }
    ]
  },
  {
    "alert_id": "4fa85f64-5717-4562-b3fc-2c963f66afa2",
    "timestamp": "2026-10-01T10:16:12Z",
    "src_ip": "192.168.1.105",
    "dst_ip": "10.0.0.42",
    "anomaly_score": 0.99,
    "confidence": 0.99,
    "risk_score": 99,
    "attack_type_guess": "Privilege Escalation - Process Injection [STAGED PREVIEW]",
    "mitre_technique": "T1055.008",
    "explanation": [
      "[STAGED PREVIEW] Host score simulated: awaiting Person B 128-D model. Syscall trace verified with Person A extractor.",
      "Process 'invoice_oct.sh' executed PTRACE_ATTACH and multiple PTRACE_POKETEXT operations targeting 'sssd'.",
      "Network flow is zero. Identity monitor is blind. Detected purely via Pillar 3 syscall anomaly."
    ],
    "model_source": "ensembler-3-pillar (snapshot preview)",
    "is_adversarial_test": true,
    "badge_text": "STAGED_HOST",
    "data_source_status": {
      "network": "measured (M5b/M5a baseline)",
      "identity": "staged / simulated (pending UEBA integration)",
      "host": "staged (pending Person B 128-D HostAutoencoder)"
    },
    "network_score": 0.0,
    "identity_score": 0.0,
    "host_score": 0.99,
    "pillar_scores": {
      "network": 0.0,
      "identity": 0.0,
      "host": 0.99
    },
    "host_mapping_status": "candidate",
    "host_attack_mappings": [
      {
        "technique_id": "T1055.008",
        "mitre_technique": "Process Injection: Ptrace System Calls",
        "mitre_tactic": "Privilege Escalation",
        "severity": "CRITICAL",
        "evidence": [
          "ptrace(PTRACE_ATTACH) targeting system daemon sssd",
          "memory modification calls"
        ],
        "evidence_complete": true
      }
    ],
    "host_explanation": [
      "Candidate mapping based on evidence in attack_mappers/host_syscall_attack_mapper.json."
    ],
    "host_shap_features": [
      {
        "feature": "ctx_is_root",
        "shap_value": 0.0412,
        "direction": "increases_anomaly"
      },
      {
        "feature": "time_mean_delta",
        "shap_value": 0.0385,
        "direction": "increases_anomaly"
      },
      {
        "feature": "ret_success_rate",
        "shap_value": -0.012,
        "direction": "decreases_anomaly"
      }
    ]
  },
  {
    "alert_id": "4fa85f64-5717-4562-b3fc-2c963f66afa3",
    "timestamp": "2026-10-01T10:17:25Z",
    "src_ip": "192.168.1.105",
    "dst_ip": "10.0.0.42",
    "anomaly_score": 0.96,
    "confidence": 0.92,
    "risk_score": 92,
    "attack_type_guess": "Persistence - Kernel Module [STAGED PREVIEW]",
    "mitre_technique": "T1547.006",
    "explanation": [
      "[STAGED PREVIEW] Host score simulated: awaiting Person B 128-D model. Syscall trace verified with Person A extractor.",
      "Compromised 'sssd' process performed tmpfs mount and init_module 'stealth_mod.ko'.",
      "Strong anomaly signal from host features. Identity pillar detects minor token anomaly."
    ],
    "model_source": "ensembler-3-pillar (snapshot preview)",
    "is_adversarial_test": true,
    "badge_text": "STAGED_HOST",
    "data_source_status": {
      "network": "measured (M5b/M5a baseline)",
      "identity": "staged / simulated (pending UEBA integration)",
      "host": "staged (pending Person B 128-D HostAutoencoder)"
    },
    "network_score": 0.0,
    "identity_score": 0.45,
    "host_score": 0.96,
    "pillar_scores": {
      "network": 0.0,
      "identity": 0.45,
      "host": 0.96
    },
    "host_mapping_status": "candidate",
    "host_attack_mappings": [
      {
        "technique_id": "T1547.006",
        "mitre_technique": "Boot or Logon Initialization Scripts: Kernel Modules and Extensions",
        "mitre_tactic": "Persistence",
        "severity": "HIGH",
        "evidence": [
          "init_module call executed from daemon context",
          "tmpfs mount event"
        ],
        "evidence_complete": true
      }
    ],
    "host_explanation": [
      "Candidate mapping based on evidence in attack_mappers/host_syscall_attack_mapper.json."
    ],
    "host_shap_features": [
      {
        "feature": "ctx_is_root",
        "shap_value": 0.0412,
        "direction": "increases_anomaly"
      },
      {
        "feature": "time_mean_delta",
        "shap_value": 0.0385,
        "direction": "increases_anomaly"
      },
      {
        "feature": "ret_success_rate",
        "shap_value": -0.012,
        "direction": "decreases_anomaly"
      }
    ]
  },
  {
    "alert_id": "4fa85f64-5717-4562-b3fc-2c963f66afa4",
    "timestamp": "2026-10-01T10:18:35Z",
    "src_ip": "192.168.1.105",
    "dst_ip": "198.51.100.42",
    "anomaly_score": 0.88,
    "confidence": 0.99,
    "risk_score": 100,
    "attack_type_guess": "Command & Control / Exfiltration [STAGED PREVIEW]",
    "mitre_technique": "T1071.001",
    "explanation": [
      "[STAGED PREVIEW] Host score simulated: awaiting Person B 128-D model. Syscall trace verified with Person A extractor.",
      "Compromised process initiated encrypted C2 connection (AF_INET connect to 198.51.100.42:443).",
      "Network flow shape was highly evasive (mimicking CDN telemetry), but multi-modal correlation triggers critical alert."
    ],
    "model_source": "ensembler-3-pillar (snapshot preview)",
    "is_adversarial_test": true,
    "badge_text": "STAGED_HOST",
    "data_source_status": {
      "network": "measured (M5b/M5a baseline)",
      "identity": "staged / simulated (pending UEBA integration)",
      "host": "staged (pending Person B 128-D HostAutoencoder)"
    },
    "network_score": 0.35,
    "identity_score": 0.65,
    "host_score": 0.88,
    "pillar_scores": {
      "network": 0.35,
      "identity": 0.65,
      "host": 0.88
    },
    "host_mapping_status": "candidate",
    "host_attack_mappings": [
      {
        "technique_id": "T1071.001",
        "mitre_technique": "Application Layer Protocol: Web Protocols (HTTPS C2)",
        "mitre_tactic": "Command and Control",
        "severity": "HIGH",
        "evidence": [
          "Outbound connect() socket initiated directly from sssd daemon context"
        ],
        "evidence_complete": true
      }
    ],
    "host_explanation": [
      "Candidate mapping based on evidence in attack_mappers/host_syscall_attack_mapper.json."
    ],
    "host_shap_features": [
      {
        "feature": "ctx_is_root",
        "shap_value": 0.0412,
        "direction": "increases_anomaly"
      },
      {
        "feature": "time_mean_delta",
        "shap_value": 0.0385,
        "direction": "increases_anomaly"
      },
      {
        "feature": "ret_success_rate",
        "shap_value": -0.012,
        "direction": "decreases_anomaly"
      }
    ]
  },
  {
    "alert_id": "m5b-evaded-slow_scan-10",
    "timestamp": "2026-10-01T10:20:00Z",
    "src_ip": "172.16.0.1",
    "dst_ip": "192.168.10.50",
    "anomaly_score": 0.000661,
    "confidence": 0.05,
    "risk_score": 8,
    "attack_type_guess": "Network Reconnaissance - Slow Scan (Delay 10s) [MEASURED EVASION]",
    "mitre_technique": "T1046",
    "explanation": [
      "[REAL MEASURED RESULT] Relational GNN (M5b) evaluation: Attacker slowed port sweep rate to 1 probe every 10s to evade graph window aggregation.",
      "Evaded 99th percentile threshold 0.000924 (score: 0.000661, rank 1077/83394)."
    ],
    "model_source": "gnn_autoencoder_v1_logscale",
    "is_adversarial_test": true,
    "badge_text": "MEASURED_NET",
    "data_source_status": {
      "network": "measured (real M5b evaluation)",
      "identity": "unobserved",
      "host": "unobserved"
    },
    "network_score": 0.000661,
    "identity_score": null,
    "host_score": null,
    "pillar_scores": {
      "network": 0.000661,
      "identity": null,
      "host": null
    },
    "host_mapping_status": "no_match",
    "host_attack_mappings": [],
    "host_explanation": [
      "Network-only event; no host syscall activity recorded."
    ],
    "host_shap_features": []
  },
  {
    "alert_id": "m5b-evaded-slow_scan-20",
    "timestamp": "2026-10-01T10:20:00Z",
    "src_ip": "172.16.0.1",
    "dst_ip": "192.168.10.50",
    "anomaly_score": 0.000185,
    "confidence": 0.05,
    "risk_score": 8,
    "attack_type_guess": "Network Reconnaissance - Slow Scan (Delay 20s) [MEASURED EVASION]",
    "mitre_technique": "T1046",
    "explanation": [
      "[REAL MEASURED RESULT] Relational GNN (M5b) evaluation: Attacker slowed port sweep rate to 1 probe every 20s to evade graph window aggregation.",
      "Evaded 99th percentile threshold 0.000924 (score: 0.000185, rank 2242/83404)."
    ],
    "model_source": "gnn_autoencoder_v1_logscale",
    "is_adversarial_test": true,
    "badge_text": "MEASURED_NET",
    "data_source_status": {
      "network": "measured (real M5b evaluation)",
      "identity": "unobserved",
      "host": "unobserved"
    },
    "network_score": 0.000185,
    "identity_score": null,
    "host_score": null,
    "pillar_scores": {
      "network": 0.000185,
      "identity": null,
      "host": null
    },
    "host_mapping_status": "no_match",
    "host_attack_mappings": [],
    "host_explanation": [
      "Network-only event; no host syscall activity recorded."
    ],
    "host_shap_features": []
  }
];
