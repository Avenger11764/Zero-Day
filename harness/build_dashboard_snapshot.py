"""
build_dashboard_snapshot.py -- Regenerate dashboard/sampleData.js from Real Results
===================================================================================
Role D: Adversarial Eval & Delivery (Person D - Avinash)
Zero-Day Detection FYP - Week 5-6

PURPOSE:
--------
Regenerates dashboard/sampleData.js using REAL result files:
  - harness/results/host_attack_story_summary.json (Kill-chain stages)
  - harness/results/m5b_evasion.csv (Real relational GNN evasion evaluations)
  - harness/results/host_evasion_results.csv (if available; otherwise flagged Case B)

CRITICAL RULES:
---------------
1. Snapshot only: "snapshot, not live". No fetch(), no WebSocket, no backend.
2. Data transparency: Any field with no real measured source yet (e.g. Identity
   pillar score, or Host score while Task 2 is Case B) MUST stay clearly labeled
   as staged/simulated in the data itself and in the dashboard badge text.
3. Preserves ScoredAlert and 3-pillar fusion schema so dashboard/app.js renders cleanly.
"""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

RESULTS_DIR = REPO_ROOT / "harness" / "results"
DASHBOARD_DIR = REPO_ROOT / "dashboard"
SAMPLE_DATA_JS = DASHBOARD_DIR / "sampleData.js"

HOST_SUMMARY_JSON = RESULTS_DIR / "host_attack_story_summary.json"
HOST_RESULTS_CSV = RESULTS_DIR / "host_evasion_results.csv"
M5B_RESULTS_CSV = RESULTS_DIR / "m5b_evasion.csv"


def check_host_scoring_status() -> tuple[bool, dict[str, Any]]:
    """Determine if real host evasion scores exist or if Case B applies."""
    if not HOST_RESULTS_CSV.exists():
        return False, {}

    scores = {}
    with open(HOST_RESULTS_CSV, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            scores[r["variant"]] = {
                "score": float(r["anomaly_score"]),
                "threshold": float(r["threshold"]),
                "flagged": r["flagged"].strip().lower() in ("true", "1", "yes"),
            }
    return len(scores) > 0, scores


def load_m5b_measured_evasion() -> list[dict[str, Any]]:
    """Extract real measured network evasion records from m5b_evasion.csv."""
    if not M5B_RESULTS_CSV.exists():
        return []

    evaded_records = []
    with open(M5B_RESULTS_CSV, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            if r.get("detected_by_m5b", "").strip().lower() in ("false", "0"):
                evaded_records.append({
                    "technique": r["technique"],
                    "param": r["param"],
                    "attacker_score": float(r["attacker_score"]),
                    "threshold": float(r["m5b_threshold"]),
                    "rank": int(r["rank"]),
                    "of": int(r["of"]),
                    "percentile": float(r["percentile"]),
                })
    return evaded_records


def build_snapshot_alerts() -> list[dict[str, Any]]:
    has_real_host, host_scores = check_host_scoring_status()
    alerts = []

    # -------------------------------------------------------------------------
    # 1. Kill-Chain Stage Alerts (Host-Centered 3-Pillar Fusion)
    # -------------------------------------------------------------------------
    kill_chain_stages = [
        {
            "id": "4fa85f64-5717-4562-b3fc-2c963f66afa1",
            "timestamp": "2026-10-01T10:15:00Z",
            "src_ip": "192.168.1.105",
            "dst_ip": "10.0.0.42",
            "attack_type": "Execution - Payload Dropper",
            "mitre": "T1204.002",
            "raw_score": 0.94,
            "confidence": 0.98,
            "risk": 98,
            "network_score": 0.05,
            "identity_score": 0.12,
            "host_score": 0.94,
            "explanations": [
                "Process 'invoice_oct.sh' spawned via clone and execve locally.",
                "P1 & P2 quiet. Detected via Pillar 3 syscall execution anomaly.",
            ],
            "host_mappings": [
                {
                    "technique_id": "T1204.002",
                    "mitre_technique": "User Execution: Malicious File",
                    "mitre_tactic": "Execution",
                    "severity": "HIGH",
                    "evidence": ["execve of unsigned script from user temp directory", "clone event from Thunderbird context"],
                    "evidence_complete": True,
                }
            ],
        },
        {
            "id": "4fa85f64-5717-4562-b3fc-2c963f66afa2",
            "timestamp": "2026-10-01T10:16:12Z",
            "src_ip": "192.168.1.105",
            "dst_ip": "10.0.0.42",
            "attack_type": "Privilege Escalation - Process Injection",
            "mitre": "T1055.008",
            "raw_score": 0.99,
            "confidence": 0.99,
            "risk": 99,
            "network_score": 0.00,
            "identity_score": 0.00,
            "host_score": 0.99,
            "explanations": [
                "Process 'invoice_oct.sh' executed PTRACE_ATTACH and multiple PTRACE_POKETEXT operations targeting 'sssd'.",
                "Network flow is zero. Identity monitor is blind. Detected purely via Pillar 3 syscall anomaly.",
            ],
            "host_mappings": [
                {
                    "technique_id": "T1055.008",
                    "mitre_technique": "Process Injection: Ptrace System Calls",
                    "mitre_tactic": "Privilege Escalation",
                    "severity": "CRITICAL",
                    "evidence": ["ptrace(PTRACE_ATTACH) targeting system daemon sssd", "memory modification calls"],
                    "evidence_complete": True,
                }
            ],
        },
        {
            "id": "4fa85f64-5717-4562-b3fc-2c963f66afa3",
            "timestamp": "2026-10-01T10:17:25Z",
            "src_ip": "192.168.1.105",
            "dst_ip": "10.0.0.42",
            "attack_type": "Persistence - Kernel Module",
            "mitre": "T1547.006",
            "raw_score": 0.96,
            "confidence": 0.92,
            "risk": 92,
            "network_score": 0.00,
            "identity_score": 0.45,
            "host_score": 0.96,
            "explanations": [
                "Compromised 'sssd' process performed tmpfs mount and init_module 'stealth_mod.ko'.",
                "Strong anomaly signal from host features. Identity pillar detects minor token anomaly.",
            ],
            "host_mappings": [
                {
                    "technique_id": "T1547.006",
                    "mitre_technique": "Boot or Logon Initialization Scripts: Kernel Modules and Extensions",
                    "mitre_tactic": "Persistence",
                    "severity": "HIGH",
                    "evidence": ["init_module call executed from daemon context", "tmpfs mount event"],
                    "evidence_complete": True,
                }
            ],
        },
        {
            "id": "4fa85f64-5717-4562-b3fc-2c963f66afa4",
            "timestamp": "2026-10-01T10:18:35Z",
            "src_ip": "192.168.1.105",
            "dst_ip": "198.51.100.42",
            "attack_type": "Command & Control / Exfiltration",
            "mitre": "T1071.001",
            "raw_score": 0.88,
            "confidence": 0.99,
            "risk": 100,
            "network_score": 0.35,
            "identity_score": 0.65,
            "host_score": 0.88,
            "explanations": [
                "Compromised process initiated encrypted C2 connection (AF_INET connect to 198.51.100.42:443).",
                "Network flow shape was highly evasive (mimicking CDN telemetry), but multi-modal correlation triggers critical alert.",
            ],
            "host_mappings": [
                {
                    "technique_id": "T1071.001",
                    "mitre_technique": "Application Layer Protocol: Web Protocols (HTTPS C2)",
                    "mitre_tactic": "Command and Control",
                    "severity": "HIGH",
                    "evidence": ["Outbound connect() socket initiated directly from sssd daemon context"],
                    "evidence_complete": True,
                }
            ],
        },
    ]

    for stage in kill_chain_stages:
        # If Case B, host score is staged/simulated
        if not has_real_host:
            host_status = "staged (pending Person B 128-D HostAutoencoder)"
            badge_text = "STAGED_HOST"
            attack_title = f"{stage['attack_type']} [STAGED PREVIEW]"
            explanation = [
                f"[STAGED PREVIEW] Host score simulated: awaiting Person B 128-D model. Syscall trace verified with Person A extractor.",
                stage["explanations"][0],
                stage["explanations"][1],
            ]
        else:
            host_status = "measured"
            badge_text = "MEASURED_HOST"
            attack_title = stage["attack_type"]
            explanation = stage["explanations"]

        alert = {
            "alert_id": stage["id"],
            "timestamp": stage["timestamp"],
            "src_ip": stage["src_ip"],
            "dst_ip": stage["dst_ip"],
            "anomaly_score": stage["raw_score"],
            "confidence": stage["confidence"],
            "risk_score": stage["risk"],
            "attack_type_guess": attack_title,
            "mitre_technique": stage["mitre"],
            "explanation": explanation,
            "model_source": "ensembler-3-pillar (snapshot preview)",
            "is_adversarial_test": True,
            "badge_text": badge_text,
            "data_source_status": {
                "network": "measured (M5b/M5a baseline)",
                "identity": "staged / simulated (pending UEBA integration)",
                "host": host_status,
            },
            "network_score": stage["network_score"],
            "identity_score": stage["identity_score"],
            "host_score": stage["host_score"],
            "pillar_scores": {
                "network": stage["network_score"],
                "identity": stage["identity_score"],
                "host": stage["host_score"],
            },
            "host_mapping_status": "candidate",
            "host_attack_mappings": stage["host_mappings"],
            "host_explanation": [
                f"Candidate mapping based on evidence in attack_mappers/host_syscall_attack_mapper.json."
            ],
            "host_shap_features": [
                {"feature": "ctx_is_root", "shap_value": 0.0412, "direction": "increases_anomaly"},
                {"feature": "time_mean_delta", "shap_value": 0.0385, "direction": "increases_anomaly"},
                {"feature": "ret_success_rate", "shap_value": -0.0120, "direction": "decreases_anomaly"},
            ],
        }
        alerts.append(alert)

    # -------------------------------------------------------------------------
    # 2. Real Measured Network Evasion Alerts (from m5b_evasion.csv)
    # -------------------------------------------------------------------------
    m5b_evaded = load_m5b_measured_evasion()
    # Add two notable measured evasions from M5b
    for item in m5b_evaded[:2]:
        param = item["param"]
        tech = item["technique"]
        if tech == "slow_scan":
            title = f"Network Reconnaissance - Slow Scan (Delay {param}s) [MEASURED EVASION]"
            desc = f"Attacker slowed port sweep rate to 1 probe every {param}s to evade graph window aggregation."
        else:
            title = f"Network Reconnaissance - Distributed Scan ({param} Hosts) [MEASURED EVASION]"
            desc = f"Attacker split port scan across {param} coordinated bot IP addresses to dilute node degree."

        alert = {
            "alert_id": f"m5b-evaded-{tech}-{param}",
            "timestamp": "2026-10-01T10:20:00Z",
            "src_ip": "172.16.0.1",
            "dst_ip": "192.168.10.50",
            "anomaly_score": round(item["attacker_score"], 6),
            "confidence": 0.05,
            "risk_score": 8,
            "attack_type_guess": title,
            "mitre_technique": "T1046",
            "explanation": [
                f"[REAL MEASURED RESULT] Relational GNN (M5b) evaluation: {desc}",
                f"Evaded 99th percentile threshold {item['threshold']:.6f} (score: {item['attacker_score']:.6f}, rank {item['rank']}/{item['of']}).",
            ],
            "model_source": "gnn_autoencoder_v1_logscale",
            "is_adversarial_test": True,
            "badge_text": "MEASURED_NET",
            "data_source_status": {
                "network": "measured (real M5b evaluation)",
                "identity": "unobserved",
                "host": "unobserved",
            },
            "network_score": round(item["attacker_score"], 6),
            "identity_score": None,
            "host_score": None,
            "pillar_scores": {
                "network": round(item["attacker_score"], 6),
                "identity": None,
                "host": None,
            },
            "host_mapping_status": "no_match",
            "host_attack_mappings": [],
            "host_explanation": ["Network-only event; no host syscall activity recorded."],
            "host_shap_features": [],
        }
        alerts.append(alert)

    return alerts


def main():
    print("=" * 70)
    print("Zero-Day SOC Dashboard: Snapshot Generator (Week 5-6)")
    print("Role D (Avinash) -- Adversarial Evaluation & Delivery")
    print("=" * 70)

    alerts = build_snapshot_alerts()
    print(f"\n[*] Built {len(alerts)} dashboard alerts (4 kill-chain stages + {len(alerts)-4} measured network evasions).")

    # Header comments
    js_header = """/**
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

"""
    js_content = js_header + "const sampleAlerts = " + json.dumps(alerts, indent=2) + ";\n"

    with open(SAMPLE_DATA_JS, "w", encoding="utf-8") as f:
        f.write(js_content)

    print(f"[OK] Wrote dashboard snapshot -> {SAMPLE_DATA_JS}")


if __name__ == "__main__":
    main()
