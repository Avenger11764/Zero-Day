"""
export_evaded_for_retraining.py -- Hardening Loop Exporter (Week 5-6)
=====================================================================
Role D: Adversarial Eval & Delivery (Person D - Avinash)
Zero-Day Detection FYP

Scaffold for the adversarial hardening loop. Exports evaded samples
generated during red-team harness evaluations into:
    harness/results/hardening_export/

CRITICAL CONSTRAINTS:
---------------------
1. Export ONLY: Does NOT retrain or modify any model under detection/.
2. Checks Task 2 host evasion results first. If host scoring is blocked,
   falls back to network-side evaded samples (from m5b_evasion.json /
   autoencoder_v2_baseline_v2.csv).
3. Ensures exported records adhere strictly to schemas/ (host 128-D
   per schemas/host_feature_vector.json or network per schemas/feature_vector.json),
   clearly labeled as adversarial.
4. If nothing has evaded yet, exits cleanly with "no evaded samples to export".
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
EXPORT_DIR = RESULTS_DIR / "hardening_export"

# Host results & traces
HOST_RESULTS_CSV = RESULTS_DIR / "host_evasion_results.csv"
HOST_TRACES = {
    "original_kill_chain": RESULTS_DIR / "host_attack_story_trace.jsonl",
    "feature_padding_variant": RESULTS_DIR / "evasion_variants" / "variant_padding.jsonl",
    "timing_morph_variant": RESULTS_DIR / "evasion_variants" / "variant_timing.jsonl",
}

# Network results
M5B_RESULTS_JSON = RESULTS_DIR / "m5b_evasion.json"
M5B_RESULTS_CSV = RESULTS_DIR / "m5b_evasion.csv"
AE_BASELINE_CSV = RESULTS_DIR / "autoencoder_v2_baseline_v2.csv"


def check_host_evaded_samples() -> list[dict[str, Any]]:
    """Check if host evasion results exist and contain evaded variants."""
    if not HOST_RESULTS_CSV.exists():
        return []

    evaded_host = []
    with open(HOST_RESULTS_CSV, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            flagged = row.get("flagged", "").strip().lower() in ("true", "1", "yes")
            if not flagged:
                variant_name = row.get("variant")
                evaded_host.append({
                    "variant": variant_name,
                    "anomaly_score": float(row.get("anomaly_score", 0.0)),
                    "threshold": float(row.get("threshold", 0.0)),
                })
    return evaded_host


def export_host_samples(evaded_variants: list[dict[str, Any]]) -> int:
    """Export 128-D host feature vectors per schemas/host_feature_vector.json."""
    from capture.host_feature_extractor import HostFeatureExtractor, SyscallRecord

    extractor = HostFeatureExtractor()
    exported_records = []

    for item in evaded_variants:
        var_name = item["variant"]
        trace_path = HOST_TRACES.get(var_name)
        if not trace_path or not trace_path.exists():
            continue

        syscall_records = []
        with open(trace_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    r = json.loads(line)
                    syscall_records.append(
                        SyscallRecord(
                            timestamp=r["timestamp"],
                            pid=r.get("pid", 1000),
                            ppid=r.get("ppid", 1),
                            uid=r.get("uid", 1000),
                            comm=r.get("comm", "unknown"),
                            syscall=r["syscall"],
                            args=r.get("args", {}),
                            ret=r.get("ret", 0),
                        )
                    )

        vec = extractor.extract_from_records(syscall_records)
        record = {
            "sample_id": f"host_evasion_{var_name}",
            "source": "harness_host_evasion",
            "pillar": "host",
            "is_adversarial": True,
            "label": "adversarial",
            "target_model": "HostAutoencoder",
            "schema_version": "1.0",
            "schema_ref": "schemas/host_feature_vector.json",
            "feature_length": len(vec),
            "feature_vector": vec.tolist(),
            "metadata": {
                "variant": var_name,
                "anomaly_score": item["anomaly_score"],
                "threshold": item["threshold"],
                "total_syscalls": len(syscall_records),
            },
        }
        exported_records.append(record)

    if not exported_records:
        return 0

    EXPORT_DIR.mkdir(parents=True, exist_ok=True)
    out_file = EXPORT_DIR / "evaded_host_samples.jsonl"
    with open(out_file, "w", encoding="utf-8") as f:
        for r in exported_records:
            f.write(json.dumps(r) + "\n")

    manifest = {
        "export_target": "host_retraining",
        "sample_count": len(exported_records),
        "exported_file": str(out_file.name),
        "feature_schema": "schemas/host_feature_vector.json",
        "feature_dim": 128,
        "label": "adversarial",
    }
    with open(EXPORT_DIR / "export_manifest.json", "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    return len(exported_records)


def export_network_samples() -> int:
    """Export network-side evaded samples when host scoring is blocked."""
    exported_samples = []

    # Source 1: m5b_evasion.json (Relational GNN evaded configurations)
    if M5B_RESULTS_JSON.exists():
        with open(M5B_RESULTS_JSON, "r", encoding="utf-8") as f:
            m5b_data = json.load(f)

        for entry in m5b_data:
            if not entry.get("detected_by_m5b", True):
                exported_samples.append({
                    "sample_id": f"m5b_evasion_{entry['technique']}_p{entry['param']}",
                    "source": "harness_relational_m5b_evasion",
                    "pillar": "network",
                    "technique": entry["technique"],
                    "param": entry["param"],
                    "is_adversarial": True,
                    "label": "adversarial",
                    "target_model": "GraphAutoencoder (M5b)",
                    "schema_ref": "schemas/feature_vector.json",
                    "evaluation_metrics": {
                        "attacker_score": entry["attacker_score"],
                        "threshold": entry["m5b_threshold"],
                        "rank": entry["rank"],
                        "of": entry["of"],
                        "percentile": entry["percentile"],
                        "m5a_flag_rate": entry.get("m5a_flag_rate"),
                    },
                })

    # Source 2: autoencoder_v2_baseline_v2.csv (Flow AE unflagged steps)
    if AE_BASELINE_CSV.exists():
        with open(AE_BASELINE_CSV, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            unflagged_rows = [row for row in reader if row.get("flagged") == "0"]

        # Aggregate unique evaded technique steps
        technique_summary = {}
        for row in unflagged_rows:
            tech = row["technique"]
            technique_summary[tech] = technique_summary.get(tech, 0) + 1

        for tech, count in technique_summary.items():
            exported_samples.append({
                "sample_id": f"flow_ae_evasion_{tech}",
                "source": "harness_flow_ae_baseline_evasion",
                "pillar": "network",
                "technique": tech,
                "is_adversarial": True,
                "label": "adversarial",
                "target_model": "Autoencoder (M5a)",
                "schema_ref": "schemas/feature_vector.json",
                "unflagged_step_count": count,
            })

    if not exported_samples:
        return 0

    EXPORT_DIR.mkdir(parents=True, exist_ok=True)
    out_file = EXPORT_DIR / "evaded_network_samples.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(exported_samples, f, indent=2)

    manifest = {
        "export_target": "network_retraining",
        "sample_count": len(exported_samples),
        "exported_file": str(out_file.name),
        "source_evaluation": "harness/results/m5b_evasion.json + autoencoder_v2_baseline_v2.csv",
        "label": "adversarial",
        "schema_ref": "schemas/feature_vector.json",
    }
    with open(EXPORT_DIR / "export_manifest.json", "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    return len(exported_samples)


def main():
    print("=" * 70)
    print("Hardening Loop Scaffold: Exporting Evaded Adversarial Samples")
    print("Role D (Avinash) -- Adversarial Evaluation & Delivery")
    print("=" * 70)

    # 1. Attempt Host Evasion Export
    host_evaded = check_host_evaded_samples()
    if host_evaded:
        print(f"[*] Found {len(host_evaded)} evaded host variant(s) in {HOST_RESULTS_CSV.name}.")
        n = export_host_samples(host_evaded)
        print(f"[OK] Exported {n} 128-D host samples to {EXPORT_DIR}/evaded_host_samples.jsonl")
        print(f"[OK] Manifest written to {EXPORT_DIR}/export_manifest.json")
        return

    # 2. Host scoring blocked / no host evasion -> Fall back to Network Evaded Samples
    print("[!] Host scoring blocked or no host evasion data yet. Checking network-side results...")
    n_net = export_network_samples()
    if n_net > 0:
        print(f"[OK] Successfully exported {n_net} network-side evaded adversarial configurations.")
        print(f"[OK] Output saved to: {EXPORT_DIR}/evaded_network_samples.json")
        print(f"[OK] Manifest saved to: {EXPORT_DIR}/export_manifest.json")
        return

    # 3. Clean exit if nothing evaded
    print("no evaded samples to export")
    sys.exit(0)


if __name__ == "__main__":
    main()
