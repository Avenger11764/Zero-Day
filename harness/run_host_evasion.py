"""
run_host_evasion.py -- Host Syscall Evasion Evaluator (Week 5-6)
===============================================================
Role D: Adversarial Eval & Delivery (Person D - Avinash)
Zero-Day Detection FYP

Evaluates evasion variants against Person B's host autoencoder model.
Extracts 128-D HostFeatureVectors from:
  1. Original Kill-Chain Trace: harness/results/host_attack_story_trace.jsonl
  2. Feature Padding Variant:  harness/results/evasion_variants/variant_padding.jsonl
  3. Timing Morph Variant:     harness/results/evasion_variants/variant_timing.jsonl

METHOD RULE (from Week 3 bug):
------------------------------
Before reporting any "evasion" result, confirm the ORIGINAL unmodified trace
is flagged by the model (score > threshold). If it is not flagged, report that
finding as-is ("baseline trace not detected, evasion not measurable") instead
of claiming evasion. Never fabricate or estimate a score.

GUARD (CASE B):
---------------
If the available host model does not accept the 128-D HostFeatureVector
(e.g., ADFA 153-D or skeleton 32-D), abort with a clear message and do NOT
force the trace into an incompatible format.
"""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path
import numpy as np

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from capture.host_feature_extractor import HostFeatureExtractor, SyscallRecord

# Paths
ORIGINAL_TRACE = REPO_ROOT / "harness" / "results" / "host_attack_story_trace.jsonl"
PADDING_VARIANT = REPO_ROOT / "harness" / "results" / "evasion_variants" / "variant_padding.jsonl"
TIMING_VARIANT = REPO_ROOT / "harness" / "results" / "evasion_variants" / "variant_timing.jsonl"
RESULTS_DIR = REPO_ROOT / "harness" / "results"
OUTPUT_CSV = RESULTS_DIR / "host_evasion_results.csv"
OUTPUT_MD = RESULTS_DIR / "host_evasion_results.md"

# Model paths
HOST_AE_128_PATH = REPO_ROOT / "detection" / "host_autoencoder_128d.pt"
HOST_AE_DEFAULT_PATH = REPO_ROOT / "detection" / "host_autoencoder.pt"
HOST_AE_ADFA_PATH = REPO_ROOT / "detection" / "host_autoencoder_adfa.pt"


def load_records(trace_path: Path) -> list[dict]:
    if not trace_path.exists():
        raise FileNotFoundError(f"Trace file not found: {trace_path}")
    records = []
    with open(trace_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def extract_128d_vector(records: list[dict], extractor: HostFeatureExtractor) -> np.ndarray:
    syscall_records = [
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
        for r in records
    ]
    vec = extractor.extract_from_records(syscall_records)
    if np.isnan(vec).any():
        raise ValueError("Extracted feature vector contains NaNs!")
    if len(vec) != 128:
        raise ValueError(f"Expected 128-D vector, got {len(vec)}-D")
    return vec


def inspect_model_compatibility() -> tuple[bool, int | None, Path | None]:
    """Check if any available host model accepts 128-D input."""
    # Check 1: 128-D dedicated checkpoint
    if HOST_AE_128_PATH.exists():
        return True, 128, HOST_AE_128_PATH

    # Check 2: Check default host_autoencoder.pt
    if HOST_AE_DEFAULT_PATH.exists():
        try:
            import torch
            ckpt = torch.load(HOST_AE_DEFAULT_PATH, map_location="cpu")
            n_dim = ckpt.get("n_dim") if isinstance(ckpt, dict) else None
            if n_dim == 128:
                return True, 128, HOST_AE_DEFAULT_PATH
            return False, n_dim or 32, HOST_AE_DEFAULT_PATH
        except Exception:
            return False, 32, HOST_AE_DEFAULT_PATH

    # Check 3: Check ADFA checkpoint
    if HOST_AE_ADFA_PATH.exists():
        # Documented in CHANGELOG and ablation as 153-D (V+3 format)
        return False, 153, HOST_AE_ADFA_PATH

    # Skeleton default in detection/host_ae.py is 32-D
    return False, 32, None


def main():
    print("=" * 70)
    print("Zero-Day Detection FYP -- Host Syscall Evasion Evaluator (Week 5-6)")
    print("Person D (Avinash) -- Adversarial Evaluation & Delivery")
    print("=" * 70)

    # 1. Feature Extraction Verification
    print("\n[Step 1] Extracting 128-D HostFeatureVectors from traces...")
    extractor = HostFeatureExtractor()

    traces = {
        "original_kill_chain": ORIGINAL_TRACE,
        "feature_padding_variant": PADDING_VARIANT,
        "timing_morph_variant": TIMING_VARIANT,
    }

    vectors = {}
    for name, path in traces.items():
        if not path.exists():
            if name != "original_kill_chain":
                print(f"[*] Variant trace {path.name} not found. Running generator...")
                from harness.host_evasion_variants import generate_variants
                generate_variants(str(ORIGINAL_TRACE), str(path.parent))
            else:
                print(f"[!] Error: Original trace {path} missing!")
                sys.exit(1)

        records = load_records(path)
        vec = extract_128d_vector(records, extractor)
        vectors[name] = vec
        print(f"  + {name}: {len(records)} records -> 128-D vector (min={vec.min():.4f}, max={vec.max():.4f}, non-zero={np.count_nonzero(vec)})")

    # 2. Inspect Host Model Compatibility (CASE A vs CASE B)
    print("\n[Step 2] Checking Host Autoencoder model compatibility...")
    is_128d_compatible, model_dim, model_path = inspect_model_compatibility()

    if not is_128d_compatible:
        print("\n" + "!" * 70)
        print("[CASE B TRIGGERED - HOST SCORING BLOCKED ON PERSON B]")
        print(f"Current host detector does not accept the 128-D HostFeatureVector.")
        print(f"  - Detected model input dimension : {model_dim}-D (expected 128-D)")
        if model_path:
            print(f"  - Model checkpoint checked       : {model_path.name}")
        print("  - Handover schema contract       : schemas/host_feature_vector.json (128-D)")
        print("\nMethodological rule:")
        print("  Role D refuses to force the 12-syscall trace into the incompatible")
        print("  ADFA V+3 (153-D) format or skeleton (32-D), as that produces meaningless numbers.")
        print("\nAction taken:")
        print("  - Detailed interface specification logged to: docs/REQUEST_TO_PERSON_B.md")
        print("  - Harness is primed and ready to score as soon as the 128-D checkpoint arrives.")
        print("!" * 70 + "\n")
        return

    # CASE A: Real Model Scoring
    print(f"\n[Step 3] Model is 128-D compatible ({model_path}). Scoring traces...")
    import torch
    from detection.host_ae import HostAutoencoder, HostScaler

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    ckpt = torch.load(model_path, map_location=device)
    model = HostAutoencoder(input_dim=128).to(device)
    model.load_state_dict(ckpt["model"])
    model.eval()

    scaler = HostScaler(log=True)
    if "scaler" in ckpt:
        scaler.load_state_dict(ckpt["scaler"])

    threshold = float(ckpt.get("threshold", 0.05))

    results = []
    for name, vec in vectors.items():
        tensor_vec = torch.tensor(vec, dtype=torch.float32).unsqueeze(0)
        norm_vec = scaler.transform(tensor_vec).to(device)
        with torch.no_grad():
            score = float(model.anomaly_score(norm_vec).cpu().numpy()[0])
        flagged = score > threshold
        results.append({
            "variant": name,
            "anomaly_score": score,
            "threshold": threshold,
            "flagged": flagged,
        })

    # METHOD RULE: Check original baseline trace
    orig_res = next(r for r in results if r["variant"] == "original_kill_chain")
    print(f"\n[Method Rule Verification]")
    print(f"  Baseline score: {orig_res['anomaly_score']:.6f} vs threshold {orig_res['threshold']:.6f}")
    if not orig_res["flagged"]:
        print("  [!] WARNING: Baseline trace not detected, evasion not measurable.")
        verdict = "baseline trace not detected, evasion not measurable"
    else:
        print("  [OK] Baseline trace detected. Evasion is measurable.")
        verdict = "valid"

    # Write CSV
    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["variant", "anomaly_score", "threshold", "flagged"])
        writer.writeheader()
        writer.writerows(results)
    print(f"\nWrote CSV -> {OUTPUT_CSV}")

    # Write Markdown
    with open(OUTPUT_MD, "w", encoding="utf-8") as f:
        f.write("# Host Evasion Scoring Results (Week 5-6)\n\n")
        f.write(f"**Status:** {verdict}\n\n")
        f.write("| Variant | Anomaly Score | Threshold | Flagged? |\n")
        f.write("|---|---|---|---|\n")
        for r in results:
            f.write(f"| {r['variant']} | {r['anomaly_score']:.6f} | {r['threshold']:.6f} | {'YES' if r['flagged'] else 'NO'} |\n")
    print(f"Wrote Markdown -> {OUTPUT_MD}")


if __name__ == "__main__":
    main()
