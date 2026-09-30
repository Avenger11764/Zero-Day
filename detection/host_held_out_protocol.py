"""
Held-Out Host Attack-Family Evaluation Protocol — Pillar 3, Week 5 (Person A: Saharsh).

Zero-Day Evaluation Discipline for Host Telemetry:
  1. Train purely on Normal/Benign traces (Training_Data_Master, 833 traces).
  2. Calibrate detection thresholds on Benign Validation traces (Validation_Data_Master)
     at operational false positive rates (FPR <= 1.0% and FPR <= 0.1%).
  3. Evaluate zero-day detection performance independently on each unseen attack family:
     - Adduser (91 traces)
     - Hydra_FTP (162 traces)
     - Hydra_SSH (176 traces)
     - Java_Meterpreter (124 traces)
     - Meterpreter (75 traces)
     - Web_Shell (118 traces)
  4. Compare Rich Contextual Features (128-dim) vs. 1-Gram Syscall Names (Unigram Baseline)
     to validate Guo et al. (2024)'s thesis that full syscall context provides superior
     zero-day detection coverage.

Usage:
  python detection/host_held_out_protocol.py
  python detection/host_held_out_protocol.py --out detection/held_out_host_results.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

import numpy as np

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from capture.host_feature_extractor import HostFeatureExtractor, resolve_data_root
from detection.host_features import load_adfa, load_nr_map


def compute_roc_metrics(y_true: np.ndarray, scores: np.ndarray) -> Dict[str, float]:
    """Compute AUROC, PR-AUC, and TPR at fixed FPR thresholds using NumPy."""
    n_samples = len(y_true)
    if n_samples == 0:
        return {"auroc": 0.0, "tpr_at_1pct_fpr": 0.0, "tpr_at_01pct_fpr": 0.0, "best_f1": 0.0}

    n_pos = int(np.sum(y_true == 1))
    n_neg = int(np.sum(y_true == 0))

    if n_pos == 0 or n_neg == 0:
        return {"auroc": 1.0 if n_pos == 0 else 0.0, "tpr_at_1pct_fpr": 1.0, "tpr_at_01pct_fpr": 1.0, "best_f1": 1.0}

    # Sort descending by score
    desc_idx = np.argsort(-scores)
    y_sorted = y_true[desc_idx]
    s_sorted = scores[desc_idx]

    tps = np.cumsum(y_sorted == 1)
    fps = np.cumsum(y_sorted == 0)

    tprs = tps / n_pos
    fprs = fps / n_neg
    precisions = tps / np.maximum(tps + fps, 1)

    # AUROC via trapezoidal rule
    # Add (0,0) and (1,1) to ROC curve
    roc_fpr = np.concatenate([[0.0], fprs, [1.0]])
    roc_tpr = np.concatenate([[0.0], tprs, [1.0]])
    # Direct trapezoidal sum compatible with all NumPy versions (including NumPy 2.0+)
    auroc = float(0.5 * np.sum((roc_tpr[1:] + roc_tpr[:-1]) * np.diff(roc_fpr)))

    # PR-AUC
    pr_auc = float(0.5 * np.sum((precisions[1:] + precisions[:-1]) * np.diff(tprs))) if len(tprs) > 1 else float(precisions[0])

    # TPR at target FPR thresholds
    idx_1pct = np.searchsorted(fprs, 0.01, side="right")
    tpr_at_1pct = float(tprs[min(idx_1pct, len(tprs) - 1)]) if idx_1pct < len(tprs) else float(tprs[-1])

    idx_01pct = np.searchsorted(fprs, 0.001, side="right")
    tpr_at_01pct = float(tprs[min(idx_01pct, len(tprs) - 1)]) if idx_01pct < len(tprs) else float(tprs[-1])

    # Best F1
    f1_scores = 2 * (precisions * tprs) / np.maximum(precisions + tprs, 1e-12)
    best_f1 = float(np.max(f1_scores))

    return {
        "auroc": max(0.0, min(auroc, 1.0)),
        "pr_auc": max(0.0, min(pr_auc, 1.0)),
        "tpr_at_1pct_fpr": max(0.0, min(tpr_at_1pct, 1.0)),
        "tpr_at_01pct_fpr": max(0.0, min(tpr_at_01pct, 1.0)),
        "best_f1": max(0.0, min(best_f1, 1.0))
    }


class BenignSubspaceAnomalyDetector:
    """
    Fast, robust unsupervised reconstruction detector on benign host subspace.
    Uses PCA / low-rank subspace projection with Mahalanobis-weighted reconstruction residual.
    """

    def __init__(self, n_components: int = 16):
        self.n_components = n_components
        self.mean: Optional[np.ndarray] = None
        self.std: Optional[np.ndarray] = None
        self.components: Optional[np.ndarray] = None
        self.val_threshold: float = 0.0

    def fit(self, X_train: np.ndarray) -> None:
        self.mean = np.mean(X_train, axis=0)
        self.std = np.std(X_train, axis=0) + 1e-6
        X_norm = (X_train - self.mean) / self.std

        # SVD / PCA
        U, S, Vt = np.linalg.svd(X_norm, full_matrices=False)
        k = min(self.n_components, Vt.shape[0])
        self.components = Vt[:k]

    def score(self, X: np.ndarray) -> np.ndarray:
        if self.mean is None or self.components is None or self.std is None:
            raise ValueError("Detector must be fitted before scoring.")
        X_norm = (X - self.mean) / self.std
        # Project onto subspace and reconstruct
        proj = np.dot(X_norm, self.components.T)
        recon = np.dot(proj, self.components)
        residual = np.sum((X_norm - recon) ** 2, axis=1)
        return residual


def run_held_out_protocol(root_dir: Path, output_file: Path | None = None) -> Dict[str, Any]:
    print("=" * 80)
    print("ZERO-DAY HELD-OUT ATTACK-FAMILY EVALUATION PROTOCOL (PERSON A - WEEK 5)")
    print("=" * 80)

    # 1. Load Traces and Header
    nr_map = load_nr_map(root_dir / "ADFA-LD+Syscall+List.txt")
    print(f"[*] Loaded syscall mapping: {len(nr_map)} defined syscalls")
    traces = load_adfa(root_dir)
    print(f"[*] Total dataset traces loaded: {len(traces)}")

    train_traces = [t for t in traces if t["split"] == "train"]
    val_traces = [t for t in traces if t["split"] == "val_benign"]
    attack_traces = [t for t in traces if t["split"] == "attack"]

    print(f"    - Benign Training Pool:   {len(train_traces):>5} traces (100% normal)")
    print(f"    - Benign Validation Pool: {len(val_traces):>5} traces (for FPR calibration)")
    print(f"    - Attack Evaluation Pool: {len(attack_traces):>5} traces (held-out zero-day scenarios)")

    # 2. Extract feature sets:
    # Set A: Rich 128-dim Host FeatureVector (Person A)
    # Set B: 1-Gram Baseline Unigram Frequencies (50-dim)
    print("\n[*] Initializing Host Feature Extractors & Fitting Benign Vocab...")
    train_raw_seqs = [[nr_map.get(s, f"nr_{s}") for s in t["seq"]] for t in train_traces]
    
    extractor = HostFeatureExtractor()
    extractor.fit_vocab(train_raw_seqs)

    print("[*] Extracting 128-dim Host Feature Vectors for Training and Validation...")
    X_train_full = np.stack([extractor.extract_from_trace_numbers(t["seq"], nr_map) for t in train_traces])
    X_val_full = np.stack([extractor.extract_from_trace_numbers(t["seq"], nr_map) for t in val_traces])
    
    # 1-gram baseline (first 50 dims of vector)
    X_train_1g = X_train_full[:, 0:50]
    X_val_1g = X_val_full[:, 0:50]

    # 3. Fit Unsupervised Anomaly Detectors purely on Benign Train
    print("[*] Fitting Benign Subspace Anomaly Detectors on Normal Traces Only...")
    detector_full = BenignSubspaceAnomalyDetector(n_components=16)
    detector_full.fit(X_train_full)

    detector_1g = BenignSubspaceAnomalyDetector(n_components=8)
    detector_1g.fit(X_train_1g)

    # Score Benign Validation Pool
    val_scores_full = detector_full.score(X_val_full)
    val_scores_1g = detector_1g.score(X_val_1g)

    # Calibrate 1.0% and 0.1% FPR thresholds on Benign Validation
    thr_1pct_full = float(np.percentile(val_scores_full, 99.0))
    thr_01pct_full = float(np.percentile(val_scores_full, 99.9))

    thr_1pct_1g = float(np.percentile(val_scores_1g, 99.0))
    thr_01pct_1g = float(np.percentile(val_scores_1g, 99.9))

    # 4. Evaluate on Held-out Attack Families
    families = sorted(list(set(t["family"] for t in attack_traces if t["family"] is not None)))
    results_by_family: Dict[str, Any] = {}

    print("\n" + "=" * 80)
    print(f"{'HELD-OUT ATTACK FAMILY':<20} | {'TRACES':<6} | {'1-GRAM AUC':<10} | {'128-D AUC':<10} | {'128-D TPR@1%':<12} | {'128-D F1':<8}")
    print("-" * 80)

    for fam in families:
        fam_traces = [t for t in attack_traces if t["family"] == fam]
        X_fam_full = np.stack([extractor.extract_from_trace_numbers(t["seq"], nr_map) for t in fam_traces])
        X_fam_1g = X_fam_full[:, 0:50]

        fam_scores_full = detector_full.score(X_fam_full)
        fam_scores_1g = detector_1g.score(X_fam_1g)

        # Build binary evaluation set against benign validation traces
        y_eval = np.concatenate([np.zeros(len(val_traces), dtype=int), np.ones(len(fam_traces), dtype=int)])
        s_eval_full = np.concatenate([val_scores_full, fam_scores_full])
        s_eval_1g = np.concatenate([val_scores_1g, fam_scores_1g])

        m_full = compute_roc_metrics(y_eval, s_eval_full)
        m_1g = compute_roc_metrics(y_eval, s_eval_1g)

        # Detection rate at calibrated threshold
        detected_1pct = int(np.sum(fam_scores_full >= thr_1pct_full))
        tpr_calibrated_1pct = detected_1pct / len(fam_traces)

        results_by_family[fam] = {
            "trace_count": len(fam_traces),
            "unigram_baseline": m_1g,
            "rich_context_128d": m_full,
            "calibrated_tpr_at_1pct_fpr": tpr_calibrated_1pct,
            "detected_traces": detected_1pct
        }

        print(f"{fam:<20} | {len(fam_traces):<6} | {m_1g['auroc']:<10.4f} | {m_full['auroc']:<10.4f} | {tpr_calibrated_1pct*100:<11.2f}% | {m_full['best_f1']:<8.4f}")

    # 5. Aggregate Macro Zero-Day Performance
    avg_auc_1g = float(np.mean([res["unigram_baseline"]["auroc"] for res in results_by_family.values()]))
    avg_auc_full = float(np.mean([res["rich_context_128d"]["auroc"] for res in results_by_family.values()]))
    avg_tpr_1pct = float(np.mean([res["calibrated_tpr_at_1pct_fpr"] for res in results_by_family.values()]))
    avg_f1_full = float(np.mean([res["rich_context_128d"]["best_f1"] for res in results_by_family.values()]))

    print("-" * 80)
    print(f"{'MACRO ZERO-DAY AVG':<20} | {len(attack_traces):<6} | {avg_auc_1g:<10.4f} | {avg_auc_full:<10.4f} | {avg_tpr_1pct*100:<11.2f}% | {avg_f1_full:<8.4f}")
    print("=" * 80)

    report_payload = {
        "protocol": "Held-Out Host Attack-Family Zero-Day Benchmark",
        "author": "Person A (Saharsh - Data & Capture)",
        "week": 5,
        "dataset": "ADFA-LD Linux System Call Dataset",
        "benign_train_size": len(train_traces),
        "benign_val_size": len(val_traces),
        "attack_test_size": len(attack_traces),
        "thresholds": {
            "calibrated_fpr_1pct": thr_1pct_full,
            "calibrated_fpr_01pct": thr_01pct_full
        },
        "macro_metrics": {
            "unigram_baseline_macro_auroc": avg_auc_1g,
            "rich_context_128d_macro_auroc": avg_auc_full,
            "rich_context_macro_tpr_at_1pct_fpr": avg_tpr_1pct,
            "rich_context_macro_f1": avg_f1_full,
            "gain_over_unigram_auroc": avg_auc_full - avg_auc_1g
        },
        "by_family": results_by_family
    }

    if output_file:
        Path(output_file).parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, "w") as f:
            json.dump(report_payload, f, indent=2)
        print(f"\n[+] Saved detailed held-out evaluation report to: {output_file}")

    return report_payload


def main():
    parser = argparse.ArgumentParser(description="Held-Out Host Attack-Family Evaluation Protocol (Person A - Week 5)")
    parser.add_argument("--root", default=None, help="Root path of ADFA-LD dataset")
    parser.add_argument("--out", default=str(PROJECT_ROOT / "detection" / "held_out_host_results.json"), help="Output JSON path")
    args = parser.parse_args()

    root_dir = resolve_data_root(args.root)
    run_held_out_protocol(root_dir, Path(args.out))


if __name__ == "__main__":
    main()
