import sys
import os
import pandas as pd
import numpy as np

# Adjust system path to import from detection directory
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from detection.stub_detector import score_flow
from harness.utils import load_benign_samples, load_malicious_samples
from harness.techniques import mimicry_attack, feature_padding_attack, slow_drip_attack

def run_evaluation():
    csv_path = "training_data/dataset_10k_normal.csv"
    
    print("Loading samples...")
    benign_samples = load_benign_samples(csv_path, n=20)
    malicious_samples = load_malicious_samples(csv_path, n=20)
    
    results = []
    
    # Track statistics for evasion rate calculations
    mimicry_successes = 0
    padding_successes = 0
    drip_successes = 0
    
    print("\nRunning Evasion Harness Evaluation against Autoencoder Model variant...")
    
    for sample_id, m_vec in enumerate(malicious_samples):
        # Pick a target benign sample deterministically for repeatability
        b_vec = benign_samples[sample_id % len(benign_samples)]
        
        # 1. Mimicry Attack
        mimicry_variants = mimicry_attack(m_vec, b_vec, steps=20)
        mimicry_evaded = False
        evaded_step_mimicry = -1
        
        for step_idx, variant in enumerate(mimicry_variants):
            alert = score_flow(variant)
            score = alert["anomaly_score"]
            flagged = score > 0.5
            
            if not flagged and not mimicry_evaded:
                mimicry_evaded = True
                evaded_step_mimicry = step_idx
                
            results.append({
                "technique": "mimicry_attack",
                "sample_id": sample_id,
                "step": step_idx,
                "anomaly_score": score,
                "flagged": int(flagged),
                "evaded_at_step": evaded_step_mimicry if step_idx == len(mimicry_variants) - 1 or mimicry_evaded else -1
            })
        if mimicry_evaded:
            mimicry_successes += 1
            
        # Update last logged step for correctness
        for r in results[-len(mimicry_variants):]:
            r["evaded_at_step"] = evaded_step_mimicry
            
        # 2. Feature Padding Attack
        padding_variants = feature_padding_attack(m_vec, b_vec, steps=20)
        padding_evaded = False
        evaded_step_padding = -1
        
        for step_idx, variant in enumerate(padding_variants):
            alert = score_flow(variant)
            score = alert["anomaly_score"]
            flagged = score > 0.5
            
            if not flagged and not padding_evaded:
                padding_evaded = True
                evaded_step_padding = step_idx
                
            results.append({
                "technique": "feature_padding_attack",
                "sample_id": sample_id,
                "step": step_idx,
                "anomaly_score": score,
                "flagged": int(flagged),
                "evaded_at_step": evaded_step_padding if step_idx == len(padding_variants) - 1 or padding_evaded else -1
            })
        if padding_evaded:
            padding_successes += 1
            
        for r in results[-len(padding_variants):]:
            r["evaded_at_step"] = evaded_step_padding
            
        # 3. Slow-Drip Attack
        drip_variants = slow_drip_attack(m_vec, n_splits=10)
        drip_evaded = False
        evaded_step_drip = -1
        
        for step_idx, variant in enumerate(drip_variants):
            alert = score_flow(variant)
            score = alert["anomaly_score"]
            flagged = score > 0.5
            
            if not flagged and not drip_evaded:
                drip_evaded = True
                evaded_step_drip = step_idx
                
            results.append({
                "technique": "slow_drip_attack",
                "sample_id": sample_id,
                "step": step_idx,
                "anomaly_score": score,
                "flagged": int(flagged),
                "evaded_at_step": evaded_step_drip if step_idx == len(drip_variants) - 1 or drip_evaded else -1
            })
        if drip_evaded:
            drip_successes += 1
            
        for r in results[-len(drip_variants):]:
            r["evaded_at_step"] = evaded_step_drip
            
    # Calculate Success Rates
    total_attempts = len(malicious_samples)
    print("\n==========================================")
    print("           EVASION EVALUATION RESULTS     ")
    print("==========================================")
    print(f"Mimicry Attack Evasion Rate        : {100 * mimicry_successes / total_attempts:.1f}%")
    print(f"Feature Padding Evasion Rate       : {100 * padding_successes / total_attempts:.1f}%")
    print(f"Slow Drip Attack Evasion Rate      : {100 * drip_successes / total_attempts:.1f}%")
    print("==========================================\n")
    
    # Save output to baseline folder
    os.makedirs("harness/results", exist_ok=True)
    df_out = pd.DataFrame(results)
    df_out.to_csv("harness/results/autoencoder_v2_baseline_v2.csv", index=False)
    print("All results saved successfully to harness/results/autoencoder_v2_baseline_v2.csv")

if __name__ == "__main__":
    run_evaluation()
