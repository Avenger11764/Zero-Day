import sys
import os
import numpy as np
import pandas as pd

# Path configurations
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from detection.stub_detector import score_flow
from harness.utils import load_benign_samples

def diagnose():
    csv_path = "training_data/dataset_10k_normal.csv"
    benign_samples = load_benign_samples(csv_path, n=10)
    
    # We want to check all 76 features
    feature_impact = []
    
    # Get column names
    df_raw = pd.read_csv(csv_path)
    df_raw.columns = df_raw.columns.str.strip()
    df_cleaned = df_raw.drop(columns=['Label', 'Flow ID', 'Source IP', 'Destination IP',
                                      'Timestamp', 'src_ip', 'dst_ip', 'src_port',
                                      'dst_port', 'protocol', 'timestamp'], errors='ignore')
    df_cleaned = df_cleaned.replace([float('inf'), float('-inf')], float('nan')).dropna(axis=1)
    df_cleaned = df_cleaned.select_dtypes(include=[float, int])
    feature_names = df_cleaned.columns.tolist()
    
    print("Testing perturbations per feature...")
    for idx in range(76):
        scores_at_multiples = []
        for multiplier in [2.0, 5.0, 10.0, 20.0]:
            temp_scores = []
            for sample in benign_samples:
                perturbed = list(sample)
                # Since the input is MinMaxScaler normalized to [0,1], let's try a direct addition 
                # or multiplication to see if we can trigger high reconstruction error.
                # In PyTorch stub_detector, the Sigmoid function limits the output to [0,1].
                # If we supply a value way outside [0,1], the squared reconstruction error (x - recon)^2
                # can grow extremely large.
                perturbed[idx] = sample[idx] + (multiplier * 1.0)
                alert = score_flow(perturbed)
                temp_scores.append(alert["anomaly_score"])
            scores_at_multiples.append(np.mean(temp_scores))
        
        # Store average score at the highest perturbation (20x)
        feature_impact.append({
            "index": idx,
            "name": feature_names[idx] if idx < len(feature_names) else f"feature_{idx}",
            "score_2x": scores_at_multiples[0],
            "score_5x": scores_at_multiples[1],
            "score_10x": scores_at_multiples[2],
            "score_20x": scores_at_multiples[3],
            "max_increase": scores_at_multiples[3] - scores_at_multiples[0]
        })
        
    # Rank by score at 20x
    feature_impact.sort(key=lambda x: x["score_20x"], reverse=True)
    print("\n--- Top 15 Ranked Features by Anomaly Score Impact ---")
    for rank, item in enumerate(feature_impact[:15]):
        print(f"{rank+1}. Index {item['index']} ({item['name']}): "
              f"2x={item['score_2x']:.4f}, 5x={item['score_5x']:.4f}, "
              f"10x={item['score_10x']:.4f}, 20x={item['score_20x']:.4f}")

if __name__ == "__main__":
    diagnose()
