import pandas as pd
import numpy as np
from sklearn.preprocessing import MinMaxScaler
import os

def load_benign_samples(csv_path, n=50):
    """
    Loads benign dataset samples applying clean column preprocessing steps.
    """
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"Dataset CSV not found at: {csv_path}")
        
    df = pd.read_csv(csv_path)
    df.columns = df.columns.str.strip()
    
    # Cleaning steps matching detection/pipeline_test.py
    df = df.drop(columns=['Label', 'Flow ID', 'Source IP', 'Destination IP',
                           'Timestamp', 'src_ip', 'dst_ip', 'src_port',
                           'dst_port', 'protocol', 'timestamp'], errors='ignore')
    
    # Drop infinity and NaN
    df = df.replace([float('inf'), float('-inf')], float('nan'))
    df = df.dropna(axis=1)
    
    # Select numeric only
    df = df.select_dtypes(include=[float, int])
    
    if df.shape[1] != 76:
        raise ValueError(f"Expected 76 clean features, but got {df.shape[1]}. Check column cleaning parameters.")
        
    # Scale variables matching training normalization
    scaler = MinMaxScaler()
    normalized_data = scaler.fit_transform(df)
    
    # Select n random indices to return
    np.random.seed(42)  # Maintain deterministic samples for repeatability
    indices = np.random.choice(len(normalized_data), size=n, replace=False)
    samples = normalized_data[indices]
    
    # Convert numpy values to plain Python floats
    return [row.tolist() for row in samples]

def load_malicious_samples(csv_path, n=50):
    """
    Generates synthetic malicious feature vectors by perturbing high-impact features
    identified via diagnostic validation (indexes 25, 17, 11, 19, 9).
    Includes an assertion check to guarantee that pre-evasion samples cross the 0.5 threshold.
    """
    from detection.stub_detector import score_flow
    
    benign_samples = load_benign_samples(csv_path, n=n)
    malicious_samples = []
    
    # Highly sensitive autoencoder reconstruction features ranked via diagnosis script:
    # 25: fwd_act_data_pkts
    # 17: pkt_len_max
    # 11: fwd_pkt_len_mean
    # 19: pkt_len_mean
    # 9:  fwd_pkt_len_max
    target_indices = [25, 17, 11, 19, 9]
    
    for sample in benign_samples:
        malicious_vec = list(sample)
        # Spike high-impact features to force high reconstruction error
        for idx in target_indices:
            malicious_vec[idx] = sample[idx] + 5.0
            
        # Verify that the generated malicious sample crosses the 0.5 threshold
        alert = score_flow(malicious_vec)
        score = alert["anomaly_score"]
        assert score > 0.5, f"Generated sample failed to exceed 0.5 detection threshold (score: {score})."
        
        malicious_samples.append(malicious_vec)
        
    return malicious_samples

