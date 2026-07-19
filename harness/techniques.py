import numpy as np

def mimicry_attack(malicious_vec, benign_vec, steps=20):
    """
    Interpolates linearly from the malicious vector toward the benign vector.
    """
    m_arr = np.array(malicious_vec)
    b_arr = np.array(benign_vec)
    intermediates = []
    
    for step in range(steps + 1):
        alpha = step / steps
        interpolated = (1 - alpha) * m_arr + alpha * b_arr
        intermediates.append(interpolated.tolist())
        
    return intermediates

def feature_padding_attack(malicious_vec, benign_vec, target_indices=None, steps=20):
    """
    Only interpolates specific feature indices most different between malicious_vec and benign_vec.
    Leaving other features in the malicious_vec as-is.
    """
    m_arr = np.array(malicious_vec)
    b_arr = np.array(benign_vec)
    
    if target_indices is None:
        # Identify indices with largest absolute difference
        diffs = np.abs(m_arr - b_arr)
        # Select top 10 feature indices
        target_indices = np.argsort(diffs)[-10:]
        
    intermediates = []
    for step in range(steps + 1):
        alpha = step / steps
        interpolated = np.copy(m_arr)
        for idx in target_indices:
            interpolated[idx] = (1 - alpha) * m_arr[idx] + alpha * b_arr[idx]
        intermediates.append(interpolated.tolist())
        
    return intermediates

def slow_drip_attack(malicious_vec, n_splits=10):
    """
    Splits a single aggregate flow into n_splits flows.
    Divides count/byte/duration features by n_splits.
    Assuming typical indices for flow_duration, flow_byts_s, flow_pkts_s, tot_fwd_pkts etc.
    """
    # For robust simulation without hardcoded layout shifts, we divide the first 25 index values
    # representing flow metrics (duration, packets, volume counts).
    intermediates = []
    for _ in range(n_splits):
        split_vec = list(malicious_vec)
        # Let's scale typical duration, byte/packet rate and packet count fields:
        # 0: flow_duration
        # 1: flow_byts_s
        # 2: flow_pkts_s
        # 3: fwd_pkts_s
        # 4: bwd_pkts_s
        # 5: tot_fwd_pkts
        # 6: tot_bwd_pkts
        # 7: totlen_fwd_pkts
        # 8: totlen_bwd_pkts
        for idx in range(15):
            split_vec[idx] = split_vec[idx] / n_splits
        intermediates.append(split_vec)
        
    return intermediates
