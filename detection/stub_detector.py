# stub_detector.py
# Week 1 
# Replace this with the real autoencoder 

def score_flow(feature_vector: list) -> dict:
    """
    Takes a feature vector (list of numbers)
    Returns an anomaly score between 0 and 1
    0 = totally normal, 1 = highly anomalous
    """
    # hardcoded for now — real model swaps in next week
    return {
        "anomaly_score": 0.08,
        "threshold": 0.50,
        "is_anomaly": False,
        "model_version": "stub-v1"
    }


# Quick test — run this file directly to confirm it works
if __name__ == "__main__":
    fake_vector = [0.1, 0.4, 0.2, 0.9, 0.3, 0.1, 0.5, 0.2,
                   0.8, 0.1, 0.3, 0.6, 0.4, 0.2, 0.7, 0.1,
                   0.9, 0.3, 0.1, 0.5]
    result = score_flow(fake_vector)
    print("Stub working:", result)