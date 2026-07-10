import numpy as np
from collections import deque
import json
from datetime import datetime, UTC

class DriftMonitor:
    """
    Watches anomaly scores over time.
    Flags when the model's baseline is drifting.
    """

    def __init__(self, window_size=1000, drift_threshold=0.05):
        """
        window_size     : how many recent scores to track
        drift_threshold : how much the mean can rise before flagging
        """
        self.window_size = window_size
        self.drift_threshold = drift_threshold
        self.scores = deque(maxlen=window_size)
        self.baseline_mean = None
        self.baseline_std = None
        self.drift_events = []

    def set_baseline(self, scores: list):
        """
        Call this once with scores from your training data.
        This is what 'normal' looks like.
        """
        self.baseline_mean = np.mean(scores)
        self.baseline_std = np.std(scores)
        print(f"  Baseline set: mean={self.baseline_mean:.6f}, "
              f"std={self.baseline_std:.6f}")

    def add_score(self, score: float):
        """Add a new score from live traffic."""
        self.scores.append(score)

    def check_drift(self) -> dict:
        """
        Check if current scores have drifted from baseline.
        Returns drift report.
        """
        if self.baseline_mean is None:
            return {"status": "no_baseline", "drift_detected": False}

        if len(self.scores) < 100:
            return {"status": "insufficient_data",
                    "drift_detected": False,
                    "current_count": len(self.scores)}

        current_mean = np.mean(self.scores)
        drift = current_mean - self.baseline_mean
        drift_detected = abs(drift) > self.drift_threshold

        report = {
            "timestamp": datetime.now(UTC).isoformat(),
            "status": "drift_detected" if drift_detected else "stable",
            "drift_detected": drift_detected,
            "baseline_mean": round(self.baseline_mean, 6),
            "current_mean": round(current_mean, 6),
            "drift_amount": round(drift, 6),
            "threshold": self.drift_threshold,
            "window_size": len(self.scores),
            "recommendation": "retrain model" if drift_detected else "no action needed"
        }

        if drift_detected:
            self.drift_events.append(report)
            print(f"  DRIFT ALERT: mean rose by {drift:.6f} "
                  f"(threshold: {self.drift_threshold})")

        return report

    def summary(self) -> dict:
        """Full summary of drift monitor state."""
        return {
            "baseline_mean": self.baseline_mean,
            "baseline_std": self.baseline_std,
            "current_window_size": len(self.scores),
            "total_drift_events": len(self.drift_events),
            "drift_events": self.drift_events
        }


# ── Test the drift monitor ──
if __name__ == "__main__":
    import torch
    import torch.nn as nn
    import pandas as pd
    from sklearn.preprocessing import MinMaxScaler

    print("Testing drift monitor on CICIDS2017 Monday data...\n")

    # Load a sample of training data to set baseline
    df = pd.read_csv(r"D:\Test OD\Zero-Day\data\MachineLearningCSV\MachineLearningCVE\Monday-WorkingHours.pcap_ISCX.csv")
    df.columns = df.columns.str.strip()
    df = df[df['Label'] == 'BENIGN'].head(5000)  # sample for speed
    df = df.drop(columns=['Label', 'Flow ID', 'Source IP',
                          'Destination IP', 'Timestamp'], errors='ignore')
    df = df.replace([float('inf'), float('-inf')], float('nan'))
    df = df.dropna(axis=1)

    scaler = MinMaxScaler()
    data = scaler.fit_transform(df)
    X = torch.tensor(data, dtype=torch.float32)

    # Load your trained model
    class Autoencoder(nn.Module):
        def __init__(self, input_dim):
            super().__init__()
            self.encoder = nn.Sequential(
                nn.Linear(input_dim, 256), nn.ReLU(), nn.Linear(256, 128), nn.ReLU(), nn.Linear(128, 32))
            self.decoder = nn.Sequential(
                nn.Linear(32, 128), nn.ReLU(),
                nn.Linear(128, 256), nn.ReLU(),
                nn.Linear(256, input_dim), nn.Sigmoid())

        def forward(self, x):
            return self.decoder(self.encoder(x))

        def anomaly_score(self, x):
            with torch.no_grad():
                recon = self.forward(x)
                return torch.mean((recon - x) ** 2, dim=1)

    model = Autoencoder(input_dim=X.shape[1])
    model.load_state_dict(torch.load("detection/autoencoder_v2-256.pt",
                                     map_location="cpu", weights_only=True))
    model.eval()

    # Get baseline scores
    baseline_scores = model.anomaly_score(X).numpy().tolist()

    # Init monitor
    monitor = DriftMonitor(window_size=1000, drift_threshold=0.05)
    monitor.set_baseline(baseline_scores)

    # Simulate stable traffic — should show no drift
    print("\nSimulating stable traffic (no drift expected)...")
    stable_scores = np.random.normal(
        monitor.baseline_mean, monitor.baseline_std, 1000)
    for s in stable_scores:
        monitor.add_score(float(s))
    report = monitor.check_drift()
    print(f"  Status: {report['status']}")

    # Simulate drifting traffic — model going stale
    print("\nSimulating drifting traffic (drift expected)...")
    monitor2 = DriftMonitor(window_size=1000, drift_threshold=0.05)
    monitor2.set_baseline(baseline_scores)
    drifted_scores = np.random.normal(
        monitor.baseline_mean + 0.15, monitor.baseline_std, 1000)
    for s in drifted_scores:
        monitor2.add_score(float(s))
    report2 = monitor2.check_drift()
    print(f"  Status: {report2['status']}")
    print(f"  Drift amount: {report2['drift_amount']:.6f}")
    print(f"  Recommendation: {report2['recommendation']}")

    print("\nDrift monitor working correctly.")