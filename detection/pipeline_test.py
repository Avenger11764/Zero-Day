import torch
import torch.nn as nn
import pandas as pd 
import numpy as np
from sklearn.preprocessing import MinMaxScaler
import sys

csv_path = sys.argv[1] if len(sys.argv) > 1 else r"D:\Test OD\Zero-Day\training_data\dataset_10k_normal.csv"

print(f"Loading A's dataset from {csv_path}")
df = pd.read_csv(csv_path)
df.columns = df.columns.str.strip()

# Drop known metadata columns by name
df = df.drop(columns=['Label', 'Flow ID', 'Source IP', 'Destination IP',
                       'Timestamp', 'src_ip', 'dst_ip', 'src_port',
                       'dst_port', 'protocol', 'timestamp'], errors='ignore')

# Drop infinity and NaN
df = df.replace([float('inf'), float('-inf')], float('nan'))
df = df.dropna(axis=1)

# Drop any remaining non-numeric columns regardless of name
df = df.select_dtypes(include=[float, int])

print(f"  Loaded {len(df)} flows, {df.shape[1]} features")

if df.shape[1] != 76:
    print(f"  WARNING: Expected 76 features, got {df.shape[1]}")
    print(f"  Tell A to re-export using CICFlowMeter to get exactly 76 features")
else:
    print("  Feature count: 76 ✓")

# Normalize
scaler = MinMaxScaler()
data = scaler.fit_transform(df)
X = torch.tensor(data, dtype=torch.float32)

# Load trained model
class Autoencoder(nn.Module):
    def __init__(self, input_dim=76):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 256),
            nn.ReLU(),
            nn.Linear(256, 128),
            nn.ReLU(),
            nn.Linear(128, 32)
        )
        self.decoder = nn.Sequential(
            nn.Linear(32, 128),
            nn.ReLU(),
            nn.Linear(128, 256),
            nn.ReLU(),
            nn.Linear(256, input_dim),
            nn.Sigmoid()
        )

    def forward(self, x):
        return self.decoder(self.encoder(x))

    def anomaly_score(self, x):
        with torch.no_grad():
            recon = self.forward(x)
            return torch.mean((recon - x) ** 2, dim=1)

model = Autoencoder(input_dim=df.shape[1])
model.load_state_dict(torch.load("detection/autoencoder_v2-256.pt",
                                  map_location="cpu", weights_only=True))
model.eval()

# Score all flows
scores = model.anomaly_score(X).numpy()
threshold = 0.5

flagged = (scores > threshold).sum()
print(f"\n  Results on A's dataset:")
print(f"  Total flows    : {len(scores)}")
print(f"  Mean score     : {scores.mean():.6f}")
print(f"  Max score      : {scores.max():.6f}")
print(f"  Min score      : {scores.min():.6f}")
print(f"  Flagged        : {flagged} ({100*flagged/len(scores):.1f}%)")
print("\n  Pipeline test complete — A's data flows into model correctly.")