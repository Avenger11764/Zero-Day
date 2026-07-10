import torch
import torch.nn as nn
import numpy as np
import pandas as pd
from sklearn.preprocessing import MinMaxScaler
from collections import defaultdict
import matplotlib.pyplot as plt

SEQUENCE_LEN = 10
HIDDEN_DIM = 64
LATENT_DIM = 16
EPOCHS = 50
BATCH_SIZE = 128

# ─────────────────────────────────────────────
# STEP 1: Load data and build sequences
# ─────────────────────────────────────────────

print("Step 1: Loading data and building sequences...")

df = pd.read_csv(r"D:\Test OD\Zero-Day\data\MachineLearningCSV\MachineLearningCVE\Monday-WorkingHours.pcap_ISCX.csv")
df.columns = df.columns.str.strip()
df = df[df['Label'] == 'BENIGN']

# Save source IP for grouping before dropping
src_ip = df['Source IP'].values if 'Source IP' in df.columns else None

df = df.drop(columns=['Label', 'Flow ID', 'Source IP', 'Destination IP',
                       'Timestamp'], errors='ignore')
df = df.replace([float('inf'), float('-inf')], float('nan'))
df = df.dropna(axis=1)

scaler = MinMaxScaler()
data = scaler.fit_transform(df)
n_features = data.shape[1]

print(f"  Loaded {data.shape[0]} flows, {n_features} features")

# Group flows by source IP and build sequences of 10
print("  Building sequences...")
if src_ip is not None:
    ip_flows = defaultdict(list)
    for i, ip in enumerate(src_ip):
        ip_flows[ip].append(data[i])

    sequences = []
    for ip, flows in ip_flows.items():
        flows = np.array(flows)
        for start in range(0, len(flows) - SEQUENCE_LEN + 1, SEQUENCE_LEN):
            seq = flows[start:start + SEQUENCE_LEN]
            if len(seq) == SEQUENCE_LEN:
                sequences.append(seq)
else:
    sequences = []
    for start in range(0, len(data) - SEQUENCE_LEN + 1, SEQUENCE_LEN):
        sequences.append(data[start:start + SEQUENCE_LEN])

sequences = np.array(sequences, dtype=np.float32)
print(f"  Built {len(sequences)} sequences of length {SEQUENCE_LEN}")

X_train = torch.tensor(sequences)


# ─────────────────────────────────────────────
# STEP 2: Define LSTM Autoencoder
# ─────────────────────────────────────────────

print("\nStep 2: Building LSTM temporal autoencoder...")

class LSTMEncoder(nn.Module):
    def __init__(self, input_dim, hidden_dim, latent_dim):
        super().__init__()
        self.lstm = nn.LSTM(input_dim, hidden_dim, batch_first=True)
        self.fc = nn.Linear(hidden_dim, latent_dim)

    def forward(self, x):
        _, (hidden, _) = self.lstm(x)
        return self.fc(hidden[-1])


class LSTMDecoder(nn.Module):
    def __init__(self, latent_dim, hidden_dim, output_dim, seq_len):
        super().__init__()
        self.seq_len = seq_len
        self.fc = nn.Linear(latent_dim, hidden_dim)
        self.lstm = nn.LSTM(hidden_dim, hidden_dim, batch_first=True)
        self.out = nn.Linear(hidden_dim, output_dim)

    def forward(self, latent):
        x = self.fc(latent).unsqueeze(1).repeat(1, self.seq_len, 1)
        x, _ = self.lstm(x)
        return torch.sigmoid(self.out(x))


class TemporalAutoencoder(nn.Module):
    def __init__(self, input_dim, hidden_dim, latent_dim, seq_len):
        super().__init__()
        self.encoder = LSTMEncoder(input_dim, hidden_dim, latent_dim)
        self.decoder = LSTMDecoder(latent_dim, hidden_dim, input_dim, seq_len)

    def forward(self, x):
        return self.decoder(self.encoder(x))

    def anomaly_score(self, x):
        with torch.no_grad():
            recon = self.forward(x)
            return torch.mean((recon - x) ** 2, dim=(1, 2))


model = TemporalAutoencoder(
    input_dim=n_features,
    hidden_dim=HIDDEN_DIM,
    latent_dim=LATENT_DIM,
    seq_len=SEQUENCE_LEN
)

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
if device.type == "cpu":
    raise RuntimeError("GPU not found. Check CUDA installation.")

model = model.to(device)
print(f"  Running on: {device}")
print(f"  Parameters: {sum(p.numel() for p in model.parameters()):,}")


# ─────────────────────────────────────────────
# STEP 3: Train
# ─────────────────────────────────────────────

print(f"\nStep 3: Training for {EPOCHS} epochs...")

optimizer = torch.optim.Adam(model.parameters(), lr=0.001)
loss_fn = nn.MSELoss()
losses = []

dataset = torch.utils.data.TensorDataset(X_train)
loader = torch.utils.data.DataLoader(dataset,
                                      batch_size=BATCH_SIZE,
                                      shuffle=True)

for epoch in range(EPOCHS):
    epoch_loss = 0
    for (batch,) in loader:
        batch = batch.to(device)
        output = model(batch)
        loss = loss_fn(output, batch)
        optimizer.zero_grad()
        loss.backward()
        optimizer.step()
        epoch_loss += loss.item()

    avg_loss = epoch_loss / len(loader)
    losses.append(avg_loss)

    if epoch % 10 == 0:
        print(f"  Epoch {epoch:3d} | Loss: {avg_loss:.6f}")

print("  Training finished.")


# ─────────────────────────────────────────────
# STEP 4: Test
# ─────────────────────────────────────────────

print("\nStep 4: Scoring sequences...")

# Normal — average traffic values across 10 timesteps
normal_seq = torch.full((1, SEQUENCE_LEN, n_features), 0.4,
                         dtype=torch.float32).to(device)

# Beaconing attack — identical pattern repeated every timestep (suspicious)
beacon_row = torch.full((1, 1, n_features), 0.95, dtype=torch.float32)
attack_seq = beacon_row.repeat(1, SEQUENCE_LEN, 1).to(device)

normal_score = model.anomaly_score(normal_seq).item()
attack_score = model.anomaly_score(attack_seq).item()

print(f"  Normal sequence score : {normal_score:.6f}  <- should be LOW")
print(f"  Beacon attack score   : {attack_score:.6f}  <- should be HIGH")

if attack_score > normal_score:
    print("  Temporal model working correctly!")
else:
    print("  Scores inverted — flag for review")


# ─────────────────────────────────────────────
# STEP 5: Save
# ─────────────────────────────────────────────

torch.save(model.state_dict(), "detection/temporal_autoencoder_v1.pt")
print("\n  Saved to detection/temporal_autoencoder_v1.pt")

plt.figure(figsize=(8, 4))
plt.plot(losses)
plt.title("Temporal Autoencoder training loss")
plt.xlabel("Epoch")
plt.ylabel("MSE Loss")
plt.tight_layout()
plt.savefig("detection/temporal_loss_curve.png")
print("  Loss curve saved to detection/temporal_loss_curve.png")
print("\nBlock 3 complete.")