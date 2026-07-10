import torch
import torch.nn as nn
import numpy as np
from sklearn.preprocessing import MinMaxScaler
import matplotlib.pyplot as plt
import pandas as pd
# #Generate synthetic data for testing
# #

# np.random.seed(42)
# n_samples=10000
# n_features=20
# normal_data = np.random.normal(loc=0.4, scale=0.1, size=(n_samples, n_features))
# normal_data = np.clip(normal_data, 0, 1)

# print("Data shape:", normal_data.shape)

# X_train = torch.tensor(normal_data, dtype=torch.float32)
# print("converted to tensor:", X_train.shape)



"""Load the dataset"""



# Monday = pure normal traffic, perfect for training
df = pd.read_csv(r"D:\Test OD\Zero-Day\data\MachineLearningCSV\MachineLearningCVE\Monday-WorkingHours.pcap_ISCX.csv")


df.columns = df.columns.str.strip()

# Keep only BENIGN rows (Monday is all benign but just to be safe)
df = df[df['Label'] == 'BENIGN']

# Drop non-numeric and label columns
df = df.drop(columns=['Label', 'Flow ID', 'Source IP', 'Destination IP',
                       'Timestamp'], errors='ignore')

# Drop columns with NaN or infinity (common in this dataset)
df = df.replace([float('inf'), float('-inf')], float('nan'))
df = df.dropna(axis=1)

# Normalize the data to [0, 1] range
from sklearn.preprocessing import MinMaxScaler
scaler = MinMaxScaler()
normal_data = scaler.fit_transform(df)

print(f"  Loaded {normal_data.shape[0]} normal flows, {normal_data.shape[1]} features")

n_features = normal_data.shape[1]
X_train = torch.tensor(normal_data, dtype=torch.float32)


"""THE Autoencoder """

class Autoencoder(nn.Module):
    def __init__(self,input_dim=20):
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
        compressed = self.encoder(x)
        reconstructed = self.decoder(compressed)
        return reconstructed
    
    def anomaly_score(self, x):
        """Reconstruction error == Anomaly hui  ==anomaly score"""
        with torch.no_grad():
            recon = self.forward(x)
            # Mean squared error 
            error = torch.mean((recon - x) ** 2, dim=1)
        return error
    
# model = Autoencoder(input_dim=n_features)

"""TRAINING"""
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
model = Autoencoder(input_dim=n_features).to(device)
print(f"  Running on: {device}")

Optimizer = torch.optim.Adam(model.parameters(), lr=0.0001)
loss_fn = nn.MSELoss()
losses = []

epochs = 100
batch_size = 256

dataset = torch.utils.data.TensorDataset(X_train)
loader = torch.utils.data.DataLoader(dataset, batch_size=batch_size, shuffle=True)

for epoch in range(epochs):
    epoch_loss = 0
    for (batch,) in loader:
        batch=batch.to(device)
        output = model(batch)
        loss = loss_fn(output, batch)
        Optimizer.zero_grad()
        loss.backward()
        Optimizer.step()
        epoch_loss += loss.item()
    avg_loss=epoch_loss / len(loader)
    losses.append(avg_loss)

    if (epoch % 10 == 0):
        print(f"Epoch {epoch:3d} | loss : {avg_loss:.6f}")
print("Training finished.")


"""Save the model"""
torch.save(model.state_dict(), "detection/autoencoder_v2-256.pt")
print("  Saved to detection/autoencoder_v2-256.pt")



"""Test - score normal vs attack"""
model.eval()

normal_sample = torch.full((1, n_features), 0.4, dtype=torch.float32).to(device)
attack_sample = torch.full((1, n_features), 0.99, dtype=torch.float32).to(device)

normal_score = model.anomaly_score(normal_sample).item()
attack_score = model.anomaly_score(attack_sample).item()

print(f"\n  Normal score : {normal_score:.6f}  <- should be LOW")
print(f"  Attack score : {attack_score:.6f}  <- should be HIGH")

if attack_score > normal_score:
    print("  Model is working correctly!")
else:
    print("  Scores wrong way — flag for week 2")





plt.figure(figsize=(8, 4))
plt.plot(losses)
plt.title("Autoencoder training loss")
plt.xlabel("Epoch")
plt.ylabel("MSE Loss")
plt.tight_layout()
plt.savefig("detection/loss_curve.png")
print("  Loss curve saved to detection/loss_curve.png")

