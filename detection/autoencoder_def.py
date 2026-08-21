"""
Canonical Autoencoder definition for M5a (per-flow baseline).

Architecture: 76 → 256 → 128 → 32 → 128 → 256 → 76 (Sigmoid)
Latent dimension: 32
Used by: stub_detector.py (production scoring), shap_explainer.py (explanations)
"""

import torch
import torch.nn as nn

EXPECTED_FEATURES = 76


class Autoencoder(nn.Module):
    """M5a baseline autoencoder: 76 → 256 → 128 → 32 → 128 → 256 → 76 (Sigmoid)."""

    def __init__(self, input_dim: int = 76):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 256),
            nn.ReLU(),
            nn.Linear(256, 128),
            nn.ReLU(),
            nn.Linear(128, 32),
        )
        self.decoder = nn.Sequential(
            nn.Linear(32, 128),
            nn.ReLU(),
            nn.Linear(128, 256),
            nn.ReLU(),
            nn.Linear(256, input_dim),
            nn.Sigmoid(),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.decoder(self.encoder(x))

    def anomaly_score(self, x: torch.Tensor) -> torch.Tensor:
        """Reconstruction error (MSE) as anomaly score."""
        with torch.no_grad():
            recon = self.forward(x)
            return torch.mean((recon - x) ** 2, dim=1)


# Feature names in exact order (76 features for M5a)
FEATURE_NAMES = [
    "flow_duration", "flow_byts_s", "flow_pkts_s", "fwd_pkts_s",
    "bwd_pkts_s", "tot_fwd_pkts", "tot_bwd_pkts", "totlen_fwd_pkts",
    "totlen_bwd_pkts", "fwd_pkt_len_max", "fwd_pkt_len_min",
    "fwd_pkt_len_mean", "fwd_pkt_len_std", "bwd_pkt_len_max",
    "bwd_pkt_len_min", "bwd_pkt_len_mean", "bwd_pkt_len_std",
    "pkt_len_max", "pkt_len_min", "pkt_len_mean", "pkt_len_std",
    "pkt_len_var", "fwd_header_len", "bwd_header_len",
    "fwd_seg_size_min", "fwd_act_data_pkts", "flow_iat_mean",
    "flow_iat_max", "flow_iat_min", "flow_iat_std", "fwd_iat_tot",
    "fwd_iat_max", "fwd_iat_min", "fwd_iat_mean", "fwd_iat_std",
    "bwd_iat_tot", "bwd_iat_max", "bwd_iat_min", "bwd_iat_mean",
    "bwd_iat_std", "fwd_psh_flags", "bwd_psh_flags", "fwd_urg_flags",
    "bwd_urg_flags", "fin_flag_cnt", "syn_flag_cnt", "rst_flag_cnt",
    "psh_flag_cnt", "ack_flag_cnt", "urg_flag_cnt", "ece_flag_cnt",
    "down_up_ratio", "pkt_size_avg", "init_fwd_win_byts",
    "init_bwd_win_byts", "active_max", "active_min", "active_mean",
    "active_std", "idle_max", "idle_min", "idle_mean", "idle_std",
    "fwd_byts_b_avg", "fwd_pkts_b_avg", "bwd_byts_b_avg",
    "bwd_pkts_b_avg", "fwd_blk_rate_avg", "bwd_blk_rate_avg",
    "fwd_seg_size_avg", "bwd_seg_size_avg", "cwr_flag_count",
    "subflow_fwd_pkts", "subflow_bwd_pkts", "subflow_fwd_byts",
    "subflow_bwd_byts",
]

# Checkpoint metadata
CHECKPOINT_META = {
    "model_type": "autoencoder_v2-256",
    "input_dim": 76,
    "latent_dim": 32,
    "architecture": "76-256-128-32-128-256-76",
    "activation": "relu",
    "output_activation": "sigmoid",
}