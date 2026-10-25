import unittest

import numpy as np
import torch
from torch import nn

from detection.host_shap_explainer import (
    explain_host_anomaly,
    feature_names_from_checkpoint,
)


class HalfScaleAutoencoder(nn.Module):
    def forward(self, features):
        return features * 0.5


class HostShapExplainerTests(unittest.TestCase):
    def test_explanation_uses_canonical_names_and_omits_feature_values(self):
        model = HalfScaleAutoencoder()
        background = np.array([[0.0] * 128, [0.25] * 128], dtype=np.float32)
        samples = np.array([[0.5] * 128], dtype=np.float32)

        result = explain_host_anomaly(model, samples, background, top_k=3)[0]

        self.assertAlmostEqual(result["anomaly_score"], 0.0625, places=5)
        self.assertEqual(len(result["top_features"]), 3)
        self.assertEqual(result["top_features"][0]["feature"], "sc_1gram_0")
        self.assertNotIn("value", result["top_features"][0])
        self.assertIn(
            result["top_features"][0]["direction"],
            {"increases_anomaly", "decreases_anomaly", "neutral"},
        )

    def test_legacy_checkpoint_names_follow_vocabulary_indices(self):
        checkpoint = {
            "V": 2,
            "n_dim": 5,
            "vocab": {60: 1, 1: 0},
        }

        names = feature_names_from_checkpoint(
            checkpoint,
            syscall_names={1: "write", 60: "umask"},
        )

        self.assertEqual(
            names,
            ("syscall_write", "syscall_umask", "trace_log10_length",
             "trace_unique_rate", "trace_unknown_fraction"),
        )

    def test_dimension_mismatch_is_reported(self):
        with self.assertRaisesRegex(ValueError, "feature names"):
            explain_host_anomaly(
                HalfScaleAutoencoder(),
                [[0.1, 0.2]],
                [[0.0, 0.0]],
                feature_names=["one"],
            )


if __name__ == "__main__":
    unittest.main()
