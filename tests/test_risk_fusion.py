import unittest

from detection.risk_fusion import PillarScores, build_unified_alert
from detection.host_syscall_mapper import classify_host_syscalls


class FixedCalibratedPredictor:
    classes_ = [0, 1]

    def __init__(self, probability=0.73):
        self.probability = probability
        self.last_samples = None

    def predict_proba(self, samples):
        self.last_samples = samples
        return [[1.0 - self.probability, self.probability]]


class RiskFusionTests(unittest.TestCase):
    def test_builds_unified_alert_from_learned_probability(self):
        predictor = FixedCalibratedPredictor()
        base_alert = {
            "alert_id": "alert-1",
            "risk_score": 5,
            "uid": 1000,
            "host_records": [{
                "pid": 123,
                "comm": "worker",
                "command_line": "worker --secret",
                "args": {"path": "/tmp/x", "module_name": "private-module"},
            }],
        }
        host_mapping = classify_host_syscalls(
            [{"syscall": "init_module", "args": {"module_name": "private-module"}}],
            host_anomaly_score=0.9,
            threshold=0.5,
            host_features={"sec_rootkit_module_flag": 1.0},
        )

        result = build_unified_alert(
            base_alert,
            PillarScores(network=0.2, identity=0.4, host=0.9),
            predictor,
            risk_model_source="risk-model-v1-calibrated",
            host_mapping=host_mapping,
            host_shap_features=[{
                "feature": "sec_rootkit_module_flag",
                "shap_value": 0.12,
                "value": 1.0,
            }],
        )

        self.assertEqual(predictor.last_samples, [[0.2, 0.4, 0.9]])
        self.assertEqual(result["pillar_scores"], {
            "network": 0.2, "identity": 0.4, "host": 0.9,
        })
        self.assertEqual(
            (result["network_score"], result["identity_score"], result["host_score"]),
            (0.2, 0.4, 0.9),
        )
        self.assertEqual(result["risk_score"], 73)
        self.assertEqual(result["confidence"], 0.73)
        self.assertNotIn("uid", result)
        self.assertNotIn("host_records", result)
        self.assertNotIn("value", result["host_shap_features"][0])
        self.assertNotIn("worker", str(result))
        self.assertNotIn("/tmp/x", str(result))
        self.assertNotIn("private-module", str(result))
        self.assertNotIn("--secret", str(result))

    def test_scores_must_be_calibrated_probabilities(self):
        with self.assertRaisesRegex(ValueError, r"\[0, 1\]"):
            PillarScores(network=1.2, identity=0.4, host=0.9)

    def test_positive_class_must_exist(self):
        class NegativeOnlyPredictor:
            classes_ = [0]

            def predict_proba(self, samples):
                return [[1.0]]

        with self.assertRaisesRegex(ValueError, "positive class 1"):
            build_unified_alert(
                {},
                PillarScores(network=0.1, identity=0.2, host=0.3),
                NegativeOnlyPredictor(),
                risk_model_source="test",
            )


if __name__ == "__main__":
    unittest.main()
