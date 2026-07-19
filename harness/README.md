# Red-Team Evasion Evaluation Harness

This framework implements and evaluates adversarial evasion techniques targeting our network anomaly detectors.

## Structure
- [utils.py](file:///d:/downloads/zero-day/harness/utils.py): Normalizes normal flows using CICIDS2017 features, and generates synthetic malicious samples by perturbing key fields (e.g. packet rates and durations).
- [techniques.py](file:///d:/downloads/zero-day/harness/techniques.py): Implements three main evasion algorithms:
  - **Mimicry Attack**: Linearly interpolates from a malicious vector toward a benign reference.
  - **Feature Padding**: Interpolates only the top 10 features with the highest absolute deviation.
  - **Slow-Drip**: Simulates a flow partition splitting volume/packet metrics over smaller splits.
- [run_harness.py](file:///d:/downloads/zero-day/harness/run_harness.py): The entry point orchestrating benchmark runs against the target autoencoder model.

## Run Evaluation
Set the terminal environment to `UTF-8` and execute the evaluation harness using:
```bash
$env:PYTHONIOENCODING="utf-8"
python harness/run_harness.py
```

## Results Logs
Results are exported to [harness/results/autoencoder_v2_baseline.csv](file:///d:/downloads/zero-day/harness/results/autoencoder_v2_baseline.csv) containing performance scores, threshold violations, and step-level details for audit mapping.
