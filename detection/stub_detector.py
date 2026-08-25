"""
DEPRECATED SHIM — the real legacy M5a lives in `legacy/`.
=========================================================
Kept only so existing imports keep working:
    from detection.stub_detector import score_flow, _get_model, ...

Checkpoint-1, the dashboard, the red-team harness and several eval scripts
import from here. The shipped plain M5a is STALE for detection purposes
(superseded by the revived 87-dim ctx AE inside alert_pipeline).

New code must NOT import from this module.
"""
from legacy.stub_detector import (  # noqa: F401
    DEFAULT_THRESHOLD,
    EXPECTED_FEATURES,
    MODEL_PATH,
    Autoencoder,
    _FEATURE_NAMES,
    _get_model,
    score_flow,
)
