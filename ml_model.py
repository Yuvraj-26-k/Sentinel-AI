"""Local Isolation Forest scoring for network behavior windows."""

from sklearn.ensemble import IsolationForest
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

FEATURE_NAMES = (
    "events",
    "unique_ports",
    "ports_per_second",
    "unique_destinations",
    "destinations_per_second",
    "mean_interarrival_seconds",
    "interarrival_std_seconds",
    "active_span_seconds",
)
MINIMUM_TRAINING_SAMPLES = 30
MAXIMUM_TRAINING_SAMPLES = 512
ANOMALY_THRESHOLD = 0.0


def window_features(window, duration_seconds=60):
    """Build stable numeric features from (time, port, destination) events."""
    if not window:
        return {name: 0.0 for name in FEATURE_NAMES}
    timestamps = [item[0] for item in window]
    ports = {item[1] for item in window}
    destinations = {item[2] for item in window}
    span = max(timestamps[-1] - timestamps[0], 0.0)
    elapsed = max(min(duration_seconds, span), 1.0)
    intervals = [
        max(timestamps[index] - timestamps[index - 1], 0.0)
        for index in range(1, len(timestamps))
    ]
    mean_interval = sum(intervals) / len(intervals) if intervals else 0.0
    variance = (
        sum((value - mean_interval) ** 2 for value in intervals) / len(intervals)
        if intervals
        else 0.0
    )
    return {
        "events": float(len(window)),
        "unique_ports": float(len(ports)),
        "ports_per_second": len(ports) / elapsed,
        "unique_destinations": float(len(destinations)),
        "destinations_per_second": len(destinations) / elapsed,
        "mean_interarrival_seconds": mean_interval,
        "interarrival_std_seconds": variance**0.5,
        "active_span_seconds": span,
    }


class IsolationForestScorer:
    def __init__(self, sample_store, minimum_samples=MINIMUM_TRAINING_SAMPLES):
        self.sample_store = sample_store
        self.minimum_samples = minimum_samples
        self._models = {}

    def invalidate(self, source):
        self._models.pop(source, None)

    def score(self, source, features):
        rows = self.sample_store.get(source, [])
        if len(rows) < self.minimum_samples:
            return None
        model = self._models.get(source)
        if model is None or model[0] != len(rows):
            estimator = make_pipeline(
                StandardScaler(),
                IsolationForest(
                    n_estimators=100,
                    contamination="auto",
                    random_state=42,
                    n_jobs=1,
                ),
            )
            estimator.fit(rows)
            model = (len(rows), estimator)
            self._models[source] = model
        vector = [features[name] for name in FEATURE_NAMES]
        decision = float(model[1].decision_function([vector])[0])
        return {
            "score": round(max(0.0, -decision), 6),
            "decision_function": round(decision, 6),
            "is_anomaly": decision < ANOMALY_THRESHOLD,
            "training_samples": len(rows),
            "model": "isolation_forest",
        }
