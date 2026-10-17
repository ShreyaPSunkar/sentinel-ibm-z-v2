
"""Severity classification for Sentinel events."""

METRIC_DEVIATION_THRESHOLD = 1.0
MULTIVARIATE_THRESHOLD = 2


def classify_event(event: dict) -> dict:
    """Add deviated metrics, correlation signal, and severity."""

    result = event.copy()
    metric_scores = result.get("metric_scores", {})

    deviated_metrics = [
        metric
        for metric, score in metric_scores.items()
        if score >= METRIC_DEVIATION_THRESHOLD
    ]

    result["deviated_metrics"] = deviated_metrics

    correlation_detected = (
        len(deviated_metrics) >= MULTIVARIATE_THRESHOLD
    )
    result["correlation_detected"] = correlation_detected

    if not result.get("is_anomaly", False):
        result["severity"] = "LOW"
        return result

    anomaly_score = result.get("anomaly_score", 0)

    failed_logins = result.get("metrics", {}).get(
        "failed_logins", 0
    )

    if (
        anomaly_score >= 3.0
        and correlation_detected
        and failed_logins >= 20
    ):
        severity = "CRITICAL"
    elif correlation_detected:
        severity = "HIGH"
    else:
        severity = "MEDIUM"

    result["severity"] = severity
    return result
