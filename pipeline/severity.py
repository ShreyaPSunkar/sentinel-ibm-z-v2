
"""Severity classification for Sentinel events."""

MULTIVARIATE_THRESHOLD = 2


def classify_event(event: dict) -> dict:
    """Add deviated metrics, correlation signal, and severity."""

    result = event.copy()

    # Use the detector's flagged metrics for consistent classification.
    deviated_metrics = result.get("flagged_metrics", [])
    result["deviated_metrics"] = list(deviated_metrics)

    correlation_detected = (
        len(deviated_metrics) >= MULTIVARIATE_THRESHOLD
    )
    result["correlation_detected"] = correlation_detected

    if not result.get("is_anomaly", False):
        result["severity"] = "LOW"
        return result

    anomaly_score = result.get("anomaly_score", 0)
    failed_logins = result.get("metrics", {}).get("failed_logins", 0)

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
