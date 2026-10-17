
"""Orchestrate anomaly detection and severity classification."""

import json
from pathlib import Path

from pipeline.severity import classify_event
from src.anomaly_detection import RobustAnomalyDetector


def create_detector(training_events):
    """Fit the detector using normal training events."""
    detector = RobustAnomalyDetector()
    detector.fit(training_events)
    return detector


def process_event(event, detector):
    """Detect anomalies and classify an event's severity."""
    prediction = detector.predict_one(event)

    result = event.copy()
    result.update(prediction)

    # Preserve the original metrics dictionary.
    result["metrics"] = event.get("metrics", {})

    return classify_event(result)


def process_events(events, detector):
    """Process a collection of events."""
    return [process_event(event, detector) for event in events]


def process_stream(events, detector):
    """Process events one at a time."""
    for event in events:
        yield process_event(event, detector)


def replay_jsonl_stream(file_path, detector):
    """Read and process events from a JSONL file."""
    with Path(file_path).open("r", encoding="utf-8") as file:
        for line in file:
            if line.strip():
                yield process_event(json.loads(line), detector)
