"""Telemetry (D68): an OpenTelemetry Collector configuration that ships the platform's own captures.

The collector reads files only the platform writes (the product's redacted logs, the gate's and the egress's
records) and exports them over OTLP to the operator's store. It never reads inside the bac and nothing in the bac can
write what it reads. Runs with the `otelcol-contrib` distribution (filelog receiver).
"""
from __future__ import annotations


def collector_config(files: dict, *, endpoint: str) -> dict:
    """files: {name: path}; endpoint: the OTLP/HTTP endpoint of the operator's store."""
    receivers = {f"filelog/{name}": {"include": [path], "start_at": "beginning",
                                     "operators": [{"type": "json_parser"}],
                                     "resource": {"standard.source": name}}
                 for name, path in sorted(files.items())}
    return {"receivers": receivers,
            "processors": {"batch": {}},
            "exporters": {"otlphttp": {"endpoint": endpoint}},
            "service": {"pipelines": {"logs": {"receivers": sorted(receivers), "processors": ["batch"],
                                               "exporters": ["otlphttp"]}}}}
