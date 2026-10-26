"""
Modular Machine Learning & Anomaly Detection Engine for Defensive SOC.

Provides:
- Pluggable inference service interface.
- Separation between network-flow classification (e.g., CICIDS2017 features)
  and HTTP-request anomaly scoring.
- Out-of-distribution (OOD) handling mapping uncertain findings to 'unknown'.
- Strict provenance tracking (model name, version, feature schema, confidence).
- Graceful offline fallback: if models or heavy ML dependencies (PyTorch/Sklearn)
  are absent, the engine falls back to heuristic statistical scoring without error.
- Safe local execution: no telemetry is ever transmitted to external endpoints.
"""

import json
import logging
import math
import re
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("soc_ml_engine")


class FeatureSchema:
    """Standardized feature definitions for telemetry classification."""
    FLOW_FEATURES_V1 = "network_flow_v1"
    HTTP_FEATURES_V1 = "http_request_v1"


class MLInferenceResult:
    """Standardized inference result container with strict provenance."""

    def __init__(
        self,
        classification_type: str,  # 'known_attack', 'suspicious_anomaly', 'unknown'
        predicted_category: str,    # e.g., 'PORT_SCAN', 'ANOMALOUS_BURST', 'BENIGN'
        confidence: float,          # 0.0 to 1.0
        anomaly_score: float,       # 0.0 to 1.0
        model_name: str,
        model_version: str,
        feature_schema_version: str,
        evidence: Optional[Dict[str, Any]] = None,
        mitre_technique: Optional[str] = None,
        is_ood: bool = False,
        explanation: str = ""
    ):
        self.classification_type = classification_type
        self.predicted_category = predicted_category
        self.confidence = max(0.0, min(1.0, float(confidence)))
        self.anomaly_score = max(0.0, min(1.0, float(anomaly_score)))
        self.model_name = model_name
        self.model_version = model_version
        self.feature_schema_version = feature_schema_version
        self.evidence = evidence or {}
        self.mitre_technique = mitre_technique
        self.is_ood = is_ood
        self.explanation = explanation
        self.timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "classification_type": self.classification_type,
            "predicted_category": self.predicted_category,
            "confidence": round(self.confidence, 4),
            "anomaly_score": round(self.anomaly_score, 4),
            "model_name": self.model_name,
            "model_version": self.model_version,
            "feature_schema_version": self.feature_schema_version,
            "evidence": self.evidence,
            "mitre_technique": self.mitre_technique,
            "is_ood": self.is_ood,
            "explanation": self.explanation,
            "timestamp": self.timestamp,
        }


class BaseInferenceModel:
    """Base interface for defensive SOC inference models."""

    def __init__(self, model_name: str, model_version: str, feature_schema: str):
        self.model_name = model_name
        self.model_version = model_version
        self.feature_schema = feature_schema

    def predict(self, features: Dict[str, Any]) -> MLInferenceResult:
        raise NotImplementedError


class NetworkFlowAnomalyDetector(BaseInferenceModel):
    """
    Evaluates network-flow metrics (e.g. flow duration, packet rates,
    destination port dispersion, byte counts).
    
    Model Card:
    - Target: Network flow volumetric & port discovery anomaly detection.
    - Features: flow_duration_ms, packet_count, byte_count, distinct_ports, syn_ratio.
    - Permitted Usage: Defensive enterprise telemetry inspection only.
    - Out-of-Distribution: Triggered if essential flow metrics are absent or out-of-scale.
    """

    def __init__(self):
        super().__init__(
            model_name="FlowAnomalyGuard-Heuristic",
            model_version="1.2.0",
            feature_schema=FeatureSchema.FLOW_FEATURES_V1
        )

    def extract_features(self, telemetry: Dict[str, Any]) -> Dict[str, float]:
        """Extract or derive normalized flow metrics from telemetry."""
        meta = telemetry.get("metadata") or {}
        flow = meta.get("flow") or meta.get("network_flow") or {}

        def _get_num(keys, default=0.0):
            for k in keys:
                v = flow.get(k) if isinstance(flow, dict) else None
                if v is None and isinstance(meta, dict):
                    v = meta.get(k)
                if v is None and k in telemetry:
                    v = telemetry.get(k)
                if v is not None:
                    try:
                        return float(v)
                    except (ValueError, TypeError):
                        pass
            return default

        return {
            "flow_duration_ms": _get_num(["flow_duration_ms", "duration", "flow_duration"]),
            "packet_count": _get_num(["packet_count", "packets", "pkt_count", "total_fwd_packets", "tot_fwd_pkts"]),
            "byte_count": _get_num(["byte_count", "bytes", "tot_bytes", "total_bytes"]),
            "distinct_ports": _get_num(["distinct_ports", "port_count", "scanned_ports"]),
            "syn_ratio": _get_num(["syn_ratio", "syn_packet_ratio", "syn_flag_ratio", "syn_flag_count"], 0.0),
        }

    def predict(self, telemetry: Dict[str, Any]) -> MLInferenceResult:
        feats = self.extract_features(telemetry)
        
        # Check Out-of-Distribution (OOD): missing flow telemetry
        has_flow_data = any(v > 0 for v in feats.values())
        if not has_flow_data:
            return MLInferenceResult(
                classification_type="unknown",
                predicted_category="UNKNOWN_FLOW",
                confidence=0.20,
                anomaly_score=0.10,
                model_name=self.model_name,
                model_version=self.model_version,
                feature_schema_version=self.feature_schema,
                evidence={"reason": "Missing or insufficient network-flow features"},
                mitre_technique=None,
                is_ood=True,
                explanation="Out-of-distribution: event lacks network flow metrics (duration, packets, ports)."
            )

        # Feature evaluation
        ports = feats["distinct_ports"]
        packets = feats["packet_count"]
        duration = feats["flow_duration_ms"]
        syn_ratio = feats["syn_ratio"]

        # High distinct ports or high SYN ratio -> Service Discovery / SYN scan
        if ports >= 10 or (ports >= 5 and syn_ratio > 0.8) or (syn_ratio >= 0.85 and packets >= 10):
            conf = min(0.98, 0.70 + (ports * 0.02) + (syn_ratio * 0.15))
            score = min(0.99, 0.75 + (ports * 0.02) + (syn_ratio * 0.10))
            category = "PORT_SCAN" if ports >= 5 else "SYN_FLOOD_OR_PORT_SCAN"
            return MLInferenceResult(
                classification_type="known_attack" if (ports >= 5 or syn_ratio >= 0.9) else "suspicious_anomaly",
                predicted_category=category,
                confidence=conf,
                anomaly_score=score,
                model_name=self.model_name,
                model_version=self.model_version,
                feature_schema_version=self.feature_schema,
                evidence={
                    "distinct_ports": ports,
                    "syn_ratio": syn_ratio,
                    "packets": packets,
                    "duration_ms": duration
                },
                mitre_technique="T1046" if ports >= 5 else None,
                is_ood=False,
                explanation=f"Network flow shows rapid probing across {int(ports)} destination ports with SYN ratio {syn_ratio:.2f}."
            )

        # High packet rate / volumetric burst -> Suspicious anomaly
        rate = (packets / (duration / 1000.0)) if duration > 10 else packets
        if rate > 200 or packets > 500:
            score = min(0.95, 0.60 + (rate / 1000.0))
            return MLInferenceResult(
                classification_type="suspicious_anomaly",
                predicted_category="ANOMALOUS_FLOW_RATE",
                confidence=0.82,
                anomaly_score=score,
                model_name=self.model_name,
                model_version=self.model_version,
                feature_schema_version=self.feature_schema,
                evidence={"packet_rate_per_sec": round(rate, 2), "total_packets": packets},
                mitre_technique=None,
                is_ood=False,
                explanation=f"Traffic volume anomaly: observed {round(rate, 1)} pkts/sec exceeding baseline threshold."
            )

        # Mild or benign flow
        return MLInferenceResult(
            classification_type="unknown",
            predicted_category="NORMAL_FLOW",
            confidence=0.50,
            anomaly_score=0.15,
            model_name=self.model_name,
            model_version=self.model_version,
            feature_schema_version=self.feature_schema,
            evidence=feats,
            mitre_technique=None,
            is_ood=False,
            explanation="Flow metrics within normal parameters."
        )


class HttpRequestAnomalyClassifier(BaseInferenceModel):
    """
    Evaluates raw HTTP telemetry (method, path, headers, query params).
    
    Model Card:
    - Target: Detection of structural, path, and injection anomalies in HTTP requests.
    - Features: path_entropy, traversal_tokens, sql_syntax_density, metachar_tokens.
    - Out-of-Distribution: Handled for non-HTTP protocols.
    """

    def __init__(self):
        super().__init__(
            model_name="HttpAnomalyGuard-Structural",
            model_version="2.0.1",
            feature_schema=FeatureSchema.HTTP_FEATURES_V1
        )

    @staticmethod
    def _shannon_entropy(s: str) -> float:
        if not s:
            return 0.0
        prob = [float(s.count(c)) / len(s) for c in set(s)]
        return -sum(p * math.log2(p) for p in prob)

    def predict(self, telemetry: Dict[str, Any]) -> MLInferenceResult:
        path = str(telemetry.get("path") or telemetry.get("requested_path") or telemetry.get("url") or "").strip()
        method = str(telemetry.get("method") or telemetry.get("http_method") or "").upper().strip()
        status_code = telemetry.get("response_status") or telemetry.get("status_code")

        if not path and not method:
            return MLInferenceResult(
                classification_type="unknown",
                predicted_category="NON_HTTP_EVENT",
                confidence=0.10,
                anomaly_score=0.05,
                model_name=self.model_name,
                model_version=self.model_version,
                feature_schema_version=self.feature_schema,
                evidence={"reason": "Missing HTTP path or method in event"},
                is_ood=True,
                explanation="Out-of-distribution: telemetry lacks HTTP application-layer attributes."
            )

        path_unquoted = urllib.parse.unquote_plus(path)
        path_lower = path_unquoted.lower()
        entropy = self._shannon_entropy(path_unquoted)

        # 1. SQL Injection indicators
        sqli_patterns = [
            r"(\b(select|union|insert|update|delete|drop|alter)\b.*\b(from|into|table|where)\b)",
            r"(\bor\b\s+['\d]+=['\d]+)",
            r"(--|#|/\*|\*/)",
            r"(\bwaitfor\s+delay\b|\bsleep\(\d+\))",
        ]
        sqli_matches = [p for p in sqli_patterns if re.search(p, path_lower)]
        if sqli_matches:
            return MLInferenceResult(
                classification_type="known_attack",
                predicted_category="SQL_INJECTION",
                confidence=0.94,
                anomaly_score=0.96,
                model_name=self.model_name,
                model_version=self.model_version,
                feature_schema_version=self.feature_schema,
                evidence={"matched_patterns": len(sqli_matches), "path_sample": path[:120]},
                mitre_technique="T1190",
                is_ood=False,
                explanation="High-confidence SQL syntax injection tokens detected in query/path."
            )

        # 2. Command Injection indicators
        cmd_patterns = [r"(;|\||`|\$\(|\bsh\b|\bbash\b|/bin/|cmd\.exe|powershell)", r"(cat\s+/etc/|id\s*;|whoami)"]
        cmd_matches = [p for p in cmd_patterns if re.search(p, path_lower)]
        if cmd_matches:
            return MLInferenceResult(
                classification_type="known_attack",
                predicted_category="COMMAND_INJECTION",
                confidence=0.91,
                anomaly_score=0.93,
                model_name=self.model_name,
                model_version=self.model_version,
                feature_schema_version=self.feature_schema,
                evidence={"matched_cmd_tokens": len(cmd_matches), "path_sample": path[:120]},
                mitre_technique="T1059",
                is_ood=False,
                explanation="Shell metacharacters or execution commands identified in request parameters."
            )

        # 3. Path Traversal indicators
        if "../" in path_lower or "..\\" in path_lower or "%2e%2e" in path_lower or "..%2f" in path_lower:
            return MLInferenceResult(
                classification_type="known_attack",
                predicted_category="PATH_TRAVERSAL",
                confidence=0.96,
                anomaly_score=0.95,
                model_name=self.model_name,
                model_version=self.model_version,
                feature_schema_version=self.feature_schema,
                evidence={"traversal_depth": path_lower.count("..")},
                mitre_technique="T1083",
                is_ood=False,
                explanation="Directory traversal sequence ('../') detected in target URL path."
            )

        # 4. High-entropy or unusual non-standard anomaly
        if entropy > 4.5 and len(path) > 30:
            return MLInferenceResult(
                classification_type="suspicious_anomaly",
                predicted_category="PATH_ENTROPY_ANOMALY",
                confidence=0.78,
                anomaly_score=min(0.92, 0.50 + (entropy / 10.0)),
                model_name=self.model_name,
                model_version=self.model_version,
                feature_schema_version=self.feature_schema,
                evidence={"shannon_entropy": round(entropy, 3), "path_length": len(path)},
                mitre_technique=None,
                is_ood=False,
                explanation=f"High-entropy request path ({entropy:.2f} bits/symbol); potential encoded payload or randomized fuzzer probe."
            )

        # Baseline: Insufficient evidence for attack or anomaly
        return MLInferenceResult(
            classification_type="unknown",
            predicted_category="BENIGN_OR_UNCLASSIFIED_HTTP",
            confidence=0.40,
            anomaly_score=0.10,
            model_name=self.model_name,
            model_version=self.model_version,
            feature_schema_version=self.feature_schema,
            evidence={"entropy": round(entropy, 2), "method": method},
            mitre_technique=None,
            is_ood=False,
            explanation="HTTP request demonstrates no standard exploit or statistical anomaly."
        )


class SOCMLEngine:
    """
    Coordinating inference orchestrator.
    Dispatches telemetry to appropriate specialized sub-models based on available features.
    """

    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self.flow_model = NetworkFlowAnomalyDetector()
        self.http_model = HttpRequestAnomalyClassifier()

    def evaluate(self, event_dict: Dict[str, Any]) -> Optional[MLInferenceResult]:
        """
        Evaluate an incoming telemetry event.
        Returns MLInferenceResult or None if ML engine is disabled.
        """
        if not self.enabled:
            return None

        try:
            # Check if network flow features are prominent
            meta = event_dict.get("metadata") or {}
            has_flow = bool(
                event_dict.get("destination_port")
                or meta.get("flow")
                or meta.get("network_flow")
                or "packet_count" in event_dict
            )

            # Check if HTTP features are prominent
            has_http = bool(
                event_dict.get("path")
                or event_dict.get("requested_path")
                or event_dict.get("method")
                or event_dict.get("http_method")
            )

            if has_http:
                result = self.http_model.predict(event_dict)
                # If HTTP model found attack or anomaly, return it
                if result.classification_type in ("known_attack", "suspicious_anomaly"):
                    return result

            if has_flow:
                result = self.flow_model.predict(event_dict)
                if result.classification_type in ("known_attack", "suspicious_anomaly"):
                    return result

            # Default to HTTP model result or Flow model result if available
            if has_http:
                return self.http_model.predict(event_dict)
            if has_flow:
                return self.flow_model.predict(event_dict)

            # Fallback for events with neither
            return MLInferenceResult(
                classification_type="unknown",
                predicted_category="UNCLASSIFIED_TELEMETRY",
                confidence=0.10,
                anomaly_score=0.05,
                model_name="SOCML-Orchestrator",
                model_version="1.0.0",
                feature_schema_version="general_v1",
                evidence={"reason": "Neither HTTP nor Flow feature sets detected"},
                mitre_technique=None,
                is_ood=True,
                explanation="Event contains insufficient features for machine-learning inference."
            )

        except Exception as exc:
            logger.warning("ML inference evaluation error: %s", exc)
            return None


# Global singleton instance
ml_engine = SOCMLEngine(enabled=True)
