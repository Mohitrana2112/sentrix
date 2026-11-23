"""
SENTRIX Risk Engine v2.5
Evidence-based cybersecurity risk calculation engine.
Computes granular risk scores (0–100), severity classifications (LOW, MEDIUM, HIGH, CRITICAL),
confidence levels (HIGH, MEDIUM, LOW), and actionable remediation guidance.
"""

from typing import List, Dict, Any, Optional


class RiskIndicator:
    """
    Represents an atomic technical heuristic security finding.
    """
    def __init__(
        self,
        name: str,
        severity: str,
        score_impact: int,
        evidence: str,
        technical_explanation: str,
        precaution: str,
        confidence: str = "HIGH",
        category: str = "Syntax & Transport"
    ):
        self.name = name
        self.severity = severity.upper()  # INFO, LOW, MEDIUM, HIGH, CRITICAL
        self.score_impact = max(0, score_impact)
        self.evidence = evidence
        self.technical_explanation = technical_explanation
        self.precaution = precaution
        self.confidence = confidence.upper()  # HIGH, MEDIUM, LOW
        self.category = category

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "severity": self.severity,
            "score_impact": self.score_impact,
            "evidence": self.evidence,
            "technical_explanation": self.technical_explanation,
            "precaution": self.precaution,
            "confidence": self.confidence,
            "category": self.category,
        }


class RiskEvaluation:
    """
    Aggregates atomic indicators, applies confidence weights, prevents duplicate impacts,
    and produces an evidence-based risk assessment.
    """
    def __init__(self, indicators: List[RiskIndicator]):
        # Deduplicate indicators by name
        seen = set()
        unique_indicators = []
        for ind in indicators:
            if ind.name not in seen:
                seen.add(ind.name)
                unique_indicators.append(ind)

        self.indicators = unique_indicators
        self.score = self._compute_score()
        self.classification = self._get_classification()
        self.confidence = self._compute_confidence()
        self.summary = self._generate_summary()

    def _compute_score(self) -> int:
        """
        Computes final risk score (0–100).
        A clean target with zero findings receives exactly 0 pts (clean baseline).
        """
        if not self.indicators:
            return 0

        # Sum weighted scores
        total_impact = 0
        for ind in self.indicators:
            # Apply confidence multiplier
            conf_mult = 1.0
            if ind.confidence == "MEDIUM":
                conf_mult = 0.85
            elif ind.confidence == "LOW":
                conf_mult = 0.65

            total_impact += ind.score_impact * conf_mult

        # Clamp between 0 and 100
        final_score = int(round(min(100, max(0, total_impact))))
        return final_score

    def _get_classification(self) -> str:
        """
        Strict classification tiers:
        0–24: LOW
        25–49: MEDIUM
        50–74: HIGH
        75–100: CRITICAL
        """
        if self.score >= 75:
            return "CRITICAL"
        elif self.score >= 50:
            return "HIGH"
        elif self.score >= 25:
            return "MEDIUM"
        else:
            return "LOW"

    def _compute_confidence(self) -> str:
        """
        Determines overall analytical confidence:
        HIGH: Strong structural signals (punycode, userinfo, confirmed brand distance, raw IP)
        MEDIUM: Moderate heuristic findings (shorteners, length, query keywords)
        LOW: Pure baseline or inconclusive signals
        """
        if not self.indicators:
            return "HIGH"  # High confidence that baseline is clean

        has_high_conf_indicator = any(ind.confidence == "HIGH" for ind in self.indicators)
        has_critical = any(ind.severity == "CRITICAL" for ind in self.indicators)

        if has_critical or has_high_conf_indicator:
            return "HIGH"
        elif len(self.indicators) >= 2:
            return "MEDIUM"
        else:
            return "MEDIUM"

    def _generate_summary(self) -> str:
        count = len(self.indicators)
        if count == 0:
            return (
                "Clean security baseline: No syntactical anomalies, typosquatting patterns, "
                "or deceptive heuristics detected. Valid transport and standard hierarchy observed."
            )

        if self.classification == "CRITICAL":
            return (
                f"Severe threat alert: {count} indicator(s) identified including critical patterns "
                f"such as brand impersonation, deceptive credentials (@), or raw IP hosting. "
                f"Immediate defensive blocking recommended."
            )
        elif self.classification == "HIGH":
            return (
                f"Elevated risk alert: {count} suspicious heuristic indicator(s) identified. "
                f"Substantial likelihood of obfuscation, phishing redirection, or credential harvest attempts."
            )
        elif self.classification == "MEDIUM":
            return (
                f"Moderate caution required: {count} indicator(s) identified such as unencrypted transport, "
                f"URL shortener masking, or sensitive query tokens. Verify domain ownership."
            )
        else:
            return (
                f"Low heuristic risk detected ({count} indicator(s)). Minor deviation from best-practice baseline; "
                f"no structural malice or brand spoofing observed."
            )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": self.score,
            "classification": self.classification,
            "confidence": self.confidence,
            "summary": self.summary,
            "indicator_count": len(self.indicators),
            "indicators": [ind.to_dict() for ind in self.indicators],
            "disclaimer": (
                "SENTRIX Heuristic Disclaimer: This assessment represents static, structural, "
                "and DNS/transport intelligence. It is not an active sandbox detonation verdict. "
                "Absence of detected anomalies does not guarantee complete absence of operational risk."
            )
        }
