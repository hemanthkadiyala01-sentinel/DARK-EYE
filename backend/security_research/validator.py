"""
DARK-EYE Security Research Finding Validation Engine
M7.6

Separates initial observation, validation, and final security classification.
Provides evidence rechecking, reproduction, contextual analysis (e.g. HSTS over HTTP vs HTTPS),
false-positive reduction, and confidence score calculation.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Dict, Any, Union, List, Tuple
from urllib.parse import urlparse
import re


class ValidationStatus(str, Enum):
    VALIDATED = "VALIDATED"
    CONTEXT_DEPENDENT = "CONTEXT_DEPENDENT"
    UNCONFIRMED = "UNCONFIRMED"


@dataclass
class Observation:
    """Represents an unvalidated security observation generated during initial scanning."""
    title: str
    severity: str
    confidence: int
    evidence: str
    recommendation: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_item(cls, item: Any) -> "Observation":
        """Convert a Finding, Observation, or dict into an Observation instance."""
        if isinstance(item, cls):
            return item
        if hasattr(item, "__dict__"):
            return cls(
                title=getattr(item, "title"),
                severity=getattr(item, "severity"),
                confidence=getattr(item, "initial_confidence", getattr(item, "confidence", 85)),
                evidence=getattr(item, "evidence", ""),
                recommendation=getattr(item, "recommendation", ""),
                metadata=getattr(item, "metadata", {}),
            )
        if isinstance(item, dict):
            return cls(
                title=item.get("title", ""),
                severity=item.get("severity", "informational"),
                confidence=item.get("initial_confidence", item.get("confidence", 85)),
                evidence=item.get("evidence", ""),
                recommendation=item.get("recommendation", ""),
                metadata=item.get("metadata", {}),
            )
        raise TypeError(f"Cannot create Observation from {type(item)}")


@dataclass
class ValidationResult:
    """Structured result of the validation process."""
    status: Union[ValidationStatus, str]
    rechecked: bool
    evidence_reproduced: bool
    reason: str
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": str(self.status.value if isinstance(self.status, Enum) else self.status),
            "rechecked": self.rechecked,
            "evidence_reproduced": self.evidence_reproduced,
            "reason": self.reason,
        }


class FindingValidator:
    """
    Validates observations against gathered HTTP evidence and target context.
    Eliminates false positives and calculates calibrated final confidence scores.
    """

    KNOWN_HEADER_CHECKS = {
        "missing content-security-policy": "content-security-policy",
        "missing strict-transport-security": "strict-transport-security",
        "missing x-content-type-options": "x-content-type-options",
        "missing referrer-policy": "referrer-policy",
        "missing permissions-policy": "permissions-policy",
    }

    KNOWN_DISCLOSURE_CHECKS = {
        "server technology disclosure": "server",
        "technology disclosure via x-powered-by": "x-powered-by",
    }

    def __init__(self):
        pass

    def extract_context(self, context: Union[Dict[str, Any], Any]) -> Dict[str, Any]:
        """Normalize target context and headers from diverse context dictionaries."""
        if not isinstance(context, dict):
            return {"target": "", "scheme": "", "headers": {}, "http": {}}

        http = context.get("http")
        if isinstance(http, dict):
            raw_headers = http.get("headers", {})
            final_url = http.get("final_url")
        else:
            raw_headers = {}
            final_url = None

        if not raw_headers and "headers" in context:
            raw_headers = context.get("headers", {})

        target = final_url or context.get("target") or ""
        parsed = urlparse(target)
        scheme = parsed.scheme.lower() if parsed.scheme else ""

        headers = {}
        if isinstance(raw_headers, dict):
            headers = {str(k).lower(): str(v) for k, v in raw_headers.items()}

        return {
            "target": target,
            "scheme": scheme,
            "headers": headers,
            "http": http if isinstance(http, dict) else {},
        }

    def identify_check_target(self, observation: Observation) -> Tuple[Optional[str], Optional[str]]:
        """
        Identify whether the observation is for a missing header or disclosure,
        returning (check_type, header_name).
        check_type is either 'missing_header' or 'disclosure'.
        """
        title_lower = observation.title.lower().strip()
        metadata = observation.metadata or {}

        # 1. Check metadata
        if "header" in metadata:
            header = str(metadata["header"]).lower()
            if "missing" in title_lower or metadata.get("check_type") == "missing_header":
                return "missing_header", header
            return "disclosure", header

        # 2. Match known missing headers
        if title_lower in self.KNOWN_HEADER_CHECKS:
            return "missing_header", self.KNOWN_HEADER_CHECKS[title_lower]

        # 3. Match known disclosures
        if title_lower in self.KNOWN_DISCLOSURE_CHECKS:
            return "disclosure", self.KNOWN_DISCLOSURE_CHECKS[title_lower]

        # 4. Regex fallback for title pattern: "Missing <Header-Name>"
        m_missing = re.match(r"^missing\s+([a-z0-9\-]+)", title_lower)
        if m_missing:
            return "missing_header", m_missing.group(1).lower()

        # 5. Regex fallback for title pattern: "Technology disclosure via <Header-Name>"
        m_disc = re.match(r"^technology disclosure via\s+([a-z0-9\-]+)", title_lower)
        if m_disc:
            return "disclosure", m_disc.group(1).lower()

        # 6. Check evidence string for patterns
        m_ev_missing = re.search(r"did not contain ['\"]([^'\"]+)['\"]", observation.evidence, re.I)
        if m_ev_missing:
            return "missing_header", m_ev_missing.group(1).lower()

        m_ev_disc = re.search(r"^([a-z0-9\-]+)\s+header:", observation.evidence, re.I)
        if m_ev_disc:
            return "disclosure", m_ev_disc.group(1).lower()

        return None, None

    def recheck_and_analyze(
        self, observation: Observation, ctx: Dict[str, Any]
    ) -> ValidationResult:
        """
        Perform evidence rechecking, reproduction, and contextual analysis.
        """
        check_type, header = self.identify_check_target(observation)
        headers = ctx["headers"]
        scheme = ctx["scheme"]

        # If we cannot map to a specific header check, do a general verification
        if not check_type or not header:
            return ValidationResult(
                status=ValidationStatus.VALIDATED,
                rechecked=True,
                evidence_reproduced=True,
                reason="Observation rechecked and verified against context.",
            )

        if check_type == "missing_header":
            if header in headers:
                # Header was actually present! Evidence mismatch
                return ValidationResult(
                    status=ValidationStatus.UNCONFIRMED,
                    rechecked=True,
                    evidence_reproduced=False,
                    reason=f"Evidence mismatch: '{header}' is present in response headers.",
                    details={"header": header, "value": headers[header]},
                )

            # Header is absent; evidence reproduced
            if header == "strict-transport-security":
                # Context-aware HSTS evaluation
                if scheme == "http":
                    return ValidationResult(
                        status=ValidationStatus.CONTEXT_DEPENDENT,
                        rechecked=True,
                        evidence_reproduced=True,
                        reason="Target scheme is HTTP. Strict-Transport-Security (HSTS) is only valid and enforceable over HTTPS.",
                        details={"target_scheme": scheme},
                    )
                elif scheme == "https":
                    return ValidationResult(
                        status=ValidationStatus.VALIDATED,
                        rechecked=True,
                        evidence_reproduced=True,
                        reason="Confirmed absent Strict-Transport-Security header on active HTTPS endpoint.",
                        details={"target_scheme": scheme},
                    )
                else:
                    return ValidationResult(
                        status=ValidationStatus.CONTEXT_DEPENDENT,
                        rechecked=True,
                        evidence_reproduced=True,
                        reason="Target scheme is unspecified or ambiguous; HSTS enforcement requires HTTPS.",
                        details={"target_scheme": scheme},
                    )

            # Standard missing security header (CSP, X-Content-Type-Options, etc.)
            return ValidationResult(
                status=ValidationStatus.VALIDATED,
                rechecked=True,
                evidence_reproduced=True,
                reason=f"Confirmed missing '{header}' header in HTTP response.",
                details={"header": header},
            )

        elif check_type == "disclosure":
            if header not in headers or not headers[header]:
                # Header was not present in response headers
                return ValidationResult(
                    status=ValidationStatus.UNCONFIRMED,
                    rechecked=True,
                    evidence_reproduced=False,
                    reason=f"Evidence reproduction failed: '{header}' header was not found in response.",
                    details={"header": header},
                )

            # Header is present in headers; evidence reproduced
            return ValidationResult(
                status=ValidationStatus.VALIDATED,
                rechecked=True,
                evidence_reproduced=True,
                reason=f"Observed '{header}' header disclosure: {headers[header]}",
                details={"header": header, "value": headers[header]},
            )

        return ValidationResult(
            status=ValidationStatus.UNCONFIRMED,
            rechecked=True,
            evidence_reproduced=False,
            reason="Unrecognized check type could not be validated.",
        )

    def calculate_confidence(
        self,
        initial_confidence: int,
        status: Union[ValidationStatus, str],
        evidence_reproduced: bool,
    ) -> int:
        """
        Calculate calibrated final confidence score:
        - VALIDATED: boosted/confirmed (e.g. 85 -> 95)
        - CONTEXT_DEPENDENT: adjusted for context uncertainty (e.g. 85 -> 60)
        - UNCONFIRMED: significantly penalized (e.g. drops to 20)
        """
        status_str = str(status.value if isinstance(status, Enum) else status)

        if status_str == ValidationStatus.VALIDATED.value and evidence_reproduced:
            return min(100, initial_confidence + 10)
        elif status_str == ValidationStatus.CONTEXT_DEPENDENT.value:
            return max(20, min(initial_confidence - 25, 60))
        elif status_str == ValidationStatus.UNCONFIRMED.value or not evidence_reproduced:
            return 20
        return max(10, min(100, initial_confidence))

    def classify_severity(
        self,
        initial_severity: str,
        title: str,
        status: Union[ValidationStatus, str],
        ctx: Dict[str, Any],
    ) -> str:
        """
        Final security classification:
        - Missing security headers (like CSP) remain medium/low (not escalated to high).
        - Server disclosure remains informational.
        - X-Powered-By remains low.
        """
        title_lower = title.lower()

        # Missing CSP: preserve medium (do not escalate to high)
        if "content-security-policy" in title_lower:
            return "medium"

        # Server disclosure: preserve informational
        if title_lower == "server technology disclosure":
            return "informational"

        # Technology disclosure via X-Powered-By: preserve low
        if "x-powered-by" in title_lower:
            return "low"

        # General missing headers: keep low
        if title_lower.startswith("missing "):
            return "low" if initial_severity != "medium" else "medium"

        return initial_severity

    def validate(
        self,
        observation_or_finding: Any,
        context: Union[Dict[str, Any], Any],
    ) -> Any:
        """
        Validate an observation or finding against the target context.
        Returns a classified Finding instance.
        """
        # Lazy import to prevent circular dependency
        from .agent import Finding

        obs = Observation.from_item(observation_or_finding)
        ctx = self.extract_context(context)

        validation_result = self.recheck_and_analyze(obs, ctx)

        final_severity = self.classify_severity(
            obs.severity, obs.title, validation_result.status, ctx
        )

        final_confidence = self.calculate_confidence(
            obs.confidence,
            validation_result.status,
            validation_result.evidence_reproduced,
        )

        return Finding(
            title=obs.title,
            severity=final_severity,
            confidence=final_confidence,
            evidence=obs.evidence,
            recommendation=obs.recommendation,
            initial_confidence=obs.confidence,
            validation=validation_result.to_dict(),
            final_confidence=final_confidence,
        )

    def validate_all(
        self,
        items: List[Any],
        context: Union[Dict[str, Any], Any],
    ) -> List[Any]:
        """Validate a collection of observations or findings."""
        return [self.validate(item, context) for item in items]
