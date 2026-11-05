"""
DARK-EYE Security Research Agent
M7.5 MVP

Scope-controlled passive security research for authorized targets.
"""

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any, List
from urllib.parse import urlparse
import json
import re
import ssl
import urllib.request

from .validator import FindingValidator, Observation, ValidationResult, ValidationStatus


@dataclass
class Finding:
    title: str
    severity: str
    confidence: int
    evidence: str
    recommendation: str
    initial_confidence: Optional[int] = None
    validation: Optional[Dict[str, Any]] = None
    final_confidence: Optional[int] = None

    def __post_init__(self):
        if self.initial_confidence is None:
            self.initial_confidence = self.confidence
        if self.final_confidence is None:
            self.final_confidence = self.confidence
        if hasattr(self.validation, "to_dict"):
            self.validation = self.validation.to_dict()
        self.confidence = self.final_confidence


class ScopeManager:
    def __init__(self, allowed_domains=None):
        self.allowed_domains = {
            d.lower().strip().lstrip("*.")
            for d in (allowed_domains or [])
        }

    def is_allowed(self, url):
        parsed = urlparse(url)

        if parsed.scheme not in ("http", "https"):
            return False

        hostname = (parsed.hostname or "").lower()

        if not hostname:
            return False

        for domain in self.allowed_domains:
            if hostname == domain or hostname.endswith("." + domain):
                return True

        return False


class SecurityResearchAgent:
    def __init__(self, target, allowed_domains, validator=None):
        self.target = target.rstrip("/")
        self.scope = ScopeManager(allowed_domains)
        self.findings: List[Finding] = []
        self.observations: List[Observation] = []
        self.validator = validator or FindingValidator()
        self.evidence = {
            "target": self.target,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "scope_verified": False,
            "http": {},
        }

    def verify_scope(self):
        allowed = self.scope.is_allowed(self.target)
        self.evidence["scope_verified"] = allowed

        if not allowed:
            raise PermissionError(
                f"TARGET OUT OF SCOPE: {self.target}"
            )

        return True

    def fetch(self):
        if not self.scope.is_allowed(self.target):
            raise PermissionError("Blocked by scope policy.")

        request = urllib.request.Request(
            self.target,
            headers={
                "User-Agent": "DARK-EYE-SecurityResearch/0.1"
            },
        )

        context = ssl.create_default_context()

        with urllib.request.urlopen(
            request,
            timeout=10,
            context=context
        ) as response:

            body = response.read(200000)

            headers = {
                k.lower(): v
                for k, v in response.headers.items()
            }

            self.evidence["http"] = {
                "status": response.status,
                "final_url": response.geturl(),
                "headers": headers,
                "content_length_sample": len(body),
            }

            return response, body

    def analyze_headers(self, headers):
        checks = {
            "content-security-policy": (
                "Missing Content-Security-Policy",
                "medium",
                "Consider implementing an appropriate Content-Security-Policy."
            ),
            "strict-transport-security": (
                "Missing Strict-Transport-Security",
                "low",
                "Enable HSTS when HTTPS is intended to be enforced."
            ),
            "x-content-type-options": (
                "Missing X-Content-Type-Options",
                "low",
                "Consider setting X-Content-Type-Options: nosniff."
            ),
            "referrer-policy": (
                "Missing Referrer-Policy",
                "low",
                "Consider setting an appropriate Referrer-Policy."
            ),
            "permissions-policy": (
                "Missing Permissions-Policy",
                "low",
                "Consider restricting unnecessary browser capabilities."
            ),
        }

        for header, (title, severity, recommendation) in checks.items():
            if header not in headers:
                obs = Observation(
                    title=title,
                    severity=severity,
                    confidence=85,
                    evidence=f"Response did not contain '{header}'.",
                    recommendation=recommendation,
                    metadata={"header": header, "check_type": "missing_header"},
                )
                self.observations.append(obs)
                self.findings.append(
                    Finding(
                        title=title,
                        severity=severity,
                        confidence=85,
                        evidence=f"Response did not contain '{header}'.",
                        recommendation=recommendation,
                    )
                )

    def analyze_server_disclosure(self, headers):
        server = headers.get("server")

        if server:
            obs = Observation(
                title="Server technology disclosure",
                severity="informational",
                confidence=90,
                evidence=f"Server header: {server}",
                recommendation=(
                    "Consider minimizing unnecessary server/version disclosure."
                ),
                metadata={"header": "server", "check_type": "disclosure"},
            )
            self.observations.append(obs)
            self.findings.append(
                Finding(
                    title=obs.title,
                    severity=obs.severity,
                    confidence=obs.confidence,
                    evidence=obs.evidence,
                    recommendation=obs.recommendation,
                )
            )

        powered = headers.get("x-powered-by")

        if powered:
            obs = Observation(
                title="Technology disclosure via X-Powered-By",
                severity="low",
                confidence=95,
                evidence=f"X-Powered-By: {powered}",
                recommendation=(
                    "Remove unnecessary framework/runtime disclosure."
                ),
                metadata={"header": "x-powered-by", "check_type": "disclosure"},
            )
            self.observations.append(obs)
            self.findings.append(
                Finding(
                    title=obs.title,
                    severity=obs.severity,
                    confidence=obs.confidence,
                    evidence=obs.evidence,
                    recommendation=obs.recommendation,
                )
            )

    def analyze_html(self, body):
        text = body.decode("utf-8", errors="ignore")

        forms = len(re.findall(r"<form\b", text, re.I))
        scripts = len(re.findall(r"<script\b", text, re.I))
        links = len(re.findall(r"<a\b", text, re.I))

        self.evidence["html_analysis"] = {
            "forms": forms,
            "scripts": scripts,
            "links": links,
        }

        interesting_paths = sorted(
            set(
                re.findall(
                    r"""(?:href|src|action)=["']([^"'#]+)["']""",
                    text,
                    re.I,
                )
            )
        )

        self.evidence["interesting_paths"] = interesting_paths[:100]

    def deduplicate(self):
        seen_obs = set()
        unique_obs = []
        for obs in self.observations:
            key = obs.title.lower()
            if key not in seen_obs:
                seen_obs.add(key)
                unique_obs.append(obs)
        self.observations = unique_obs

        seen_find = set()
        unique_find = []
        for finding in self.findings:
            key = finding.title.lower()
            if key not in seen_find:
                seen_find.add(key)
                unique_find.append(finding)
        self.findings = unique_find

    def validate_findings(self):
        context = {
            "target": self.target,
            **self.evidence,
        }
        items_to_validate = self.observations if self.observations else self.findings
        self.findings = self.validator.validate_all(items_to_validate, context)
        return self.findings

    def run(self):
        self.verify_scope()

        response, body = self.fetch()

        headers = self.evidence["http"]["headers"]

        self.analyze_headers(headers)
        self.analyze_server_disclosure(headers)
        self.analyze_html(body)

        self.deduplicate()
        self.validate_findings()

        return {
            "evidence": self.evidence,
            "findings": [asdict(f) for f in self.findings],
        }


def save_report(result, output_dir="security_reports"):
    Path(output_dir).mkdir(exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    json_path = Path(output_dir) / f"dark_eye_{timestamp}.json"
    md_path = Path(output_dir) / f"dark_eye_{timestamp}.md"

    json_path.write_text(
        json.dumps(result, indent=2),
        encoding="utf-8",
    )

    lines = [
        "# DARK-EYE Security Research Report",
        "",
        f"Target: `{result['evidence']['target']}`",
        "",
        f"Scope verified: `{result['evidence']['scope_verified']}`",
        "",
        "## Findings",
        "",
    ]

    findings = result["findings"]

    if not findings:
        lines.append("No findings generated by the current passive checks.")

    for i, finding in enumerate(findings, 1):
        lines.extend([
            f"### {i}. {finding['title']}",
            "",
            f"- Severity: **{finding['severity']}**",
            f"- Confidence: **{finding['confidence']}%**",
        ])
        if finding.get("validation"):
            v = finding["validation"]
            lines.append(f"- Validation Status: **{v.get('status')}** (Reproduced: {v.get('evidence_reproduced')})")
            if v.get("reason"):
                lines.append(f"- Validation Reason: {v.get('reason')}")
        lines.extend([
            f"- Evidence: {finding['evidence']}",
            f"- Recommendation: {finding['recommendation']}",
            "",
        ])

    md_path.write_text("\n".join(lines), encoding="utf-8")

    return json_path, md_path

