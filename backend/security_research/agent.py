"""
DARK-EYE Security Research Agent
M7.7

Scope-controlled, explicitly authorized passive security research for approved targets.
Features:
- Program and scope metadata with path boundary support
- Explicit authorization lifecycle and verification gate (AUTHORIZED, UNAUTHORIZED, EXPIRED, REVOKED)
- Passive endpoint inventory with normalization, scope classification, and deduplication
- Cryptographic evidence bundling with SHA-256 payload integrity
- Security audit trail recording all critical decision milestones
"""

from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional, Dict, Any, List, Union, Tuple, Set
from urllib.parse import urlparse, urljoin, urlsplit, urlunsplit
import hashlib
import json
import re
import ssl
import urllib.request

from .validator import FindingValidator, Observation, ValidationResult, ValidationStatus


# ==============================================================================
# Authorization Models
# ==============================================================================

class AuthorizationStatus(str, Enum):
    AUTHORIZED = "AUTHORIZED"
    UNAUTHORIZED = "UNAUTHORIZED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


@dataclass
class PermissionGrant:
    """Explicit authorization record authorizing security research."""
    status: Union[AuthorizationStatus, str] = AuthorizationStatus.UNAUTHORIZED
    authorized_by: str = ""
    scope_reference: str = ""
    valid_until: Optional[str] = None  # ISO timestamp (e.g. 2026-12-31T23:59:59Z)
    allow_passive: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)

    def is_valid(self) -> bool:
        stat = self.status.value if isinstance(self.status, Enum) else str(self.status)
        if stat != AuthorizationStatus.AUTHORIZED.value:
            return False
        if not self.allow_passive:
            return False
        if self.valid_until:
            try:
                until_dt = datetime.fromisoformat(self.valid_until)
                if until_dt.tzinfo is None:
                    until_dt = until_dt.replace(tzinfo=timezone.utc)
                now_dt = datetime.now(timezone.utc)
                if now_dt > until_dt:
                    return False
            except Exception:
                pass
        return True

    def to_dict(self) -> Dict[str, Any]:
        stat = self.status.value if isinstance(self.status, Enum) else str(self.status)
        return {
            "status": stat,
            "authorized_by": self.authorized_by,
            "scope_reference": self.scope_reference,
            "valid_until": self.valid_until,
            "allow_passive": self.allow_passive,
            "is_valid": self.is_valid(),
            "metadata": dict(self.metadata),
        }


# ==============================================================================
# Program & Scope Models
# ==============================================================================

@dataclass
class ProgramMetadata:
    """Program identity, guidelines reference, and scope boundaries."""
    program_id: str = "default-engagement"
    name: str = "Authorized Research Engagement"
    allowed_domains: List[str] = field(default_factory=list)
    excluded_paths: List[str] = field(default_factory=list)
    policy_url: Optional[str] = None
    contact: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "program_id": self.program_id,
            "name": self.name,
            "allowed_domains": list(self.allowed_domains),
            "excluded_paths": list(self.excluded_paths),
            "policy_url": self.policy_url,
            "contact": self.contact,
            "metadata": dict(self.metadata),
        }


class ScopeManager:
    """Enforces target domain boundaries and out-of-scope path exclusions."""
    def __init__(
        self,
        allowed_domains=None,
        program: Optional[ProgramMetadata] = None,
        excluded_paths: Optional[List[str]] = None,
    ):
        domains = list(allowed_domains or [])
        if program and program.allowed_domains:
            domains.extend(program.allowed_domains)

        self.allowed_domains: Set[str] = {
            d.lower().strip().lstrip("*.")
            for d in domains
            if d and d.strip()
        }
        self.program = program

        all_excluded = list(excluded_paths or [])
        if program and program.excluded_paths:
            all_excluded.extend(program.excluded_paths)

        self.excluded_paths: Set[str] = {
            p.lower().strip() for p in all_excluded if p and p.strip()
        }

    def is_allowed(self, url: str) -> bool:
        parsed = urlparse(url)

        if parsed.scheme not in ("http", "https"):
            return False

        hostname = (parsed.hostname or "").lower()
        if not hostname:
            return False

        domain_matched = False
        for domain in self.allowed_domains:
            if hostname == domain or hostname.endswith("." + domain):
                domain_matched = True
                break

        if not domain_matched:
            return False

        # Path boundary / exclusion check
        if self.excluded_paths and parsed.path:
            norm_path = parsed.path.lower()
            for exc in self.excluded_paths:
                exc_clean = exc.rstrip("/")
                if norm_path == exc_clean or norm_path.startswith(exc_clean + "/"):
                    return False

        return True


# ==============================================================================
# Endpoint Intelligence Models
# ==============================================================================

@dataclass
class Endpoint:
    """Discovered web endpoint catalog entry."""
    url: str
    path: str
    method: str = "GET"
    endpoint_type: str = "link"  # link, form, script, resource
    is_in_scope: bool = True
    source_tag: str = ""
    parameters: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "path": self.path,
            "method": self.method,
            "endpoint_type": self.endpoint_type,
            "is_in_scope": self.is_in_scope,
            "source_tag": self.source_tag,
            "parameters": list(self.parameters),
        }


class EndpointInventory:
    """
    Passively tracks, normalizes, deduplicates, and classifies endpoints discovered
    during research. Never issues requests to discovered endpoints.
    """
    def __init__(self, base_url: str, scope_manager: Optional[ScopeManager] = None):
        self.base_url = base_url
        self.scope_manager = scope_manager
        self.endpoints: Dict[str, Endpoint] = {}

    def normalize_url(self, raw_url: str) -> Optional[Tuple[str, str, List[str]]]:
        raw = raw_url.strip()
        if not raw or raw.startswith("#"):
            return None

        lower_raw = raw.lower()
        # Ignore pseudo-protocols and non-http schemes
        if lower_raw.startswith(("javascript:", "mailto:", "tel:", "data:", "blob:", "about:", "sms:", "callto:")):
            return None

        # Resolve relative URLs against base
        resolved = urljoin(self.base_url, raw)
        parsed = urlsplit(resolved)

        if parsed.scheme.lower() not in ("http", "https"):
            return None

        hostname = (parsed.hostname or "").lower()
        if not hostname:
            return None

        netloc = hostname
        if parsed.port and not (
            (parsed.scheme == "http" and parsed.port == 80)
            or (parsed.scheme == "https" and parsed.port == 443)
        ):
            netloc = f"{hostname}:{parsed.port}"

        path = parsed.path or "/"
        while "//" in path:
            path = path.replace("//", "/")

        params: List[str] = []
        if parsed.query:
            for q in parsed.query.split("&"):
                if "=" in q:
                    k, _ = q.split("=", 1)
                    if k:
                        params.append(k)
                elif q:
                    params.append(q)
            params = sorted(set(params))

        normalized_url = urlunsplit((parsed.scheme.lower(), netloc, path, parsed.query, ""))
        return normalized_url, path, params

    def add_endpoint(
        self,
        raw_url: str,
        method: str = "GET",
        endpoint_type: str = "link",
        source_tag: str = "",
    ) -> Optional[Endpoint]:
        norm = self.normalize_url(raw_url)
        if not norm:
            return None

        normalized_url, path, params = norm
        method_upper = method.upper()
        key = f"{method_upper}:{normalized_url}"

        if key in self.endpoints:
            return self.endpoints[key]

        is_in_scope = True
        if self.scope_manager:
            is_in_scope = self.scope_manager.is_allowed(normalized_url)

        endpoint = Endpoint(
            url=normalized_url,
            path=path,
            method=method_upper,
            endpoint_type=endpoint_type,
            is_in_scope=is_in_scope,
            source_tag=source_tag,
            parameters=params,
        )
        self.endpoints[key] = endpoint
        return endpoint

    def get_in_scope(self) -> List[Endpoint]:
        return [ep for ep in self.endpoints.values() if ep.is_in_scope]

    def to_list(self) -> List[Dict[str, Any]]:
        return [ep.to_dict() for ep in self.endpoints.values()]


# ==============================================================================
# Audit Trail Models
# ==============================================================================

@dataclass
class AuditEvent:
    """Chronological, security-relevant decision or activity record."""
    event_type: str
    timestamp: str
    target: str
    status: str = "INFO"  # INFO, OK, DENIED, ERROR
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_type": self.event_type,
            "timestamp": self.timestamp,
            "target": self.target,
            "status": self.status,
            "details": dict(self.details),
        }


class AuditTrail:
    """Captures an immutable sequence of research operational events."""
    def __init__(self, target: str = ""):
        self.target = target
        self.events: List[AuditEvent] = []

    def record(
        self,
        event_type: str,
        details: Optional[Dict[str, Any]] = None,
        status: str = "INFO",
        target: Optional[str] = None,
    ) -> AuditEvent:
        event = AuditEvent(
            event_type=event_type,
            timestamp=datetime.now(timezone.utc).isoformat(),
            target=target or self.target,
            status=status,
            details=details or {},
        )
        self.events.append(event)
        return event

    def to_list(self) -> List[Dict[str, Any]]:
        return [e.to_dict() for e in self.events]


# ==============================================================================
# Evidence Bundle Model
# ==============================================================================

@dataclass
class EvidenceBundle:
    """Structured container holding all collected passive research data and provenance."""
    target: str
    timestamp: str
    scope_verified: bool = False
    authorization_verified: bool = False
    request: Dict[str, Any] = field(default_factory=dict)
    response: Dict[str, Any] = field(default_factory=dict)
    http: Dict[str, Any] = field(default_factory=dict)
    html_analysis: Dict[str, Any] = field(default_factory=dict)
    interesting_paths: List[str] = field(default_factory=list)
    sha256_digest: str = ""
    endpoints: List[Dict[str, Any]] = field(default_factory=list)
    audit_trail: List[Dict[str, Any]] = field(default_factory=list)
    program: Dict[str, Any] = field(default_factory=dict)
    permission: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "timestamp": self.timestamp,
            "scope_verified": self.scope_verified,
            "authorization_verified": self.authorization_verified,
            "request": dict(self.request),
            "response": dict(self.response),
            "http": dict(self.http),
            "html_analysis": dict(self.html_analysis),
            "interesting_paths": list(self.interesting_paths),
            "sha256_digest": self.sha256_digest,
            "endpoints": list(self.endpoints),
            "audit_trail": list(self.audit_trail),
            "program": dict(self.program),
            "permission": dict(self.permission),
        }


# ==============================================================================
# Finding Model (Preserved with M7.6 validation extensions)
# ==============================================================================

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


# ==============================================================================
# Security Research Agent Core
# ==============================================================================

class SecurityResearchAgent:
    """
    Main orchestrator for scoped, authorized, passive security research.
    Strictly enforces authorization checks before network execution.
    """
    def __init__(
        self,
        target: str,
        allowed_domains: Optional[List[str]] = None,
        validator: Optional[FindingValidator] = None,
        permission: Optional[PermissionGrant] = None,
        program: Optional[ProgramMetadata] = None,
    ):
        self.target = target.rstrip("/")
        self.program = program or ProgramMetadata(
            program_id="default-engagement",
            name="Authorized Research Engagement",
            allowed_domains=list(allowed_domains or []),
        )
        # Explicit authorization grant: if not supplied, defaults to UNAUTHORIZED
        self.permission = permission or PermissionGrant(
            status=AuthorizationStatus.UNAUTHORIZED,
            scope_reference=self.program.program_id,
        )
        self.scope = ScopeManager(
            allowed_domains=allowed_domains,
            program=self.program,
        )
        self.findings: List[Finding] = []
        self.observations: List[Observation] = []
        self.validator = validator or FindingValidator()
        self.audit = AuditTrail(target=self.target)
        self.inventory = EndpointInventory(base_url=self.target, scope_manager=self.scope)

        now_iso = datetime.now(timezone.utc).isoformat()
        self.evidence_bundle = EvidenceBundle(
            target=self.target,
            timestamp=now_iso,
            scope_verified=False,
            authorization_verified=False,
            program=self.program.to_dict(),
            permission=self.permission.to_dict(),
        )
        # Keep self.evidence synchronized as a dict for 100% backward compatibility
        self.evidence: Dict[str, Any] = self.evidence_bundle.to_dict()

    def _sync_evidence(self):
        """Synchronizes structured evidence bundle and legacy evidence dictionary."""
        self.evidence_bundle.audit_trail = self.audit.to_list()
        self.evidence_bundle.endpoints = self.inventory.to_list()
        if isinstance(self.evidence, dict) and "http" in self.evidence and self.evidence["http"] and not self.evidence_bundle.http:
            self.evidence_bundle.http = self.evidence["http"]

        synced = self.evidence_bundle.to_dict()
        if isinstance(self.evidence, dict):
            for k, v in self.evidence.items():
                if k not in synced or (v and not synced[k]):
                    synced[k] = v
        self.evidence = synced

    def verify_scope(self) -> bool:
        allowed = self.scope.is_allowed(self.target)
        self.evidence_bundle.scope_verified = allowed
        self._sync_evidence()

        if not allowed:
            self.audit.record(
                event_type="SCOPE_EVALUATED",
                details={"allowed": False, "target": self.target},
                status="DENIED",
            )
            self._sync_evidence()
            raise PermissionError(f"TARGET OUT OF SCOPE: {self.target}")

        self.audit.record(
            event_type="SCOPE_EVALUATED",
            details={"allowed": True, "target": self.target},
            status="OK",
        )
        self._sync_evidence()
        return True

    def verify_authorization(self) -> bool:
        """Enforces explicit authorization verification."""
        stat_val = str(
            self.permission.status.value
            if isinstance(self.permission.status, Enum)
            else getattr(self.permission, "status", "MISSING")
        )
        self.audit.record(
            event_type="AUTHORIZATION_CHECKED",
            details={
                "status": stat_val,
                "authorized_by": getattr(self.permission, "authorized_by", ""),
                "valid_until": getattr(self.permission, "valid_until", None),
            },
            status="INFO",
        )

        if not self.permission or not self.permission.is_valid():
            self.audit.record(
                event_type="AUTHORIZATION_DENIED",
                details={
                    "reason": f"Explicit AUTHORIZED permission required (current: {stat_val})",
                    "target": self.target,
                },
                status="DENIED",
            )
            self._sync_evidence()
            raise PermissionError(
                f"AUTHORIZATION DENIED for target '{self.target}': explicit AUTHORIZED PermissionGrant required (current status: {stat_val})."
            )

        self.evidence_bundle.authorization_verified = True
        self._sync_evidence()
        return True

    def fetch(self):
        # 1. Enforce scope
        if not self.scope.is_allowed(self.target):
            self.audit.record("SCOPE_EVALUATED", {"allowed": False, "target": self.target}, status="DENIED")
            self._sync_evidence()
            raise PermissionError("Blocked by scope policy.")

        # 2. Enforce explicit authorization
        if not self.permission or not self.permission.is_valid():
            stat_val = str(
                self.permission.status.value
                if isinstance(self.permission.status, Enum)
                else getattr(self.permission, "status", "MISSING")
            )
            self.audit.record("AUTHORIZATION_DENIED", {"target": self.target, "status": stat_val}, status="DENIED")
            self._sync_evidence()
            raise PermissionError(f"Blocked by authorization policy: explicit AUTHORIZED grant required (current status: {stat_val}).")

        request_headers = {
            "User-Agent": "DARK-EYE-SecurityResearch/0.1",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
        req_time = datetime.now(timezone.utc).isoformat()
        self.evidence_bundle.request = {
            "method": "GET",
            "url": self.target,
            "headers": request_headers,
            "timestamp": req_time,
        }

        self.audit.record(
            event_type="HTTP_DISPATCHED",
            details={"method": "GET", "url": self.target},
            status="OK",
        )
        self._sync_evidence()

        request = urllib.request.Request(
            self.target,
            headers=request_headers,
        )
        context = ssl.create_default_context()

        with urllib.request.urlopen(
            request,
            timeout=10,
            context=context,
        ) as response:
            body = response.read(200000)

            headers = {
                k.lower(): v
                for k, v in response.headers.items()
            }

            sha256 = hashlib.sha256(body).hexdigest()
            resp_url = response.geturl()
            resp_status = response.status

            http_data = {
                "status": resp_status,
                "final_url": resp_url,
                "headers": headers,
                "content_length_sample": len(body),
            }

            self.evidence_bundle.http = http_data
            self.evidence_bundle.response = {
                "status": resp_status,
                "final_url": resp_url,
                "headers": headers,
                "content_length_sample": len(body),
                "sha256_digest": sha256,
            }
            self.evidence_bundle.sha256_digest = sha256

            self.audit.record(
                event_type="FETCH_COMPLETED",
                details={
                    "status": resp_status,
                    "final_url": resp_url,
                    "sha256": sha256,
                    "bytes": len(body),
                },
                status="OK",
            )
            self._sync_evidence()

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
                recommendation="Consider minimizing unnecessary server/version disclosure.",
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
                recommendation="Remove unnecessary framework/runtime disclosure.",
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

        self.evidence_bundle.html_analysis = {
            "forms": forms,
            "scripts": scripts,
            "links": links,
        }

        # Discover endpoints safely (passive cataloging, no network dispatch)
        # 1. Forms
        for m in re.finditer(r"""<form\b[^>]*?\baction=["']([^"'#]*)["'][^>]*>""", text, re.I):
            action = m.group(1) or self.target
            form_tag = m.group(0)
            method_m = re.search(r"""\bmethod=["']([^"']+)["']""", form_tag, re.I)
            form_method = method_m.group(1).upper() if method_m else "POST"
            self.inventory.add_endpoint(action, method=form_method, endpoint_type="form", source_tag="form")

        # 2. Scripts
        for m in re.finditer(r"""<script\b[^>]*?\bsrc=["']([^"'#]+)["']""", text, re.I):
            src = m.group(1)
            self.inventory.add_endpoint(src, method="GET", endpoint_type="script", source_tag="script")

        # 3. Links
        for m in re.finditer(r"""<a\b[^>]*?\bhref=["']([^"'#]+)["']""", text, re.I):
            href = m.group(1)
            self.inventory.add_endpoint(href, method="GET", endpoint_type="link", source_tag="a")

        # 4. Resource tags
        for m in re.finditer(r"""<(?:link|img|iframe|source)\b[^>]*?\b(?:href|src)=["']([^"'#]+)["']""", text, re.I):
            uri = m.group(1)
            self.inventory.add_endpoint(uri, method="GET", endpoint_type="resource", source_tag="resource")

        # Backward compatibility interesting_paths
        interesting_paths = sorted({ep.path for ep in self.inventory.endpoints.values() if ep.path})
        self.evidence_bundle.interesting_paths = interesting_paths[:100]
        self._sync_evidence()

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
        if isinstance(self.evidence, dict) and "http" in self.evidence and self.evidence["http"]:
            context = dict(self.evidence)
        else:
            context = self.evidence_bundle.to_dict()

        items_to_validate = self.observations if self.observations else self.findings
        self.findings = self.validator.validate_all(items_to_validate, context)

        val_counts = {}
        for f in self.findings:
            st = f.validation.get("status") if f.validation else "UNKNOWN"
            val_counts[st] = val_counts.get(st, 0) + 1

        self.audit.record(
            event_type="FINDINGS_VALIDATED",
            details={
                "total_findings": len(self.findings),
                "breakdown": val_counts,
            },
            status="OK",
        )
        self._sync_evidence()
        return self.findings

    def run(self):
        self.verify_scope()
        self.verify_authorization()

        response, body = self.fetch()

        headers = self.evidence_bundle.http.get("headers", {})

        self.analyze_headers(headers)
        self.analyze_server_disclosure(headers)
        self.analyze_html(body)

        self.deduplicate()
        self.validate_findings()

        self._sync_evidence()

        return {
            "evidence": self.evidence,
            "findings": [asdict(f) for f in self.findings],
        }


# ==============================================================================
# Reporting Serialization
# ==============================================================================

def save_report(result, output_dir="security_reports"):
    """
    Saves JSON evidence bundle and Markdown security report with full
    endpoint inventory, audit trail, and validation details.
    """
    Path(output_dir).mkdir(exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    json_path = Path(output_dir) / f"dark_eye_{timestamp}.json"
    md_path = Path(output_dir) / f"dark_eye_{timestamp}.md"

    evidence = result.get("evidence", {})
    target = evidence.get("target", "Unknown Target")
    scope_verified = evidence.get("scope_verified", False)
    auth_verified = evidence.get("authorization_verified", False)
    sha256 = evidence.get("sha256_digest", "")
    program_id = evidence.get("program", {}).get("program_id", "N/A")
    permission_stat = evidence.get("permission", {}).get("status", "N/A")

    audit_trail = evidence.get("audit_trail", [])
    if isinstance(audit_trail, list):
        audit_trail.append({
            "event_type": "REPORT_GENERATED",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target": target,
            "status": "OK",
            "details": {"json_report": str(json_path), "md_report": str(md_path)},
        })

    json_path.write_text(
        json.dumps(result, indent=2),
        encoding="utf-8",
    )

    lines = [
        "# DARK-EYE Security Research Report",
        "",
        f"Target: `{target}`",
        f"Program ID: `{program_id}`",
        f"Scope verified: `{scope_verified}`",
        f"Authorization Status: `{permission_stat}` (Verified: `{auth_verified}`)",
    ]

    if sha256:
        lines.append(f"Response SHA-256: `{sha256}`")

    lines.extend([
        "",
        "## Findings",
        "",
    ])

    findings = result.get("findings", [])
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

    # Discovered Endpoints
    endpoints = evidence.get("endpoints", [])
    if endpoints:
        lines.extend([
            "## Discovered Endpoints (Passive Inventory)",
            "",
            f"Total discovered endpoints: **{len(endpoints)}**",
            "",
        ])
        for ep in endpoints[:30]:
            scope_badge = "IN-SCOPE" if ep.get("is_in_scope") else "OUT-OF-SCOPE"
            lines.append(f"- `[{ep.get('method', 'GET')}]` {ep.get('url')} (`{ep.get('endpoint_type', 'link')}`) - **{scope_badge}**")
        if len(endpoints) > 30:
            lines.append(f"\n*(Showing 30 of {len(endpoints)} endpoints; see JSON report for full inventory)*")
        lines.append("")

    # Audit Trail
    if audit_trail:
        lines.extend([
            "## Research Audit Trail",
            "",
        ])
        for event in audit_trail:
            ev_type = event.get("event_type", "EVENT")
            ev_time = event.get("timestamp", "")
            ev_status = event.get("status", "INFO")
            lines.append(f"- `[{ev_time}]` **{ev_type}** (`{ev_status}`)")
        lines.append("")

    md_path.write_text("\n".join(lines), encoding="utf-8")

    return json_path, md_path
