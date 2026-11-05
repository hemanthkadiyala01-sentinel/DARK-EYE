"""
DARK-EYE Security Research Agent
M7.8

Scope-controlled, explicitly authorized passive security research for approved targets.
Features:
- ResearchAction enum defining fine-grained, passive research permissions
- Structured ScopeTarget definition with exact host vs. wildcard and port enforcement
- ScopeDecision and ScopeReason providing explanatory scope evaluation
- Explicit authorization lifecycle and action-aware verification gate
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
# Research Actions & Authorization Models
# ==============================================================================

class ResearchAction(str, Enum):
    """
    Explicitly permitted passive security research actions.
    Active exploitation, brute force, fuzzing, or destructive actions are strictly excluded.
    """
    PASSIVE_RECON = "PASSIVE_RECON"
    HEADER_ANALYSIS = "HEADER_ANALYSIS"
    ENDPOINT_DISCOVERY = "ENDPOINT_DISCOVERY"
    FINDING_VALIDATION = "FINDING_VALIDATION"
    REPORT_GENERATION = "REPORT_GENERATION"


DEFAULT_PASSIVE_ACTIONS: Set[ResearchAction] = {
    ResearchAction.PASSIVE_RECON,
    ResearchAction.HEADER_ANALYSIS,
    ResearchAction.ENDPOINT_DISCOVERY,
    ResearchAction.FINDING_VALIDATION,
    ResearchAction.REPORT_GENERATION,
}


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
    allowed_actions: Optional[Set[Union[ResearchAction, str]]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def is_valid(self) -> bool:
        stat = self.status.value if isinstance(self.status, Enum) else str(self.status)
        if stat != AuthorizationStatus.AUTHORIZED.value:
            return False
        if not self.allow_passive:
            return False
        if self.valid_until is not None:
            if not isinstance(self.valid_until, str) or not self.valid_until.strip():
                return False

            try:
                until_dt = datetime.fromisoformat(
                    self.valid_until.strip().replace("Z", "+00:00")
                )
                if until_dt.tzinfo is None:
                    until_dt = until_dt.replace(tzinfo=timezone.utc)

                now_dt = datetime.now(timezone.utc)
                if now_dt >= until_dt:
                    return False
            except (ValueError, TypeError, OverflowError):
                return False

        return True

    def is_action_allowed(self, action: Union[ResearchAction, str]) -> bool:
        """
        Determines if a specific research action is authorized.
        Denies by default for invalid/expired/revoked authorization or unknown actions.
        """
        if not self.is_valid():
            return False

        # Convert to ResearchAction enum
        if isinstance(action, ResearchAction):
            act_enum = action
        else:
            try:
                act_enum = ResearchAction(str(action))
            except ValueError:
                # Unknown/unrecognized actions are strictly denied
                return False

        if not self.allow_passive:
            return False

        # If allowed_actions is explicitly specified, only those actions are permitted
        if self.allowed_actions is not None:
            normalized_allowed = set()
            for a in self.allowed_actions:
                if isinstance(a, ResearchAction):
                    normalized_allowed.add(a)
                elif str(a) in ResearchAction._value2member_map_:
                    normalized_allowed.add(ResearchAction(str(a)))
                else:
                    normalized_allowed.add(str(a))
            return act_enum in normalized_allowed

        # If allowed_actions is None (legacy M7.7 grant), allow standard passive actions
        return act_enum in DEFAULT_PASSIVE_ACTIONS

    def to_dict(self) -> Dict[str, Any]:
        stat = self.status.value if isinstance(self.status, Enum) else str(self.status)
        actions_list = None
        if self.allowed_actions is not None:
            actions_list = [
                a.value if isinstance(a, Enum) else str(a)
                for a in self.allowed_actions
            ]
        return {
            "status": stat,
            "authorized_by": self.authorized_by,
            "scope_reference": self.scope_reference,
            "valid_until": self.valid_until,
            "allow_passive": self.allow_passive,
            "allowed_actions": actions_list,
            "is_valid": self.is_valid(),
            "metadata": dict(self.metadata),
        }


# ==============================================================================
# Scope Intelligence Models
# ==============================================================================

class ScopeReason(str, Enum):
    ALLOWED = "ALLOWED"
    INVALID_SCHEME = "INVALID_SCHEME"
    INVALID_URL = "INVALID_URL"
    DOMAIN_NOT_ALLOWED = "DOMAIN_NOT_ALLOWED"
    SUBDOMAIN_NOT_ALLOWED = "SUBDOMAIN_NOT_ALLOWED"
    PORT_NOT_ALLOWED = "PORT_NOT_ALLOWED"
    PATH_EXCLUDED = "PATH_EXCLUDED"
    EXPLICITLY_EXCLUDED = "EXPLICITLY_EXCLUDED"


@dataclass
class ScopeTarget:
    """Structured scope target boundary definition."""
    host: str
    exact_host: bool = False
    allowed_ports: Optional[Set[int]] = None
    excluded_paths: List[str] = field(default_factory=list)
    description: str = ""

    def __post_init__(self):
        self.host = self.host.lower().strip().lstrip("*.")
        if self.allowed_ports is not None:
            self.allowed_ports = set(self.allowed_ports)
        if self.excluded_paths:
            self.excluded_paths = [p.lower().strip() for p in self.excluded_paths if p]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "host": self.host,
            "exact_host": self.exact_host,
            "allowed_ports": sorted(list(self.allowed_ports)) if self.allowed_ports is not None else None,
            "excluded_paths": list(self.excluded_paths),
            "description": self.description,
        }


@dataclass
class ScopeDecision:
    """Detailed result of scope evaluation including reason and matched target."""
    url: str
    allowed: bool
    reason: Union[ScopeReason, str]
    matched_target: Optional[ScopeTarget] = None
    hostname: Optional[str] = None
    port: Optional[int] = None
    path: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        reason_val = self.reason.value if isinstance(self.reason, Enum) else str(self.reason)
        return {
            "url": self.url,
            "allowed": self.allowed,
            "reason": reason_val,
            "matched_target": self.matched_target.to_dict() if self.matched_target else None,
            "hostname": self.hostname,
            "port": self.port,
            "path": self.path,
            "details": dict(self.details),
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
    targets: List[ScopeTarget] = field(default_factory=list)
    excluded_domains: List[str] = field(default_factory=list)
    policy_url: Optional[str] = None
    contact: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "program_id": self.program_id,
            "name": self.name,
            "allowed_domains": list(self.allowed_domains),
            "excluded_paths": list(self.excluded_paths),
            "targets": [t.to_dict() if hasattr(t, "to_dict") else t for t in self.targets],
            "excluded_domains": list(self.excluded_domains),
            "policy_url": self.policy_url,
            "contact": self.contact,
            "metadata": dict(self.metadata),
        }


class ScopeManager:
    """
    Enforces target domain boundaries, ports, and out-of-scope path exclusions.
    Provides structured ScopeDecision evaluations while maintaining is_allowed backward compatibility.
    """
    def __init__(
        self,
        allowed_domains: Optional[List[Union[str, ScopeTarget]]] = None,
        program: Optional[ProgramMetadata] = None,
        excluded_paths: Optional[List[str]] = None,
        targets: Optional[List[ScopeTarget]] = None,
        excluded_domains: Optional[List[str]] = None,
    ):
        self.program = program
        self.targets: List[ScopeTarget] = []

        # 1. Ingest structured targets
        if targets:
            self.targets.extend(targets)
        if program and program.targets:
            self.targets.extend(program.targets)

        # 2. Ingest allowed_domains (convert strings to ScopeTarget)
        legacy_domains = list(allowed_domains or [])
        if program and program.allowed_domains:
            legacy_domains.extend(program.allowed_domains)

        for d in legacy_domains:
            if isinstance(d, ScopeTarget):
                self.targets.append(d)
            elif isinstance(d, str) and d.strip():
                clean_host = d.lower().strip().lstrip("*.")
                self.targets.append(ScopeTarget(host=clean_host, exact_host=False))

        # Backward compatibility attribute: allowed_domains set
        self.allowed_domains: Set[str] = {t.host for t in self.targets}

        # 3. Ingest path exclusions
        all_excluded_paths = list(excluded_paths or [])
        if program and program.excluded_paths:
            all_excluded_paths.extend(program.excluded_paths)

        self.excluded_paths: Set[str] = {
            p.lower().strip() for p in all_excluded_paths if p and p.strip()
        }

        # 4. Ingest domain exclusions
        all_excluded_domains = list(excluded_domains or [])
        if program and program.excluded_domains:
            all_excluded_domains.extend(program.excluded_domains)

        self.excluded_domains: Set[str] = {
            d.lower().strip().lstrip("*.") for d in all_excluded_domains if d and d.strip()
        }

    def evaluate_scope(self, url: str) -> ScopeDecision:
        """Evaluates whether a target URL is in scope, returning structured reasoning."""
        if not url or not isinstance(url, str):
            return ScopeDecision(
                url=str(url),
                allowed=False,
                reason=ScopeReason.INVALID_URL,
                details={"error": "URL is empty or not a string"},
            )

        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return ScopeDecision(
                url=url,
                allowed=False,
                reason=ScopeReason.INVALID_SCHEME,
                details={"scheme": parsed.scheme},
            )

        hostname = (parsed.hostname or "").lower()
        if not hostname:
            return ScopeDecision(
                url=url,
                allowed=False,
                reason=ScopeReason.INVALID_URL,
                details={"error": "Missing hostname in URL"},
            )

        # 1. Check explicit domain exclusions
        for exc_d in self.excluded_domains:
            if hostname == exc_d or hostname.endswith("." + exc_d):
                return ScopeDecision(
                    url=url,
                    allowed=False,
                    reason=ScopeReason.EXPLICITLY_EXCLUDED,
                    hostname=hostname,
                    details={"excluded_domain": exc_d},
                )

        # 2. Match targets deterministically.
        # Exact hostname matches take precedence over wildcard parent matches.
        # For subdomains, the most-specific applicable target controls.
        exact_matches: List[ScopeTarget] = []
        wildcard_matches: List[ScopeTarget] = []
        subdomain_denied_targets: List[ScopeTarget] = []

        for target in self.targets:
            target_host = target.host.lower().strip()

            if hostname == target_host:
                exact_matches.append(target)
            elif hostname.endswith("." + target_host):
                if target.exact_host:
                    subdomain_denied_targets.append(target)
                else:
                    wildcard_matches.append(target)

        matched_target: Optional[ScopeTarget] = None

        if exact_matches:
            # Prefer the more restrictive configured port policy.
            exact_matches.sort(
                key=lambda target: (
                    len(target.host),
                    target.allowed_ports is not None,
                    target.host,
                ),
                reverse=True,
            )
            matched_target = exact_matches[0]

        else:
            best_wildcard = max(
                wildcard_matches,
                key=lambda target: (len(target.host), target.host),
                default=None,
            )

            best_restriction = max(
                subdomain_denied_targets,
                key=lambda target: (len(target.host), target.host),
                default=None,
            )

            # A specific exact-host restriction must not be bypassed
            # by a broader parent-domain wildcard grant.
            if best_restriction is not None and (
                best_wildcard is None
                or len(best_restriction.host) >= len(best_wildcard.host)
            ):
                return ScopeDecision(
                    url=url,
                    allowed=False,
                    reason=ScopeReason.SUBDOMAIN_NOT_ALLOWED,
                    matched_target=best_restriction,
                    hostname=hostname,
                    details={
                        "target_host": best_restriction.host,
                        "exact_host": True,
                    },
                )

            matched_target = best_wildcard

        if not matched_target:
            return ScopeDecision(
                url=url,
                allowed=False,
                reason=ScopeReason.DOMAIN_NOT_ALLOWED,
                hostname=hostname,
                details={"configured_targets": [t.host for t in self.targets]},
            )

        # 3. Port check
        effective_port = parsed.port
        if effective_port is None:
            effective_port = 443 if parsed.scheme == "https" else 80

        if matched_target.allowed_ports is not None and len(matched_target.allowed_ports) > 0:
            if effective_port not in matched_target.allowed_ports:
                return ScopeDecision(
                    url=url,
                    allowed=False,
                    reason=ScopeReason.PORT_NOT_ALLOWED,
                    matched_target=matched_target,
                    hostname=hostname,
                    port=effective_port,
                    path=parsed.path,
                    details={
                        "allowed_ports": sorted(list(matched_target.allowed_ports)),
                        "requested_port": effective_port,
                    },
                )

        # 4. Path exclusion check
        path = parsed.path or "/"
        norm_path = path.lower()
        all_excluded_paths = set(self.excluded_paths)
        if matched_target.excluded_paths:
            all_excluded_paths.update(matched_target.excluded_paths)

        for exc in all_excluded_paths:
            exc_clean = exc.rstrip("/")
            if norm_path == exc_clean or norm_path.startswith(exc_clean + "/"):
                return ScopeDecision(
                    url=url,
                    allowed=False,
                    reason=ScopeReason.PATH_EXCLUDED,
                    matched_target=matched_target,
                    hostname=hostname,
                    port=effective_port,
                    path=path,
                    details={"matched_exclusion": exc},
                )

        return ScopeDecision(
            url=url,
            allowed=True,
            reason=ScopeReason.ALLOWED,
            matched_target=matched_target,
            hostname=hostname,
            port=effective_port,
            path=path,
        )

    def is_allowed(self, url: str) -> bool:
        """Backward-compatible boolean wrapper around evaluate_scope()."""
        return self.evaluate_scope(url).allowed


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
    Strictly enforces authorization checks and action permissions before execution.
    """
    def __init__(
        self,
        target: str,
        allowed_domains: Optional[List[Union[str, ScopeTarget]]] = None,
        validator: Optional[FindingValidator] = None,
        permission: Optional[PermissionGrant] = None,
        program: Optional[ProgramMetadata] = None,
        targets: Optional[List[ScopeTarget]] = None,
    ):
        self.target = target.rstrip("/")
        self.program = program or ProgramMetadata(
            program_id="default-engagement",
            name="Authorized Research Engagement",
            allowed_domains=[d for d in (allowed_domains or []) if isinstance(d, str)],
        )
        # Explicit authorization grant: if not supplied, defaults to UNAUTHORIZED
        self.permission = permission or PermissionGrant(
            status=AuthorizationStatus.UNAUTHORIZED,
            scope_reference=self.program.program_id,
        )
        self.scope = ScopeManager(
            allowed_domains=allowed_domains,
            program=self.program,
            targets=targets,
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
        decision = self.scope.evaluate_scope(self.target)
        allowed = decision.allowed
        self.evidence_bundle.scope_verified = allowed
        reason_val = decision.reason.value if isinstance(decision.reason, Enum) else str(decision.reason)

        if not allowed:
            self.audit.record(
                event_type="SCOPE_EVALUATED",
                details={
                    "allowed": False,
                    "target": self.target,
                    "reason": reason_val,
                    "decision": decision.to_dict(),
                },
                status="DENIED",
            )
            self._sync_evidence()
            raise PermissionError(f"TARGET OUT OF SCOPE: {self.target} (Reason: {reason_val})")

        self.audit.record(
            event_type="SCOPE_EVALUATED",
            details={
                "allowed": True,
                "target": self.target,
                "reason": reason_val,
                "decision": decision.to_dict(),
            },
            status="OK",
        )
        self._sync_evidence()
        return True

    def verify_authorization(self) -> bool:
        """Enforces explicit authorization status verification."""
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

    def verify_action(self, action: Union[ResearchAction, str]) -> bool:
        """Verifies that a specific research action is permitted by the grant."""
        try:
            act_enum = action if isinstance(action, ResearchAction) else ResearchAction(str(action))
        except (TypeError, ValueError):
            action_value = str(action)
            self.audit.record(
                event_type="ACTION_AUTHORIZATION_DENIED",
                details={
                    "action": action_value,
                    "reason": f"Unknown research action '{action_value}' is denied by default",
                    "target": self.target,
                },
                status="DENIED",
            )
            self._sync_evidence()
            raise PermissionError(
                f"ACTION AUTHORIZATION DENIED: Unknown research action '{action_value}' is not permitted."
            )

        if not self.permission.is_action_allowed(act_enum):
            self.audit.record(
                event_type="ACTION_AUTHORIZATION_DENIED",
                details={
                    "action": act_enum.value,
                    "reason": f"Action '{act_enum.value}' is not permitted by PermissionGrant",
                    "target": self.target,
                },
                status="DENIED",
            )
            self._sync_evidence()
            raise PermissionError(
                f"ACTION AUTHORIZATION DENIED: Action '{act_enum.value}' is not permitted on target '{self.target}'."
            )
        return True

    def generate_report(self, result=None, output_dir="security_reports"):
        """Generate a report only when REPORT_GENERATION is explicitly authorized."""
        self.verify_action(ResearchAction.REPORT_GENERATION)
        report_result = result if result is not None else {
            "evidence": self.evidence,
            "findings": [asdict(f) for f in self.findings],
        }
        return save_report(report_result, output_dir=output_dir)

    def fetch(self):
        # 1. Enforce authorization validity
        if not self.permission or not self.permission.is_valid():
            stat_val = str(
                self.permission.status.value
                if isinstance(self.permission.status, Enum)
                else getattr(self.permission, "status", "MISSING")
            )
            self.audit.record("AUTHORIZATION_DENIED", {"target": self.target, "status": stat_val}, status="DENIED")
            self._sync_evidence()
            raise PermissionError(f"Blocked by authorization policy: explicit AUTHORIZED grant required (current status: {stat_val}).")

        # 2. Enforce action authorization for recon
        if not self.permission.is_action_allowed(ResearchAction.PASSIVE_RECON):
            self.audit.record(
                event_type="ACTION_AUTHORIZATION_DENIED",
                details={
                    "action": ResearchAction.PASSIVE_RECON.value,
                    "reason": "PASSIVE_RECON action not permitted",
                    "target": self.target,
                },
                status="DENIED",
            )
            self._sync_evidence()
            raise PermissionError(f"Blocked by authorization policy: action '{ResearchAction.PASSIVE_RECON.value}' not permitted on '{self.target}'.")

        # 3. Enforce scope
        decision = self.scope.evaluate_scope(self.target)
        if not decision.allowed:
            reason_val = decision.reason.value if isinstance(decision.reason, Enum) else str(decision.reason)
            self.audit.record("SCOPE_EVALUATED", {"allowed": False, "target": self.target, "reason": reason_val}, status="DENIED")
            self._sync_evidence()
            raise PermissionError(f"Blocked by scope policy: {reason_val}")

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
        """Passively catalogs discovered endpoints in the response body. Never dispatches requests."""
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
        # 1. Authorization validity check
        self.verify_authorization()

        # 2. Action authorization check for passive recon
        self.verify_action(ResearchAction.PASSIVE_RECON)

        # 3. Scope verification check
        self.verify_scope()

        # 4. Network execution
        response, body = self.fetch()

        headers = self.evidence_bundle.http.get("headers", {})

        # 5. Header analysis phase check
        if self.permission.is_action_allowed(ResearchAction.HEADER_ANALYSIS):
            self.analyze_headers(headers)
            self.analyze_server_disclosure(headers)
        else:
            self.audit.record(
                event_type="ACTION_AUTHORIZATION_DENIED",
                details={
                    "action": ResearchAction.HEADER_ANALYSIS.value,
                    "reason": "Header analysis not authorized in PermissionGrant",
                    "target": self.target,
                },
                status="DENIED",
            )

        # 6. Endpoint discovery phase check
        if self.permission.is_action_allowed(ResearchAction.ENDPOINT_DISCOVERY):
            self.analyze_html(body)
        else:
            self.audit.record(
                event_type="ACTION_AUTHORIZATION_DENIED",
                details={
                    "action": ResearchAction.ENDPOINT_DISCOVERY.value,
                    "reason": "Endpoint discovery not authorized in PermissionGrant",
                    "target": self.target,
                },
                status="DENIED",
            )

        self.deduplicate()

        # 7. Finding validation phase check
        if self.permission.is_action_allowed(ResearchAction.FINDING_VALIDATION):
            self.validate_findings()
        else:
            self.audit.record(
                event_type="ACTION_AUTHORIZATION_DENIED",
                details={
                    "action": ResearchAction.FINDING_VALIDATION.value,
                    "reason": "Finding validation not authorized in PermissionGrant",
                    "target": self.target,
                },
                status="DENIED",
            )

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
    endpoint inventory, audit trail, authorized actions, and validation details.
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
    permission_dict = evidence.get("permission", {})
    permission_stat = permission_dict.get("status", "N/A")
    allowed_actions = permission_dict.get("allowed_actions")

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

    if allowed_actions is not None:
        actions_str = ", ".join(allowed_actions) if allowed_actions else "None"
        lines.append(f"Authorized Actions: `{actions_str}`")

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
