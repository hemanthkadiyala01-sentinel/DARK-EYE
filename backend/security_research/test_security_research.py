from dataclasses import asdict
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock
import hashlib

from backend.security_research.agent import (
    ScopeManager,
    SecurityResearchAgent,
    Finding,
    save_report,
    AuthorizationStatus,
    PermissionGrant,
    ProgramMetadata,
    Endpoint,
    EndpointInventory,
    EvidenceBundle,
    AuditEvent,
    AuditTrail,
)
from backend.security_research.validator import (
    FindingValidator,
    ValidationStatus,
    Observation,
    ValidationResult,
)


# ==============================================================================
# Scope Tests (M7.5 / M7.7)
# ==============================================================================

def test_scope_exact_domain():
    manager = ScopeManager(["example.com"])

    assert manager.is_allowed("https://example.com")
    assert manager.is_allowed("https://api.example.com")


def test_scope_blocks_other_domain():
    manager = ScopeManager(["example.com"])

    assert not manager.is_allowed("https://example.org")


def test_scope_blocks_non_http():
    manager = ScopeManager(["example.com"])

    assert not manager.is_allowed("ftp://example.com/file")


def test_scope_with_program_metadata_and_path_exclusions():
    """ProgramMetadata path exclusions (e.g. /admin, /logout) must block out-of-scope paths."""
    program = ProgramMetadata(
        program_id="sec-eng-01",
        name="Security Lab Engagement",
        allowed_domains=["target.local"],
        excluded_paths=["/admin", "/logout", "/private/"],
    )
    manager = ScopeManager(program=program)

    assert manager.is_allowed("https://target.local/api/users")
    assert manager.is_allowed("https://target.local/dashboard")
    assert not manager.is_allowed("https://target.local/admin")
    assert not manager.is_allowed("https://target.local/admin/settings")
    assert not manager.is_allowed("https://target.local/logout")
    assert not manager.is_allowed("https://target.local/private/keys")
    assert not manager.is_allowed("https://other.local/api")


# ==============================================================================
# M7.6 Finding Validation Engine Tests
# ==============================================================================

def test_validated_missing_csp():
    """Missing CSP on response without CSP should be VALIDATED with preserved severity and boosted confidence."""
    validator = FindingValidator()
    obs = Observation(
        title="Missing Content-Security-Policy",
        severity="medium",
        confidence=85,
        evidence="Response did not contain 'content-security-policy'.",
        recommendation="Consider implementing an appropriate Content-Security-Policy.",
        metadata={"header": "content-security-policy", "check_type": "missing_header"},
    )
    context = {
        "target": "https://example.com",
        "http": {
            "headers": {
                "content-type": "text/html",
                "x-content-type-options": "nosniff",
            }
        },
    }

    finding = validator.validate(obs, context)

    assert finding.title == "Missing Content-Security-Policy"
    assert finding.severity == "medium"
    assert finding.initial_confidence == 85
    assert finding.final_confidence == 95
    assert finding.confidence == 95
    assert finding.validation["status"] == ValidationStatus.VALIDATED.value
    assert finding.validation["rechecked"] is True
    assert finding.validation["evidence_reproduced"] is True
    assert "Confirmed missing 'content-security-policy'" in finding.validation["reason"]


def test_hsts_on_http_context_dependent():
    """HSTS missing on an HTTP target must be CONTEXT_DEPENDENT."""
    validator = FindingValidator()
    obs = Observation(
        title="Missing Strict-Transport-Security",
        severity="low",
        confidence=85,
        evidence="Response did not contain 'strict-transport-security'.",
        recommendation="Enable HSTS when HTTPS is intended to be enforced.",
        metadata={"header": "strict-transport-security", "check_type": "missing_header"},
    )
    context = {
        "target": "http://example.com",
        "http": {
            "final_url": "http://example.com/",
            "headers": {
                "content-type": "text/html",
            },
        },
    }

    finding = validator.validate(obs, context)

    assert finding.title == "Missing Strict-Transport-Security"
    assert finding.validation["status"] == ValidationStatus.CONTEXT_DEPENDENT.value
    assert finding.validation["rechecked"] is True
    assert finding.validation["evidence_reproduced"] is True
    assert "HTTP" in finding.validation["reason"]
    assert "HTTPS" in finding.validation["reason"]
    assert finding.final_confidence == 60


def test_hsts_on_https_validated():
    """HSTS missing on an HTTPS target must be VALIDATED."""
    validator = FindingValidator()
    obs = Observation(
        title="Missing Strict-Transport-Security",
        severity="low",
        confidence=85,
        evidence="Response did not contain 'strict-transport-security'.",
        recommendation="Enable HSTS when HTTPS is intended to be enforced.",
    )
    context = {
        "target": "https://secure.example.com",
        "http": {
            "final_url": "https://secure.example.com/",
            "headers": {
                "content-type": "text/html",
            },
        },
    }

    finding = validator.validate(obs, context)

    assert finding.validation["status"] == ValidationStatus.VALIDATED.value
    assert finding.validation["rechecked"] is True
    assert finding.validation["evidence_reproduced"] is True
    assert finding.final_confidence == 95
    assert "HTTPS" in finding.validation["reason"]


def test_hsts_on_https_present_evidence_mismatch():
    """If HSTS is actually present, observation claiming missing HSTS must be UNCONFIRMED."""
    validator = FindingValidator()
    obs = Observation(
        title="Missing Strict-Transport-Security",
        severity="low",
        confidence=85,
        evidence="Response did not contain 'strict-transport-security'.",
        recommendation="Enable HSTS when HTTPS is intended to be enforced.",
    )
    context = {
        "target": "https://secure.example.com",
        "http": {
            "headers": {
                "strict-transport-security": "max-age=31536000; includeSubDomains",
            },
        },
    }

    finding = validator.validate(obs, context)

    assert finding.validation["status"] == ValidationStatus.UNCONFIRMED.value
    assert finding.validation["rechecked"] is True
    assert finding.validation["evidence_reproduced"] is False
    assert finding.final_confidence == 20
    assert "Evidence mismatch" in finding.validation["reason"]


def test_evidence_mismatch_unconfirmed():
    """Header present in response when finding claimed missing should result in UNCONFIRMED."""
    validator = FindingValidator()

    # Case 1: Missing CSP claimed, but header actually present
    obs_csp = Observation(
        title="Missing Content-Security-Policy",
        severity="medium",
        confidence=85,
        evidence="Response did not contain 'content-security-policy'.",
        recommendation="Consider implementing an appropriate Content-Security-Policy.",
    )
    context_with_csp = {
        "target": "https://example.com",
        "http": {
            "headers": {
                "content-security-policy": "default-src 'self'",
            }
        },
    }

    finding_csp = validator.validate(obs_csp, context_with_csp)

    assert finding_csp.validation["status"] == ValidationStatus.UNCONFIRMED.value
    assert finding_csp.validation["evidence_reproduced"] is False
    assert finding_csp.final_confidence == 20

    # Case 2: Server disclosure claimed, but server header missing
    obs_server = Observation(
        title="Server technology disclosure",
        severity="informational",
        confidence=90,
        evidence="Server header: Apache",
        recommendation="Minimize server disclosure.",
    )
    context_no_server = {
        "target": "https://example.com",
        "http": {
            "headers": {
                "content-type": "text/html",
            }
        },
    }

    finding_server = validator.validate(obs_server, context_no_server)

    assert finding_server.validation["status"] == ValidationStatus.UNCONFIRMED.value
    assert finding_server.validation["evidence_reproduced"] is False
    assert finding_server.final_confidence == 20


def test_server_disclosure_remains_informational():
    """Server disclosure findings should remain informational per requirement."""
    validator = FindingValidator()
    obs = Observation(
        title="Server technology disclosure",
        severity="informational",
        confidence=90,
        evidence="Server header: nginx/1.18.0",
        recommendation="Consider minimizing unnecessary server/version disclosure.",
    )
    context = {
        "target": "https://example.com",
        "http": {
            "headers": {
                "server": "nginx/1.18.0",
            }
        },
    }

    finding = validator.validate(obs, context)

    assert finding.validation["status"] == ValidationStatus.VALIDATED.value
    assert finding.validation["evidence_reproduced"] is True
    assert finding.severity == "informational"
    assert finding.final_confidence == 100


def test_confidence_calculation():
    """Direct unit tests for confidence scoring formula across all statuses."""
    validator = FindingValidator()

    # Validated: +10, max 100
    assert validator.calculate_confidence(85, ValidationStatus.VALIDATED, True) == 95
    assert validator.calculate_confidence(90, ValidationStatus.VALIDATED, True) == 100
    assert validator.calculate_confidence(95, ValidationStatus.VALIDATED, True) == 100

    # Context Dependent: initial - 25, clamped between 20 and 60
    assert validator.calculate_confidence(85, ValidationStatus.CONTEXT_DEPENDENT, True) == 60
    assert validator.calculate_confidence(70, ValidationStatus.CONTEXT_DEPENDENT, True) == 45
    assert validator.calculate_confidence(30, ValidationStatus.CONTEXT_DEPENDENT, True) == 20

    # Unconfirmed or evidence reproduction failure: fixed at 20
    assert validator.calculate_confidence(85, ValidationStatus.UNCONFIRMED, False) == 20
    assert validator.calculate_confidence(95, ValidationStatus.VALIDATED, False) == 20


def test_preservation_of_m75_behavior(tmp_path):
    """Verify backwards compatibility of Finding dataclass and save_report output."""
    legacy_finding = Finding(
        title="Missing Permissions-Policy",
        severity="low",
        confidence=85,
        evidence="Response did not contain 'permissions-policy'.",
        recommendation="Restrict browser capabilities.",
    )

    assert legacy_finding.title == "Missing Permissions-Policy"
    assert legacy_finding.severity == "low"
    assert legacy_finding.confidence == 85
    assert legacy_finding.initial_confidence == 85
    assert legacy_finding.final_confidence == 85
    assert legacy_finding.validation is None

    agent = SecurityResearchAgent(
        target="https://example.com",
        allowed_domains=["example.com"],
    )
    headers = {
        "content-type": "text/html",
        "server": "Apache/2.4.41",
    }
    agent.analyze_headers(headers)
    agent.analyze_server_disclosure(headers)

    assert len(agent.observations) > 0
    assert len(agent.findings) > 0

    # Simulate validate_findings with context
    agent.evidence["http"] = {"headers": headers, "final_url": "https://example.com/"}
    agent.validate_findings()

    findings_dict = [asdict(f) for f in agent.findings]
    result = {
        "evidence": agent.evidence,
        "findings": findings_dict,
    }

    json_path, md_path = save_report(result, output_dir=str(tmp_path))

    assert json_path.exists()
    assert md_path.exists()
    content = md_path.read_text(encoding="utf-8")
    assert "Missing Content-Security-Policy" in content
    assert "Validation Status:" in content


def test_agent_run_integration():
    """Test full SecurityResearchAgent.run() flow with mock HTTP response and explicit authorization."""
    permission = PermissionGrant(
        status=AuthorizationStatus.AUTHORIZED,
        authorized_by="Lead Security Auditor",
        scope_reference="ENGAGEMENT-2026-001",
    )
    agent = SecurityResearchAgent(
        target="http://example.com",
        allowed_domains=["example.com"],
        permission=permission,
    )

    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.geturl.return_value = "http://example.com/"
    mock_response.headers = {
        "Server": "nginx/1.19",
        "Content-Type": "text/html",
    }
    body_content = b"<html><head><title>Test</title></head><body><form action='/login' method='post'></form></body></html>"
    mock_response.read.return_value = body_content

    mock_cm = MagicMock()
    mock_cm.__enter__.return_value = mock_response
    with patch("urllib.request.urlopen", return_value=mock_cm):
        result = agent.run()

    assert "evidence" in result
    assert "findings" in result

    findings_by_title = {f["title"]: f for f in result["findings"]}

    # Missing CSP: Validated, medium severity, 85 -> 95 confidence
    assert "Missing Content-Security-Policy" in findings_by_title
    csp_finding = findings_by_title["Missing Content-Security-Policy"]
    assert csp_finding["severity"] == "medium"
    assert csp_finding["initial_confidence"] == 85
    assert csp_finding["final_confidence"] == 95
    assert csp_finding["validation"]["status"] == "VALIDATED"
    assert csp_finding["validation"]["rechecked"] is True
    assert csp_finding["validation"]["evidence_reproduced"] is True

    # Missing HSTS on HTTP target: CONTEXT_DEPENDENT
    assert "Missing Strict-Transport-Security" in findings_by_title
    hsts_finding = findings_by_title["Missing Strict-Transport-Security"]
    assert hsts_finding["validation"]["status"] == "CONTEXT_DEPENDENT"
    assert hsts_finding["final_confidence"] == 60

    # Server disclosure: Validated, informational
    assert "Server technology disclosure" in findings_by_title
    server_finding = findings_by_title["Server technology disclosure"]
    assert server_finding["severity"] == "informational"
    assert server_finding["validation"]["status"] == "VALIDATED"
    assert server_finding["final_confidence"] == 100

    # M7.7 Evidence verification
    evidence = result["evidence"]
    assert evidence["authorization_verified"] is True
    assert evidence["scope_verified"] is True
    assert evidence["sha256_digest"] == hashlib.sha256(body_content).hexdigest()
    assert len(evidence["endpoints"]) > 0
    assert len(evidence["audit_trail"]) >= 5


# ==============================================================================
# M7.7 Authorization Gate Tests
# ==============================================================================

def test_authorization_status_values():
    assert AuthorizationStatus.AUTHORIZED == "AUTHORIZED"
    assert AuthorizationStatus.UNAUTHORIZED == "UNAUTHORIZED"
    assert AuthorizationStatus.EXPIRED == "EXPIRED"
    assert AuthorizationStatus.REVOKED == "REVOKED"


def test_permission_grant_validity():
    grant_valid = PermissionGrant(
        status=AuthorizationStatus.AUTHORIZED,
        authorized_by="Lead SecOps",
    )
    assert grant_valid.is_valid() is True

    grant_unauth = PermissionGrant(
        status=AuthorizationStatus.UNAUTHORIZED,
    )
    assert grant_unauth.is_valid() is False

    grant_revoked = PermissionGrant(
        status=AuthorizationStatus.REVOKED,
    )
    assert grant_revoked.is_valid() is False

    # Expired timestamp
    yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    grant_expired = PermissionGrant(
        status=AuthorizationStatus.AUTHORIZED,
        valid_until=yesterday,
    )
    assert grant_expired.is_valid() is False

    # Future timestamp
    tomorrow = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    grant_future = PermissionGrant(
        status=AuthorizationStatus.AUTHORIZED,
        valid_until=tomorrow,
    )
    assert grant_future.is_valid() is True


def test_agent_run_without_permission_denied():
    """Agent created without explicit AUTHORIZED permission must raise PermissionError on run()."""
    agent = SecurityResearchAgent(
        target="http://example.com",
        allowed_domains=["example.com"],
        # No permission provided -> defaults to UNAUTHORIZED
    )

    try:
        agent.run()
        assert False, "Expected PermissionError was not raised"
    except PermissionError as exc:
        assert "AUTHORIZATION DENIED" in str(exc)

    # Verify denial is recorded in audit trail
    denied_events = [e for e in agent.audit.events if e.event_type == "AUTHORIZATION_DENIED"]
    assert len(denied_events) > 0
    assert denied_events[0].status == "DENIED"


def test_agent_fetch_refuses_when_permission_revoked():
    """Direct fetch() call must also refuse execution when permission is revoked."""
    agent = SecurityResearchAgent(
        target="http://example.com",
        allowed_domains=["example.com"],
        permission=PermissionGrant(status=AuthorizationStatus.REVOKED),
    )

    try:
        agent.fetch()
        assert False, "Expected PermissionError was not raised"
    except PermissionError as exc:
        assert "authorization policy" in str(exc).lower() or "revoked" in str(exc).lower()


# ==============================================================================
# M7.7 Endpoint Intelligence Tests
# ==============================================================================

def test_endpoint_inventory_relative_resolution_and_dedup():
    scope = ScopeManager(["example.com"])
    inventory = EndpointInventory(base_url="https://example.com/subfolder/page.html", scope_manager=scope)

    # 1. Relative paths
    ep1 = inventory.add_endpoint("/api/v1/users", method="GET", endpoint_type="link")
    assert ep1.url == "https://example.com/api/v1/users"
    assert ep1.path == "/api/v1/users"
    assert ep1.is_in_scope is True

    # 2. Relative file
    ep2 = inventory.add_endpoint("assets/app.js", method="GET", endpoint_type="script")
    assert ep2.url == "https://example.com/subfolder/assets/app.js"

    # 3. Deduplication (same method and normalized url)
    ep1_dup = inventory.add_endpoint("/api/v1/users", method="GET")
    assert len(inventory.endpoints) == 2
    assert ep1_dup is ep1

    # Different method is distinct
    ep1_post = inventory.add_endpoint("/api/v1/users", method="POST", endpoint_type="form")
    assert len(inventory.endpoints) == 3
    assert ep1_post.method == "POST"


def test_endpoint_inventory_ignores_non_http_schemes():
    inventory = EndpointInventory(base_url="https://example.com")

    assert inventory.add_endpoint("javascript:alert(1)") is None
    assert inventory.add_endpoint("mailto:security@example.com") is None
    assert inventory.add_endpoint("tel:+1234567890") is None
    assert inventory.add_endpoint("#top-section") is None
    assert inventory.add_endpoint("data:text/html;base64,PHNjcmlwdD4=") is None
    assert len(inventory.endpoints) == 0


def test_endpoint_scope_classification():
    scope = ScopeManager(["example.com"])
    inventory = EndpointInventory(base_url="https://example.com", scope_manager=scope)

    in_scope_ep = inventory.add_endpoint("https://api.example.com/v2/items")
    assert in_scope_ep.is_in_scope is True

    out_scope_ep = inventory.add_endpoint("https://cdn.thirdparty.com/library.js")
    assert out_scope_ep.is_in_scope is False

    in_scope_list = inventory.get_in_scope()
    assert len(in_scope_list) == 1
    assert in_scope_list[0].url == "https://api.example.com/v2/items"


# ==============================================================================
# M7.7 Evidence & Cryptographic Integrity Tests
# ==============================================================================

def test_evidence_bundle_sha256_digest():
    raw_payload = b"Hello, secure DARK-EYE world! 12345"
    expected_digest = hashlib.sha256(raw_payload).hexdigest()

    bundle = EvidenceBundle(
        target="https://example.com",
        timestamp=datetime.now(timezone.utc).isoformat(),
        sha256_digest=expected_digest,
    )

    data = bundle.to_dict()
    assert data["sha256_digest"] == expected_digest
    assert len(data["sha256_digest"]) == 64


# ==============================================================================
# M7.7 Audit Trail & Reporting Tests
# ==============================================================================

def test_audit_trail_lifecycle_events():
    audit = AuditTrail(target="https://target.local")

    e1 = audit.record("SCOPE_EVALUATED", {"allowed": True}, status="OK")
    e2 = audit.record("AUTHORIZATION_CHECKED", {"status": "AUTHORIZED"}, status="OK")
    e3 = audit.record("HTTP_DISPATCHED", {"url": "https://target.local"}, status="OK")
    e4 = audit.record("FETCH_COMPLETED", {"status": 200}, status="OK")
    e5 = audit.record("FINDINGS_VALIDATED", {"total": 3}, status="OK")

    events = audit.to_list()
    assert len(events) == 5
    assert [e["event_type"] for e in events] == [
        "SCOPE_EVALUATED",
        "AUTHORIZATION_CHECKED",
        "HTTP_DISPATCHED",
        "FETCH_COMPLETED",
        "FINDINGS_VALIDATED",
    ]


def test_m77_report_serialization_with_endpoints_and_audit(tmp_path):
    """Verify that save_report writes M7.7 evidence, endpoints, and audit trail into JSON and MD."""
    result = {
        "evidence": {
            "target": "https://vault.corp.local",
            "timestamp": "2026-09-07T12:00:00Z",
            "scope_verified": True,
            "authorization_verified": True,
            "sha256_digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "program": {"program_id": "VAULT-ASSESSMENT"},
            "permission": {"status": "AUTHORIZED"},
            "endpoints": [
                {
                    "url": "https://vault.corp.local/login",
                    "path": "/login",
                    "method": "POST",
                    "endpoint_type": "form",
                    "is_in_scope": True,
                },
                {
                    "url": "https://cdn.external.com/script.js",
                    "path": "/script.js",
                    "method": "GET",
                    "endpoint_type": "script",
                    "is_in_scope": False,
                },
            ],
            "audit_trail": [
                {"event_type": "SCOPE_EVALUATED", "timestamp": "2026-09-07T12:00:01Z", "status": "OK"},
                {"event_type": "AUTHORIZATION_CHECKED", "timestamp": "2026-09-07T12:00:02Z", "status": "OK"},
            ],
        },
        "findings": [
            {
                "title": "Missing Content-Security-Policy",
                "severity": "medium",
                "confidence": 95,
                "evidence": "No CSP header found",
                "recommendation": "Deploy CSP",
                "validation": {
                    "status": "VALIDATED",
                    "rechecked": True,
                    "evidence_reproduced": True,
                    "reason": "Confirmed absent",
                },
            }
        ],
    }

    json_path, md_path = save_report(result, output_dir=str(tmp_path))

    assert json_path.exists()
    assert md_path.exists()

    md_content = md_path.read_text(encoding="utf-8")
    assert "Target: `https://vault.corp.local`" in md_content
    assert "Program ID: `VAULT-ASSESSMENT`" in md_content
    assert "Response SHA-256:" in md_content
    assert "Discovered Endpoints (Passive Inventory)" in md_content
    assert "https://vault.corp.local/login" in md_content
    assert "Research Audit Trail" in md_content
    assert "SCOPE_EVALUATED" in md_content
