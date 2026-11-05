from dataclasses import asdict
from unittest.mock import patch, MagicMock
from backend.security_research.agent import (
    ScopeManager,
    SecurityResearchAgent,
    Finding,
    save_report,
)
from backend.security_research.validator import (
    FindingValidator,
    ValidationStatus,
    Observation,
    ValidationResult,
)


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
    # Finding initialized with 5 positional arguments (M7.5 style)
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

    # Report saving functionality preserves format and incorporates validation details
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
    """Test full SecurityResearchAgent.run() flow with mock HTTP response."""
    agent = SecurityResearchAgent(
        target="http://example.com",
        allowed_domains=["example.com"],
    )

    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.geturl.return_value = "http://example.com/"
    mock_response.headers = {
        "Server": "nginx/1.19",
        "Content-Type": "text/html",
    }
    mock_response.read.return_value = b"<html><head><title>Test</title></head><body><form action='/login'></form></body></html>"

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

