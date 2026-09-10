from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from scopelens.domain.evidence import EvidenceReference, Observation
from scopelens.domain.services import ServiceEndpoint


@pytest.fixture
def evidence() -> EvidenceReference:
    return EvidenceReference(
        artifact_sha256="a" * 64,
        record_locator="record:1",
        scanner="fixture",
        scanner_version="1.0",
        adapter_version="1.0",
        profile_id="conservative",
        profile_revision="1",
        captured_at=datetime(2026, 9, 10, tzinfo=UTC),
    )


def test_observation_retains_evidence_and_canonical_identity(
    evidence: EvidenceReference,
) -> None:
    observation = Observation(
        subject="HTTPS://APP.EXAMPLE.TEST:443/",
        key="http.status",
        value=200,
        evidence=(evidence,),
    )
    assert observation.subject == "https://app.example.test"
    assert observation.evidence == (evidence,)
    assert Observation.model_validate_json(observation.model_dump_json()) == observation
    with pytest.raises(ValidationError):
        observation.subject = "https://other.example.test"
    with pytest.raises(ValidationError):
        evidence.scanner_version = "2.0"


@pytest.mark.parametrize("value", [True, 200, 1.5, "banner"])
def test_observation_values_preserve_scalar_types(
    evidence: EvidenceReference, value: object
) -> None:
    observation = Observation.model_validate(
        {
            "subject": "192.0.2.1",
            "key": "service.banner",
            "value": value,
            "evidence": [evidence],
        }
    )
    assert type(observation.value) is type(value)


@pytest.mark.parametrize("value", [None, [], {}, float("inf"), float("nan")])
def test_rejects_unsupported_observation_values(
    evidence: EvidenceReference, value: object
) -> None:
    with pytest.raises(ValidationError):
        Observation.model_validate(
            {
                "subject": "192.0.2.1",
                "key": "service.banner",
                "value": value,
                "evidence": [evidence],
            }
        )


def test_observation_requires_source_evidence() -> None:
    with pytest.raises(ValidationError):
        Observation(
            subject="192.0.2.1", key="service.banner", value="example", evidence=()
        )


def test_service_subject_keeps_address_transport_and_port(
    evidence: EvidenceReference,
) -> None:
    subject = ServiceEndpoint(address="192.0.2.1", transport="tcp", port=443)
    observation = Observation(
        subject=subject, key="service.state", value="open", evidence=(evidence,)
    )
    assert Observation.model_validate_json(observation.model_dump_json()) == observation
    assert subject != ServiceEndpoint(address="192.0.2.1", transport="udp", port=443)
    assert subject != ServiceEndpoint(address="192.0.2.1", transport="tcp", port=80)


@pytest.mark.parametrize(
    "field,value",
    [
        ("port", 0),
        ("port", 65536),
        ("port", True),
        ("port", "443"),
        ("transport", "ip"),
        ("address", "example.test"),
    ],
)
def test_service_subject_rejects_invalid_identity(field: str, value: object) -> None:
    data: dict[str, object] = {"address": "192.0.2.1", "transport": "tcp", "port": 443}
    data[field] = value
    with pytest.raises(ValidationError):
        ServiceEndpoint.model_validate(data)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("artifact_sha256", "a" * 63),
        ("artifact_sha256", "z" * 64),
        ("record_locator", ""),
        ("record_locator", "   "),
        ("scanner_version", ""),
        ("profile_revision", ""),
        ("captured_at", datetime(2026, 9, 10)),
        ("captured_at", "not-a-timestamp"),
    ],
)
def test_evidence_requires_valid_provenance(
    evidence: EvidenceReference, field: str, value: object
) -> None:
    data = evidence.model_dump()
    data[field] = value
    with pytest.raises(ValidationError):
        EvidenceReference.model_validate(data)
