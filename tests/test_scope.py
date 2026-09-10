import pytest
from pydantic import ValidationError

from scopelens.domain.scope import (
    AssessmentProject,
    AuthorizedScope,
    NetworkTarget,
    ScanProfile,
    ScopeViolation,
    WebTarget,
)


@pytest.fixture
def web_scope() -> AuthorizedScope:
    return AuthorizedScope(
        web_targets=(
            WebTarget(
                origin="https://app.example.test",
                approved_addresses=("192.0.2.2", "192.0.2.1"),
            ),
        )
    )


def test_web_permission_never_grants_network_permission(
    web_scope: AuthorizedScope,
) -> None:
    with pytest.raises(ScopeViolation):
        web_scope.authorize_network(NetworkTarget(address="192.0.2.1", ports=(443,)))


def test_network_permission_never_grants_web_permission() -> None:
    scope = AuthorizedScope(
        network_targets=(NetworkTarget(address="192.0.2.1", ports=(443,)),)
    )
    with pytest.raises(ScopeViolation):
        scope.authorize_web("https://192.0.2.1", ("192.0.2.1",))


def test_network_authorization_requires_address_and_every_port() -> None:
    scope = AuthorizedScope(
        network_targets=(NetworkTarget(address="192.0.2.1", ports=(80, 443)),)
    )
    scope.authorize_network(NetworkTarget(address="192.0.2.1", ports=(443,)))
    with pytest.raises(ScopeViolation):
        scope.authorize_network(NetworkTarget(address="192.0.2.2", ports=(443,)))
    with pytest.raises(ScopeViolation):
        scope.authorize_network(NetworkTarget(address="192.0.2.1", ports=(443, 22)))


def test_private_addresses_are_not_implicitly_authorized() -> None:
    scope = AuthorizedScope(
        network_targets=(NetworkTarget(address="127.0.0.1", ports=(8000,)),)
    )
    with pytest.raises(ScopeViolation):
        scope.authorize_network(NetworkTarget(address="10.0.0.1", ports=(8000,)))


def test_all_supplied_dns_answers_must_be_approved(web_scope: AuthorizedScope) -> None:
    web_scope.authorize_web("HTTPS://APP.EXAMPLE.TEST:443/", ("192.0.2.1",))
    web_scope.authorize_web("https://app.example.test", ("192.0.2.2", "192.0.2.1"))
    with pytest.raises(ScopeViolation):
        web_scope.authorize_web(
            "https://app.example.test", ("192.0.2.1", "203.0.113.1")
        )
    with pytest.raises(ScopeViolation):
        web_scope.authorize_web("https://app.example.test", ("203.0.113.1",))


@pytest.mark.parametrize("addresses", [(), ("::1",), ("169.254.169.254",)])
def test_empty_or_unsupported_dns_results_fail_closed(
    web_scope: AuthorizedScope, addresses: tuple[str, ...]
) -> None:
    with pytest.raises(ValueError):
        web_scope.authorize_web("https://app.example.test", addresses)


@pytest.mark.parametrize(
    "origin",
    [
        "http://app.example.test",
        "https://app.example.test:8443",
        "https://other.example.test",
        "https://sub.app.example.test",
        "https://app.example.test.attacker.test",
    ],
)
def test_shared_ip_does_not_authorize_another_origin(
    web_scope: AuthorizedScope, origin: str
) -> None:
    with pytest.raises(ScopeViolation):
        web_scope.authorize_web(origin, ("192.0.2.1",))


def test_scope_is_immutable_and_rejects_unknown_fields(
    web_scope: AuthorizedScope,
) -> None:
    with pytest.raises(ValidationError):
        web_scope.web_targets = ()
    with pytest.raises(ValidationError):
        WebTarget.model_validate(
            {
                "origin": "https://app.example.test",
                "approved_addresses": ["192.0.2.1"],
                "follow_redirects": True,
            }
        )


def test_empty_and_duplicate_scope_entries_are_rejected(
    web_scope: AuthorizedScope,
) -> None:
    with pytest.raises(ValidationError):
        AuthorizedScope()
    with pytest.raises(ValidationError):
        AuthorizedScope(web_targets=web_scope.web_targets * 2)
    with pytest.raises(ValidationError):
        AuthorizedScope(
            network_targets=(
                NetworkTarget(address="192.0.2.1", ports=(80,)),
                NetworkTarget(address="192.0.2.1", ports=(443,)),
            )
        )
    with pytest.raises(ValidationError):
        AuthorizedScope(
            web_targets=(
                web_scope.web_targets[0],
                WebTarget(
                    origin="HTTPS://APP.EXAMPLE.TEST:443/",
                    approved_addresses=("192.0.2.1",),
                ),
            )
        )


@pytest.mark.parametrize(
    "identifier", ["", "--option", "../project", "Project", "a b", "id\n"]
)
def test_project_identifiers_are_explicit_slugs(
    web_scope: AuthorizedScope, identifier: str
) -> None:
    with pytest.raises(ValidationError):
        AssessmentProject(id=identifier, name="Project", scope=web_scope)


@pytest.mark.parametrize("name", ["", "   ", "Project\nname"])
def test_project_names_cannot_be_blank_or_contain_controls(
    web_scope: AuthorizedScope, name: str
) -> None:
    with pytest.raises(ValidationError):
        AssessmentProject(id="project", name=name, scope=web_scope)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("max_targets", 0),
        ("max_targets", 17),
        ("requests_per_second", 0),
        ("requests_per_second", 6),
        ("requests_per_second", True),
        ("request_timeout_seconds", 0),
        ("request_timeout_seconds", 31),
        ("request_timeout_seconds", "10"),
        ("tcp_ports", [443, 443]),
    ],
)
def test_profile_limits_are_bounded_and_strict(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        ScanProfile.model_validate({"id": "conservative", field: value})
