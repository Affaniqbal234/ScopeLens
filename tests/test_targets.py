import pytest
from pydantic import TypeAdapter, ValidationError

from scopelens.domain.scope import NetworkTarget, WebTarget
from scopelens.domain.targets import IPv4, Origin


@pytest.mark.parametrize("address", ["127.0.0.1", "10.0.0.4", "192.0.2.10", "8.8.8.8"])
def test_exact_ipv4_addresses(address: str) -> None:
    assert TypeAdapter(IPv4).validate_python(address) == address


@pytest.mark.parametrize(
    "address",
    [
        "",
        "example.test",
        "192.0.2.0/24",
        "192.0.2.1-10",
        "::1",
        "::ffff:127.0.0.1",
        "127.1",
        "2130706433",
        "0x7f000001",
        "0177.0.0.1",
        "127.0.0.01",
        " 127.0.0.1",
        "127.0.0.1\n",
        "--help",
        "0.0.0.0",
        "0.1.2.3",
        "169.254.169.254",
        "224.0.0.1",
        "240.0.0.1",
        "255.255.255.255",
        2130706433,
        True,
    ],
)
def test_rejects_invalid_or_denied_addresses(address: object) -> None:
    with pytest.raises(ValidationError):
        TypeAdapter(IPv4).validate_python(address)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("HTTPS://App.Example.test:443/", "https://app.example.test"),
        ("http://APP.example.test:80", "http://app.example.test"),
        ("http://app.example.test:443", "http://app.example.test:443"),
        ("https://app.example.test:8443/", "https://app.example.test:8443"),
        ("http://127.0.0.1:8000", "http://127.0.0.1:8000"),
        ("http://localhost", "http://localhost"),
    ],
)
def test_canonical_origin_identity(value: str, expected: str) -> None:
    adapter = TypeAdapter(Origin)
    assert adapter.validate_python(value) == expected
    assert adapter.validate_python(expected) == expected


@pytest.mark.parametrize(
    "origin",
    [
        "",
        "app.example.test",
        "//app.example.test",
        "ftp://app.example.test",
        "https:///app.example.test",
        "https://user:secret@app.example.test",
        "https://@app.example.test",
        "https://app.example.test/path",
        "https://app.example.test?",
        "https://app.example.test?token=secret",
        "https://app.example.test#",
        "https://app.example.test:0",
        "https://app.example.test:65536",
        "https://app.example.test:-1",
        "https://app.example.test:invalid",
        "https://app.example.test:",
        " https://app.example.test",
        "https://app.exa\nmple.test",
        "https://app.exa\tmple.test",
        "https://app.example.test\x7f",
        "https://app.example.test\\@elsewhere.test",
        "https://*.example.test",
        "https://-option.test",
        "https://app..example.test",
        "https://app.example.test.",
        "https://[::1]",
        "http://127.1",
        "http://2130706433",
        "http://0x7f000001",
        "http://0x",
        "http://app.0x",
        "http://0177.0.0.1",
        "http://127.0.0.01",
        "http://%31%32%37.0.0.1",
        "http://169.254.169.254",
        "http://224.0.0.1",
        "https://exämple.test",
        "https://" + "a" * 64 + ".test",
        42,
        True,
    ],
)
def test_rejects_ambiguous_or_unsupported_origins(origin: object) -> None:
    with pytest.raises(ValidationError):
        TypeAdapter(Origin).validate_python(origin)


@pytest.mark.parametrize(
    "origin", ["https://[v1.example]", "https://[v1.app.example.test]:443"]
)
def test_bracketed_ip_literals_do_not_become_hostname_origins(origin: str) -> None:
    with pytest.raises(ValidationError):
        TypeAdapter(Origin).validate_python(origin)


@pytest.mark.parametrize("port", [0, -1, 65536, "80", 80.0, True, None])
def test_ports_require_bounded_integers(port: object) -> None:
    with pytest.raises(ValidationError):
        NetworkTarget.model_validate({"address": "127.0.0.1", "ports": [port]})


def test_ports_have_stable_order_and_preserve_boundaries() -> None:
    target = NetworkTarget(address="127.0.0.1", ports=(65535, 443, 1))
    assert target.ports == (1, 443, 65535)


@pytest.mark.parametrize("ports", [(), (80, 80), tuple(range(1, 66))])
def test_rejects_empty_duplicate_or_excessive_ports(ports: tuple[int, ...]) -> None:
    with pytest.raises(ValidationError):
        NetworkTarget(address="127.0.0.1", ports=ports)


@pytest.mark.parametrize("addresses", [(), ("192.0.2.1", "192.0.2.1")])
def test_web_target_requires_unique_approved_addresses(
    addresses: tuple[str, ...],
) -> None:
    with pytest.raises(ValidationError):
        WebTarget(origin="https://app.example.test", approved_addresses=addresses)


def test_ip_origin_cannot_approve_another_address() -> None:
    with pytest.raises(ValidationError):
        WebTarget(origin="http://127.0.0.1", approved_addresses=("192.0.2.1",))
    with pytest.raises(ValidationError):
        WebTarget(
            origin="http://127.0.0.1", approved_addresses=("127.0.0.1", "192.0.2.1")
        )
    assert (
        WebTarget(origin="http://127.0.0.1", approved_addresses=("127.0.0.1",)).origin
        == "http://127.0.0.1"
    )
