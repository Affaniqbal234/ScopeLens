import socket
import subprocess
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from xml.etree import ElementTree

import pytest

from scopelens.adapters import nmap
from scopelens.adapters.base import (
    ImportContext,
    ParsedReport,
    ReportParseError,
    ScannerAdapter,
)
from scopelens.adapters.nmap import NmapAdapter, import_nmap
from scopelens.domain.services import ServiceEndpoint

FIXTURES = Path(__file__).parent / "fixtures" / "nmap"


@pytest.fixture
def context() -> ImportContext:
    return ImportContext(profile_id="fixture", profile_revision="1")


@pytest.fixture
def raw() -> bytes:
    return (FIXTURES / "services.xml").read_bytes()


def test_adapter_preserves_states_metadata_and_evidence(
    raw: bytes, context: ImportContext
) -> None:
    adapter: ScannerAdapter = NmapAdapter()
    report = adapter.parse(raw, context)
    assert report.reported_exit == "success"
    assert report.evidence.artifact_sha256 == sha256(raw).hexdigest()
    assert report.evidence.scanner == "nmap"
    assert report.evidence.scanner_version == "7.95"
    assert report.evidence.adapter_version == nmap.ADAPTER_VERSION
    assert report.evidence.profile_id == "fixture"
    assert report.evidence.profile_revision == "1"
    assert report.evidence.captured_at == datetime.fromtimestamp(1700000010, UTC)
    states = {
        item.subject.port: item.value
        for item in report.observations
        if item.key == "service.state" and isinstance(item.subject, ServiceEndpoint)
    }
    assert states == {
        22: "open",
        25: "closed",
        80: "filtered",
        81: "unfiltered",
        82: "open|filtered",
        83: "closed|filtered",
    }
    ssh = {
        item.key: item.value
        for item in report.observations
        if isinstance(item.subject, ServiceEndpoint) and item.subject.port == 22
    }
    assert ssh == {
        "service.state": "open",
        "service.state_reason": "syn-ack",
        "service.name": "ssh",
        "service.product": "Example SSH",
        "service.version": "1.2",
        "service.extrainfo": "lab only",
        "service.name_method": "probed",
        "service.name_confidence": 10,
        "service.cpe": "cpe:/a:example:ssh:1.2",
    }
    root = ElementTree.fromstring(raw)
    for item in report.observations:
        reference = item.evidence[0]
        assert reference.artifact_sha256 == report.evidence.artifact_sha256
        assert (
            root.find("." + reference.record_locator.removeprefix("/nmaprun"))
            is not None
        )
        expected_time = 1700000005 if item.subject != "192.0.2.11" else 1700000010
        assert reference.captured_at == datetime.fromtimestamp(expected_time, UTC)
    assert ParsedReport.model_validate_json(report.model_dump_json()) == report
    assert report == adapter.parse(raw, context)


def test_missing_metadata_is_not_a_negative_observation(
    raw: bytes, context: ImportContext
) -> None:
    report = NmapAdapter().parse(raw, context)
    smtp = {
        item.key: item.value
        for item in report.observations
        if isinstance(item.subject, ServiceEndpoint) and item.subject.port == 25
    }
    assert smtp["service.name_method"] == "table"
    assert smtp["service.name_confidence"] == 3
    assert "service.version" not in smtp
    filtered = [
        item
        for item in report.observations
        if isinstance(item.subject, ServiceEndpoint) and item.subject.port == 80
    ]
    assert {item.key for item in filtered} == {"service.state", "service.state_reason"}
    down = {
        item.key: item.value
        for item in report.observations
        if item.subject == "192.0.2.11"
    }
    assert down == {"host.state": "down", "host.state_reason": "no-response"}
    assert any(
        item.key == "host.timed_out" and item.value is False
        for item in report.observations
    )
    summary = next(
        item for item in report.observations if item.key == "ports.closed.count"
    )
    assert summary.value == 2
    assert summary.subject == "192.0.2.10"
    assert not any(
        isinstance(item.subject, ServiceEndpoint) and item.subject.port in (443, 8000)
        for item in report.observations
    )


def test_empty_report_keeps_provenance_without_inventing_hosts(
    context: ImportContext,
) -> None:
    report = import_nmap(FIXTURES / "empty.xml", context)
    assert report.observations == ()
    assert (
        report.evidence.artifact_sha256
        == sha256((FIXTURES / "empty.xml").read_bytes()).hexdigest()
    )


def test_transport_and_missing_exit_status_remain_distinct(
    context: ImportContext,
) -> None:
    report = import_nmap(FIXTURES / "minimal.xml", context)
    assert report.reported_exit is None
    assert {
        (item.subject.transport, item.value)
        for item in report.observations
        if isinstance(item.subject, ServiceEndpoint) and item.key == "service.state"
    } == {("udp", "open|filtered"), ("tcp", "closed")}


def test_error_and_timeout_are_retained(raw: bytes, context: ImportContext) -> None:
    report = NmapAdapter().parse(
        raw.replace(b'exit="success"', b'exit="error"').replace(
            b'timedout="false"', b'timedout="true"'
        ),
        context,
    )
    assert report.reported_exit == "error"
    assert any(
        item.key == "host.timed_out" and item.value is True
        for item in report.observations
    )


@pytest.mark.parametrize(
    "raw",
    [b"", b"not XML", b"<nmaprun", b"<nmaprun/>", b"<other/>", b"\x1f\x8bcompressed"],
)
def test_rejects_malformed_reports(raw: bytes, context: ImportContext) -> None:
    with pytest.raises(ReportParseError):
        NmapAdapter().parse(raw, context)


@pytest.mark.parametrize(
    "old,new",
    [
        (b"</nmaprun>", b""),
        (b"</host>", b"</wrong>"),
        (b'scanner="nmap"', b'scanner="other"'),
        (b'version="7.95"', b'version=""'),
        (b'exit="success"', b'exit="other"'),
        (b'time="1700000010"', b'time="NaN"'),
        (b'time="1700000010"', b'time="999999999999999999999"'),
        (b'endtime="1700000005"', b'endtime="1700000011"'),
        (b'portid="22"', b'portid="0"'),
        (b'portid="22"', b'portid="65536"'),
        (b'portid="22"', b'portid="+22"'),
        (b'portid="22"', b'portid="22.0"'),
        (b'protocol="tcp"', b'protocol="ip"'),
        (b'addr="192.0.2.10"', b'addr="169.254.169.254"'),
        (b'addr="192.0.2.10"', b'addr="example.test"'),
        (b'addrtype="ipv4"', b'addrtype="ipv6"'),
        (b'state="up"', b'state="maybe"'),
        (b'state="open"', b'state="maybe"'),
        (b'timedout="false"', b'timedout="0"'),
        (b'method="probed"', b'method="guessed"'),
        (b'conf="10"', b'conf="11"'),
        (b'count="2"', b'count="-1"'),
        (b"<runstats>", b"<ignored>"),
        (b"</runstats>", b"</ignored>"),
        (b'<status state="up" reason="syn-ack" reason_ttl="64"/>', b""),
        (b'<state state="open" reason="syn-ack" reason_ttl="64"/>', b""),
    ],
)
def test_rejects_invalid_or_unsupported_data(
    raw: bytes, context: ImportContext, old: bytes, new: bytes
) -> None:
    assert old in raw
    with pytest.raises(ReportParseError):
        NmapAdapter().parse(raw.replace(old, new), context)


@pytest.mark.parametrize(
    "tag", ["host", "status", "ports", "service", "port", "runstats", "finished"]
)
def test_rejects_ambiguous_duplicate_records(
    raw: bytes, context: ImportContext, tag: str
) -> None:
    root = ElementTree.fromstring(raw)
    for parent in root.iter():
        child = parent.find(tag)
        if child is not None:
            parent.append(child)
            break
    else:
        pytest.fail("fixture has no matching element")
    with pytest.raises(ReportParseError):
        NmapAdapter().parse(ElementTree.tostring(root), context)


@pytest.mark.parametrize(
    "declaration",
    [
        '<!ENTITY attack "expanded">',
        '<!ENTITY attack SYSTEM "file:///nonexistent/secret.txt">',
        '<!ENTITY attack SYSTEM "https://example.test/secret">',
        '<!ENTITY % attack SYSTEM "https://example.test/remote.dtd">%attack;',
        '<!ENTITY a "ha"><!ENTITY attack "&a;&a;&a;&a;">',
    ],
)
@pytest.mark.parametrize("encoding", ["utf-8", "utf-16"])
def test_entities_are_rejected(
    raw: bytes, context: ImportContext, declaration: str, encoding: str
) -> None:
    document = raw.decode().replace('encoding="UTF-8"', f'encoding="{encoding}"')
    document = document.replace(
        "<!DOCTYPE nmaprun>", f"<!DOCTYPE nmaprun [{declaration}]>"
    )
    document = document.replace("lab.example.test", "&attack;")
    with pytest.raises(ReportParseError, match="unsafe"):
        NmapAdapter().parse(document.encode(encoding), context)


def test_parser_never_opens_external_resources_or_executes(
    raw: bytes,
    context: ImportContext,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("parser must not access files, network, DNS, or processes")

    monkeypatch.setattr("builtins.open", forbidden)
    monkeypatch.setattr(Path, "open", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "gethostbyname", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    external_dtd = raw.replace(
        b"<!DOCTYPE nmaprun>",
        b'<!DOCTYPE nmaprun SYSTEM "https://example.test/external.dtd">',
    )
    assert NmapAdapter().parse(external_dtd, context).observations
    xinclude = raw.replace(
        b"</nmaprun>",
        b'<xi:include xmlns:xi="http://www.w3.org/2001/XInclude" href="file:///nonexistent/secret.txt" parse="text"/></nmaprun>',
    )
    assert NmapAdapter().parse(xinclude, context).observations


def test_size_limit_applies_to_bytes_and_file(
    raw: bytes, context: ImportContext, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(nmap, "MAX_XML_BYTES", len(raw))
    assert NmapAdapter().parse(raw, context).observations
    with pytest.raises(ReportParseError, match="limit"):
        NmapAdapter().parse(raw + b" ", context)
    path = tmp_path / "oversized.xml"
    path.write_bytes(raw + b" " * 100)
    with pytest.raises(ReportParseError, match="limit"):
        import_nmap(path, context)


@pytest.mark.parametrize("limit", ["MAX_XML_DEPTH", "MAX_XML_ELEMENTS"])
def test_structural_limits(
    raw: bytes, context: ImportContext, monkeypatch: pytest.MonkeyPatch, limit: str
) -> None:
    monkeypatch.setattr(nmap, limit, 2)
    with pytest.raises(ReportParseError, match="structural"):
        NmapAdapter().parse(raw, context)


def test_missing_file_is_reported(context: ImportContext, tmp_path: Path) -> None:
    with pytest.raises(ReportParseError, match="cannot read"):
        import_nmap(tmp_path / "missing.xml", context)


def test_ignored_sections_do_not_invent_observations(
    raw: bytes, context: ImportContext
) -> None:
    plain = NmapAdapter().parse(raw, context)
    with_extras = raw.replace(
        b"</host>",
        b'<hostscript><script id="example" output="CVE-2000-0000"/></hostscript><os><osmatch name="Example OS" accuracy="100"/></os><future value="untrusted"/></host>',
    )
    changed = NmapAdapter().parse(with_extras, context)
    assert [(o.subject, o.key, o.value) for o in changed.observations] == [
        (o.subject, o.key, o.value) for o in plain.observations
    ]
    assert changed.evidence.artifact_sha256 != plain.evidence.artifact_sha256


@pytest.mark.parametrize("encoding", [b"unknown-encoding", b"UTF-7", b"UTF-32"])
def test_unsupported_encodings_return_parse_errors(
    raw: bytes, context: ImportContext, encoding: bytes
) -> None:
    with pytest.raises(ReportParseError, match="malformed"):
        NmapAdapter().parse(raw.replace(b"UTF-8", encoding), context)


def test_utf16_report_preserves_observations(
    raw: bytes, context: ImportContext
) -> None:
    encoded = (
        raw.decode().replace('encoding="UTF-8"', 'encoding="UTF-16"').encode("utf-16")
    )
    original = NmapAdapter().parse(raw, context)
    report = NmapAdapter().parse(encoded, context)
    assert [(item.subject, item.key, item.value) for item in report.observations] == [
        (item.subject, item.key, item.value) for item in original.observations
    ]
    assert report.evidence.artifact_sha256 == sha256(encoded).hexdigest()


def test_internal_dtd_cannot_supply_missing_metadata(
    raw: bytes, context: ImportContext
) -> None:
    document = raw.replace(
        b"<!DOCTYPE nmaprun>",
        b'<!DOCTYPE nmaprun [<!ATTLIST service product CDATA "fabricated">]>',
    )
    with pytest.raises(ReportParseError, match="unsafe"):
        NmapAdapter().parse(document, context)


def test_ip_protocol_summary_is_not_a_port_count(context: ImportContext) -> None:
    document = b"""<nmaprun scanner="nmap" version="7.95">
      <scaninfo type="ipproto" protocol="ip" numservices="256" services="0-255"/>
      <host><status state="up"/><address addr="192.0.2.1"/>
        <ports><extraports state="closed" count="256"/></ports>
      </host><runstats><finished time="1700000010"/></runstats>
    </nmaprun>"""
    with pytest.raises(ReportParseError):
        NmapAdapter().parse(document, context)


def test_summary_can_span_multiple_transport_protocols(
    raw: bytes, context: ImportContext
) -> None:
    document = raw.replace(b'count="2"', b'count="131070"')
    report = NmapAdapter().parse(document, context)
    assert (
        next(
            item.value
            for item in report.observations
            if item.key == "ports.closed.count"
        )
        == 131070
    )


def test_empty_optional_value_is_preserved(raw: bytes, context: ImportContext) -> None:
    report = NmapAdapter().parse(raw.replace(b'version="1.2"', b'version=""'), context)
    assert (
        next(
            item.value for item in report.observations if item.key == "service.version"
        )
        == ""
    )
