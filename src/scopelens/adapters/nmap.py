from datetime import UTC, datetime
from hashlib import sha256
from io import BytesIO
from pathlib import Path
from xml.etree.ElementTree import Element, ParseError

from defusedxml.common import DefusedXmlException, DTDForbidden
from defusedxml.ElementTree import DefusedXMLParser, iterparse
from pydantic import ValidationError

from scopelens.adapters.base import ImportContext, ParsedReport, ReportParseError
from scopelens.domain.evidence import EvidenceReference, Observation
from scopelens.domain.services import ServiceEndpoint
from scopelens.domain.targets import normalize_address

MAX_XML_BYTES = 8 * 1024 * 1024
MAX_XML_DEPTH = 32
MAX_XML_ELEMENTS = 50_000
ADAPTER_VERSION = "1"
PORT_STATES = {
    "open",
    "closed",
    "filtered",
    "unfiltered",
    "open|filtered",
    "closed|filtered",
}
HOST_STATES = {"up", "down", "unknown", "skipped"}


class _NmapXMLParser(DefusedXMLParser):
    def defused_start_doctype_decl(
        self, name: str, sysid: str | None, pubid: str | None, has_internal_subset: bool
    ) -> None:
        # Nmap emits a bare DOCTYPE; internal defaults could fabricate metadata.
        if has_internal_subset or name != "nmaprun":
            raise DTDForbidden(name, sysid, pubid)


def _xml_root(raw: bytes) -> Element:
    if len(raw) > MAX_XML_BYTES:
        raise ReportParseError("Nmap XML exceeds the 8 MiB limit")
    depth = count = 0
    root: Element | None = None
    try:
        for event, element in iterparse(
            BytesIO(raw),
            events=("start", "end"),
            parser=_NmapXMLParser(
                forbid_dtd=True, forbid_entities=True, forbid_external=True
            ),
        ):
            if event == "start":
                depth += 1
                count += 1
                if depth > MAX_XML_DEPTH or count > MAX_XML_ELEMENTS:
                    raise ReportParseError("Nmap XML exceeds structural limits")
                if root is None:
                    root = element
            else:
                depth -= 1
    except ReportParseError:
        raise
    except ParseError, DefusedXmlException, LookupError, ValueError:
        raise ReportParseError("malformed or unsafe Nmap XML") from None
    if root is None or root.tag != "nmaprun" or root.get("scanner") != "nmap":
        raise ReportParseError("expected an Nmap XML report")
    return root


def _one(parent: Element, tag: str, *, required: bool = True) -> Element | None:
    children = parent.findall(tag)
    if len(children) > 1 or (required and not children):
        raise ReportParseError(f"expected one {tag} element")
    return children[0] if children else None


def _required(parent: Element, tag: str) -> Element:
    child = _one(parent, tag)
    assert child is not None
    return child


def _integer(value: str | None, *, maximum: int) -> int:
    if value is None or not value.isascii() or not value.isdecimal():
        raise ReportParseError("expected a nonnegative integer in Nmap XML")
    if len(value) > 12 or int(value) > maximum:
        raise ReportParseError("numeric value is outside the supported range")
    return int(value)


class NmapAdapter:
    name = "nmap"
    artifact_name = "stdout.xml"
    root_locator = "/nmaprun"

    def parse(self, raw: bytes, context: ImportContext) -> ParsedReport:
        root = _xml_root(raw)
        try:
            return self._normalize(root, sha256(raw).hexdigest(), context)
        except ValidationError, ValueError, OverflowError, OSError:
            # Validation messages can contain scanner-controlled attribute values.
            raise ReportParseError("invalid or unsupported Nmap report data") from None

    def _normalize(
        self, root: Element, digest: str, context: ImportContext
    ) -> ParsedReport:
        for scaninfo in root.findall("scaninfo"):
            if scaninfo.get("protocol") not in ("tcp", "udp", "sctp"):
                raise ReportParseError("unsupported scan protocol")
        finished = _required(_required(root, "runstats"), "finished")
        captured_at = datetime.fromtimestamp(
            _integer(finished.get("time"), maximum=253402300799), UTC
        )
        evidence = EvidenceReference(
            artifact_sha256=digest,
            record_locator="/nmaprun",
            scanner="nmap",
            scanner_version=root.get("version", ""),
            adapter_version=ADAPTER_VERSION,
            profile_id=context.profile_id,
            profile_revision=context.profile_revision,
            captured_at=captured_at,
        )
        observations: list[Observation] = []
        seen_addresses: set[str] = set()
        for index, host in enumerate(root.findall("host"), 1):
            addresses = [
                a
                for a in host.findall("address")
                if a.get("addrtype", "ipv4") == "ipv4"
            ]
            if len(addresses) != 1:
                raise ReportParseError("each host must have exactly one IPv4 address")
            address = normalize_address(addresses[0].get("addr", ""))
            if address in seen_addresses:
                raise ReportParseError("duplicate host address")
            seen_addresses.add(address)
            locator = f"/nmaprun/host[{index}]"
            host_evidence = evidence
            if host.get("endtime") is not None:
                ended = datetime.fromtimestamp(
                    _integer(host.get("endtime"), maximum=253402300799), UTC
                )
                if ended > captured_at:
                    raise ReportParseError("host timestamp is after report completion")
                host_evidence = evidence.model_copy(update={"captured_at": ended})
            observations.extend(self._host(host, address, locator, host_evidence))
        return ParsedReport.model_validate(
            {
                "evidence": evidence,
                "reported_exit": finished.get("exit"),
                "observations": observations,
            }
        )

    def _host(
        self, host: Element, address: str, locator: str, evidence: EvidenceReference
    ) -> list[Observation]:
        observations: list[Observation] = []

        def emit(
            subject: str | ServiceEndpoint, key: str, value: str | int | bool, path: str
        ) -> None:
            observations.append(
                Observation(
                    subject=subject,
                    key=key,
                    value=value,
                    evidence=(evidence.model_copy(update={"record_locator": path}),),
                )
            )

        status = _required(host, "status")
        state = status.get("state", "")
        if state not in HOST_STATES:
            raise ReportParseError("unsupported host state")
        emit(address, "host.state", state, locator + "/status")
        if (reason := status.get("reason")) is not None:
            emit(address, "host.state_reason", reason, locator + "/status")
        if (timed_out := host.get("timedout")) is not None:
            if timed_out not in ("true", "false"):
                raise ReportParseError("invalid host timeout flag")
            emit(address, "host.timed_out", timed_out == "true", locator)
        hostnames = _one(host, "hostnames", required=False)
        if hostnames is not None:
            for index, hostname in enumerate(hostnames.findall("hostname"), 1):
                path = f"{locator}/hostnames/hostname[{index}]"
                if (name := hostname.get("name")) is not None:
                    emit(address, "host.name", name, path)
                if (source := hostname.get("type")) is not None:
                    emit(address, "host.name_source", source, path)
        ports = _one(host, "ports", required=False)
        if ports is None:
            return observations
        for index, summary in enumerate(ports.findall("extraports"), 1):
            state = summary.get("state", "")
            if state not in PORT_STATES:
                raise ReportParseError("unsupported port state")
            count = _integer(summary.get("count"), maximum=3 * 65536)
            emit(
                address,
                f"ports.{state.replace('|', '_or_')}.count",
                count,
                f"{locator}/ports/extraports[{index}]",
            )
        seen_services: set[ServiceEndpoint] = set()
        for index, port in enumerate(ports.findall("port"), 1):
            subject = ServiceEndpoint.model_validate(
                {
                    "address": address,
                    "transport": port.get("protocol"),
                    "port": _integer(port.get("portid"), maximum=65535),
                }
            )
            if subject in seen_services:
                raise ReportParseError("duplicate service endpoint")
            seen_services.add(subject)
            path = f"{locator}/ports/port[{index}]"
            status = _required(port, "state")
            state = status.get("state", "")
            if state not in PORT_STATES:
                raise ReportParseError("unsupported port state")
            emit(subject, "service.state", state, path + "/state")
            if (reason := status.get("reason")) is not None:
                emit(subject, "service.state_reason", reason, path + "/state")
            service = _one(port, "service", required=False)
            if service is None:
                continue
            for attribute in ("name", "product", "version", "extrainfo", "tunnel"):
                if (value := service.get(attribute)) is not None:
                    emit(subject, f"service.{attribute}", value, path + "/service")
            if (method := service.get("method")) is not None:
                if method not in ("table", "probed"):
                    raise ReportParseError("unsupported service identification method")
                emit(subject, "service.name_method", method, path + "/service")
            if service.get("conf") is not None:
                emit(
                    subject,
                    "service.name_confidence",
                    _integer(service.get("conf"), maximum=10),
                    path + "/service",
                )
            for cpe_index, cpe in enumerate(service.findall("cpe"), 1):
                if cpe.text is not None:
                    emit(
                        subject,
                        "service.cpe",
                        cpe.text,
                        f"{path}/service/cpe[{cpe_index}]",
                    )
        return observations


def import_nmap(path: Path, context: ImportContext) -> ParsedReport:
    try:
        with path.open("rb") as source:
            raw = source.read(MAX_XML_BYTES + 1)
    except OSError:
        raise ReportParseError("cannot read the Nmap XML file") from None
    return NmapAdapter().parse(raw, context)
