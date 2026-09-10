from ipaddress import IPv4Address
from typing import Annotated, Self
from urllib.parse import urlsplit

from pydantic import Field, field_validator, model_validator

from scopelens.domain.targets import (
    DomainModel,
    Identifier,
    IPv4,
    Origin,
    Ports,
)


class NetworkTarget(DomainModel):
    address: IPv4
    ports: Annotated[Ports, Field(min_length=1)]


class WebTarget(DomainModel):
    origin: Origin
    approved_addresses: Annotated[tuple[IPv4, ...], Field(min_length=1, max_length=16)]

    @field_validator("approved_addresses")
    @classmethod
    def unique_addresses(cls, addresses: tuple[str, ...]) -> tuple[str, ...]:
        if len(addresses) != len(set(addresses)):
            raise ValueError("duplicate approved addresses are not allowed")
        return tuple(sorted(addresses))

    @model_validator(mode="after")
    def match_literal_address(self) -> Self:
        try:
            address = str(IPv4Address(urlsplit(self.origin).hostname or ""))
        except ValueError:
            return self
        if self.approved_addresses != (address,):
            raise ValueError("an IP origin must approve exactly its own address")
        return self


class ScopeViolation(ValueError):
    """A requested operation exceeds its configured authorization."""


class AuthorizedScope(DomainModel):
    network_targets: Annotated[tuple[NetworkTarget, ...], Field(max_length=16)] = ()
    web_targets: Annotated[tuple[WebTarget, ...], Field(max_length=16)] = ()

    @model_validator(mode="after")
    def validate_targets(self) -> Self:
        if not self.network_targets and not self.web_targets:
            raise ValueError("scope must contain at least one explicit target")
        if len({target.address for target in self.network_targets}) != len(
            self.network_targets
        ):
            raise ValueError("duplicate network targets are not allowed")
        if len({target.origin for target in self.web_targets}) != len(self.web_targets):
            raise ValueError("duplicate web origins are not allowed")
        return self

    def authorize_network(self, target: NetworkTarget) -> None:
        for permitted in self.network_targets:
            if target.address == permitted.address and set(target.ports) <= set(
                permitted.ports
            ):
                return
        raise ScopeViolation("network address or requested ports are not authorized")

    def authorize_web(self, origin: str, resolved_addresses: tuple[str, ...]) -> None:
        """Check supplied DNS results without resolving or contacting the origin."""
        requested = WebTarget(origin=origin, approved_addresses=resolved_addresses)
        for permitted in self.web_targets:
            if requested.origin == permitted.origin:
                if set(requested.approved_addresses) <= set(
                    permitted.approved_addresses
                ):
                    return
                raise ScopeViolation(
                    "a resolved address is outside the authorized origin"
                )
        raise ScopeViolation("web origin is not authorized")


class AssessmentProject(DomainModel):
    id: Identifier
    name: Annotated[str, Field(strict=True, min_length=1, max_length=120)]
    scope: AuthorizedScope

    @field_validator("name")
    @classmethod
    def nonblank_name(cls, name: str) -> str:
        if not name.strip() or any(ord(char) < 32 or ord(char) == 127 for char in name):
            raise ValueError(
                "project names cannot be blank or contain control characters"
            )
        return name.strip()


class ScanProfile(DomainModel):
    id: Identifier
    tcp_ports: Ports = ()
    max_targets: Annotated[int, Field(strict=True, ge=1, le=16)] = 16
    requests_per_second: Annotated[int, Field(strict=True, ge=1, le=5)] = 5
    request_timeout_seconds: Annotated[int, Field(strict=True, ge=1, le=30)] = 10
