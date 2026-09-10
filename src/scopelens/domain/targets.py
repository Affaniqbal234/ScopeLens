import re
from ipaddress import IPv4Address
from typing import Annotated
from urllib.parse import urlsplit

from pydantic import AfterValidator, BaseModel, ConfigDict, Field


class DomainModel(BaseModel):
    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        validate_default=True,
        hide_input_in_errors=True,
    )


Identifier = Annotated[
    str, Field(strict=True, min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_-]*$")
]
Port = Annotated[int, Field(strict=True, ge=1, le=65535)]


def normalize_address(value: str) -> str:
    try:
        address = IPv4Address(value)
    except ValueError:
        raise ValueError("use an exact dotted-decimal IPv4 address") from None
    if (
        int(address) >> 24 == 0
        or address.is_multicast
        or address.is_reserved
        or address.is_link_local
    ):
        raise ValueError(
            "unspecified, multicast, reserved and link-local targets are denied"
        )
    return str(address)


def normalize_origin(value: str) -> str:
    # urlsplit strips some control characters rather than rejecting them.
    if not value.isascii() or any(
        ord(char) <= 32 or ord(char) == 127 for char in value
    ):
        raise ValueError(
            "origins must use ASCII without whitespace or control characters"
        )
    if any(char in value for char in ("\\", "?", "#")):
        raise ValueError("origins cannot contain backslashes, queries or fragments")
    if "[" in value or "]" in value:
        raise ValueError("bracketed IP literals are not supported")
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        raise ValueError("invalid HTTP(S) origin or port") from None
    if parsed.scheme not in ("http", "https") or not host:
        raise ValueError("use an absolute HTTP(S) origin")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("origins cannot contain credentials")
    if parsed.path not in ("", "/"):
        raise ValueError("scope authorizes a whole origin, not a URL path")
    if parsed.netloc.endswith(":") or port == 0:
        raise ValueError("ports must be integers from 1 to 65535")
    try:
        IPv4Address(host)
    except ValueError:
        labels = host.split(".")
        if len(host) > 253 or any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in labels
        ):
            raise ValueError("use an exact ASCII hostname or IPv4 address") from None
        # Numeric host aliases can be interpreted as IP addresses by other clients.
        if re.fullmatch(r"[0-9]+|0x[0-9a-f]*", labels[-1]):
            raise ValueError("ambiguous numeric hostnames are not supported") from None
    else:
        host = normalize_address(host)
    default_port = 80 if parsed.scheme == "http" else 443
    suffix = f":{port}" if port is not None and port != default_port else ""
    return f"{parsed.scheme}://{host}{suffix}"


def normalize_subject(value: str) -> str:
    return normalize_origin(value) if "://" in value else normalize_address(value)


def unique_ports(ports: tuple[int, ...]) -> tuple[int, ...]:
    if len(ports) != len(set(ports)):
        raise ValueError("duplicate ports are not allowed")
    return tuple(sorted(ports))


IPv4 = Annotated[str, Field(strict=True), AfterValidator(normalize_address)]
Origin = Annotated[str, Field(strict=True), AfterValidator(normalize_origin)]
TargetIdentity = Annotated[str, Field(strict=True), AfterValidator(normalize_subject)]
Ports = Annotated[tuple[Port, ...], Field(max_length=64), AfterValidator(unique_ports)]
