import tomllib
from pathlib import Path
from typing import Annotated, Self

from pydantic import Field, ValidationError, model_validator

from scopelens.domain.scope import AssessmentProject, NetworkTarget, ScanProfile
from scopelens.domain.targets import DomainModel

MAX_CONFIG_BYTES = 1024 * 1024


class ProjectConfig(DomainModel):
    project: AssessmentProject
    profiles: Annotated[tuple[ScanProfile, ...], Field(min_length=1, max_length=16)]

    @model_validator(mode="after")
    def validate_profiles(self) -> Self:
        if len({profile.id for profile in self.profiles}) != len(self.profiles):
            raise ValueError("duplicate profile identifiers are not allowed")
        scope = self.project.scope
        target_count = len(scope.network_targets) + len(scope.web_targets)
        addresses = {target.address for target in scope.network_targets}
        addresses.update(
            address
            for target in scope.web_targets
            for address in target.approved_addresses
        )
        for profile in self.profiles:
            if max(target_count, len(addresses)) > profile.max_targets:
                raise ValueError("scope exceeds a profile's target limit")
            if bool(profile.tcp_ports) != bool(scope.network_targets):
                raise ValueError("TCP ports require network targets, and vice versa")
            for target in scope.network_targets:
                scope.authorize_network(
                    NetworkTarget(address=target.address, ports=profile.tcp_ports)
                )
        return self


class ConfigurationError(ValueError):
    """A local configuration file could not be loaded or validated."""


def load_config(path: Path) -> ProjectConfig:
    try:
        with path.open("rb") as source:
            raw = source.read(MAX_CONFIG_BYTES + 1)
    except OSError:
        raise ConfigurationError("cannot read the configuration file") from None
    if len(raw) > MAX_CONFIG_BYTES:
        raise ConfigurationError("configuration exceeds the 1 MiB limit")
    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except UnicodeDecodeError, tomllib.TOMLDecodeError:
        raise ConfigurationError("configuration must be valid UTF-8 TOML") from None
    try:
        return ProjectConfig.model_validate(data)
    except ValidationError as exc:
        error = exc.errors(
            include_url=False, include_context=False, include_input=False
        )[0]
        location = ".".join(str(part) for part in error["loc"]) or "configuration"
        raise ConfigurationError(f"invalid {location!a}: {error['msg']}") from None
