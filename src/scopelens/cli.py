import argparse
import asyncio
import sys
from importlib.metadata import version
from pathlib import Path

from pydantic import ValidationError

from scopelens.adapters.base import ImportContext, ReportParseError
from scopelens.adapters.nmap import import_nmap
from scopelens.config import ConfigurationError, load_config
from scopelens.domain.scope import ScopeViolation
from scopelens.execution.nmap import scan_nmap
from scopelens.execution.process import ExecutionError


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="scopelens",
        description="ScopeLens: authorized security assessment tooling.",
        allow_abbrev=False,
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {version('scopelens')}"
    )
    commands = parser.add_subparsers(dest="command")
    validate = commands.add_parser(
        "validate-config",
        help="validate a local scope configuration without network access",
    )
    validate.add_argument("path", type=Path)
    nmap = commands.add_parser(
        "import-nmap",
        help="parse a local Nmap XML report as JSON without scanning",
        allow_abbrev=False,
    )
    nmap.add_argument("path", type=Path)
    nmap.add_argument("--profile-id", required=True)
    nmap.add_argument("--profile-revision", required=True)
    scan = commands.add_parser(
        "scan-nmap",
        help="run a bounded, authorized TCP scan on Linux",
        allow_abbrev=False,
    )
    scan.add_argument("config", type=Path)
    scan.add_argument("--profile", required=True)
    scan.add_argument("--artifacts", type=Path, default=Path(".scopelens/artifacts"))
    args = parser.parse_args(argv)
    if args.command == "validate-config":
        try:
            config = load_config(args.path)
        except ConfigurationError as exc:
            parser.error(str(exc))
        print(f"Configuration valid for project {config.project.id!r}.")
    elif args.command == "import-nmap":
        try:
            context = ImportContext(
                profile_id=args.profile_id, profile_revision=args.profile_revision
            )
        except ValidationError:
            parser.error("invalid import profile metadata")
        try:
            report = import_nmap(args.path, context)
        except ReportParseError as exc:
            parser.error(str(exc))
        print(report.model_dump_json(indent=2))
    elif args.command == "scan-nmap":
        try:
            result = asyncio.run(
                scan_nmap(load_config(args.config), args.profile, args.artifacts)
            )
        except (
            ConfigurationError,
            ExecutionError,
            ScopeViolation,
            ValidationError,
        ) as exc:
            if isinstance(exc, ExecutionError) and exc.artifacts is not None:
                parser.error(f"{exc}; private artifacts: {str(exc.artifacts)!r}")
            parser.error(str(exc))
        except KeyboardInterrupt:
            parser.exit(130, "scan cancelled; partial private artifacts retained\n")
        print(result.report.model_dump_json(indent=2))
        print(
            f"Private artifacts: {str(result.artifacts.directory)!r}", file=sys.stderr
        )
    else:
        parser.print_help()
