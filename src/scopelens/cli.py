import argparse
import asyncio
import json
import sys
from dataclasses import asdict
from datetime import datetime
from importlib.metadata import version
from pathlib import Path

from pydantic import ValidationError

from scopelens.adapters.base import ImportContext, ReportParseError
from scopelens.adapters.httpx import import_httpx
from scopelens.adapters.nmap import import_nmap
from scopelens.adapters.nuclei import import_nuclei
from scopelens.adapters.nuclei_templates import (
    NUCLEI_VERSION,
    reviewed_templates,
    template_revision,
)
from scopelens.assessment.recheck import recheck_web
from scopelens.config import ConfigurationError, load_config
from scopelens.domain.scope import ScopeViolation, WebTarget
from scopelens.execution.httpx import HTTPX_EXECUTABLE, scan_httpx
from scopelens.execution.nmap import scan_nmap
from scopelens.execution.nuclei import NUCLEI_EXECUTABLE, scan_nuclei
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
    commands.add_parser(
        "nuclei-templates", help="show the bundled reviewed template manifest"
    )
    recheck = commands.add_parser(
        "recheck-web",
        help="run the fixed deterministic web rechecks on one approved origin",
        allow_abbrev=False,
    )
    recheck.add_argument("config", type=Path)
    recheck.add_argument("--profile", required=True)
    recheck.add_argument("--origin", required=True)
    recheck.add_argument("--address", required=True)
    recheck.add_argument("--artifacts", type=Path, default=Path(".scopelens/artifacts"))
    for name, help_text in (
        ("import-httpx", "parse local httpx JSONL without scanning"),
        ("scan-httpx", "probe one authorized web origin on Linux"),
        ("import-nuclei", "parse reviewed Nuclei JSONL without scanning"),
        ("scan-nuclei", "run reviewed Nuclei HTTP checks on one approved origin"),
    ):
        web = commands.add_parser(name, help=help_text, allow_abbrev=False)
        web.add_argument("path", type=Path)
        web.add_argument("--origin", required=True)
        web.add_argument("--address", required=True)
        if name.startswith("import-"):
            web.add_argument("--profile-id", required=True)
            web.add_argument("--profile-revision", required=True)
            web.add_argument("--scanner-version", required=True)
            if name == "import-nuclei":
                web.add_argument("--template-revision", required=True)
                web.add_argument(
                    "--captured-at", type=datetime.fromisoformat, required=True
                )
        else:
            web.add_argument("--profile", required=True)
            web.add_argument(
                "--artifacts", type=Path, default=Path(".scopelens/artifacts")
            )
            if name == "scan-nuclei":
                web.add_argument("--nuclei-binary", default=NUCLEI_EXECUTABLE)
            else:
                web.add_argument("--httpx-binary", default=HTTPX_EXECUTABLE)
    from scopelens.storage.cli import add_commands, run_assessment, run_history

    api = commands.add_parser(
        "api-serve",
        help="serve the authenticated local assessment API",
        allow_abbrev=False,
    )
    api.add_argument("config", type=Path)
    api.add_argument("--artifacts", type=Path, default=Path(".scopelens/history"))
    from scopelens.api.cli import local_port

    api.add_argument("--port", type=local_port, default=8000)
    api.add_argument("--cors-origin", action="append", default=[])

    add_commands(commands)
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
    elif args.command == "nuclei-templates":
        print(
            json.dumps(
                {
                    "scanner_version": NUCLEI_VERSION,
                    "revision": template_revision(),
                    "templates": [asdict(item) for item in reviewed_templates()],
                },
                indent=2,
            )
        )
    elif args.command == "recheck-web":
        try:
            target = WebTarget(origin=args.origin, approved_addresses=(args.address,))
            recheck_result = asyncio.run(
                recheck_web(
                    load_config(args.config), args.profile, args.artifacts, target
                )
            )
        except (
            ConfigurationError,
            ExecutionError,
            ScopeViolation,
        ) as exc:
            if isinstance(exc, ExecutionError) and exc.artifacts is not None:
                parser.error(f"{exc}; private artifacts: {str(exc.artifacts)!r}")
            parser.error(str(exc))
        except ValidationError:
            parser.error("invalid web target or assessment data")
        except KeyboardInterrupt:
            parser.exit(
                130, "recheck cancelled; any partial private artifacts were retained\n"
            )
        print(recheck_result.model_dump_json(indent=2))
    elif args.command in ("import-httpx", "scan-httpx", "import-nuclei", "scan-nuclei"):
        try:
            target = WebTarget(origin=args.origin, approved_addresses=(args.address,))
            if args.command.startswith("import-"):
                importer = (
                    import_nuclei if args.command == "import-nuclei" else import_httpx
                )
                report = importer(
                    args.path,
                    ImportContext(
                        profile_id=args.profile_id,
                        profile_revision=args.profile_revision,
                        scanner_version=args.scanner_version,
                        web_target=target,
                        template_revision=getattr(args, "template_revision", None),
                        captured_at=getattr(args, "captured_at", None),
                    ),
                )
            else:
                scanner = scan_nuclei if args.command == "scan-nuclei" else scan_httpx
                result = asyncio.run(
                    scanner(
                        load_config(args.path),
                        args.profile,
                        args.artifacts,
                        target,
                        args.nuclei_binary
                        if args.command == "scan-nuclei"
                        else args.httpx_binary,
                    )
                )
                report = result.report
                print(
                    f"Private artifacts: {str(result.artifacts.directory)!r}",
                    file=sys.stderr,
                )
        except (
            ConfigurationError,
            ReportParseError,
            ScopeViolation,
            ExecutionError,
        ) as exc:
            if isinstance(exc, ExecutionError) and exc.artifacts is not None:
                parser.error(f"{exc}; private artifacts: {str(exc.artifacts)!r}")
            parser.error(str(exc))
        except ValidationError:
            parser.error("invalid web target or scanner metadata")
        except KeyboardInterrupt:
            parser.exit(130, "scan cancelled; partial private artifacts retained\n")
        print(report.model_dump_json(indent=2))
    elif args.command and args.command.startswith("history-"):
        run_history(args, parser)
    elif args.command and args.command.startswith("assessment-"):
        run_assessment(args, parser)
    elif args.command == "api-serve":
        from scopelens.api.cli import run_api

        run_api(args, parser)
    else:
        parser.print_help()
