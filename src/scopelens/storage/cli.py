import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from uuid import UUID

from pydantic import ValidationError
from sqlalchemy.exc import SQLAlchemyError

from scopelens.adapters.base import ReportParseError
from scopelens.config import ConfigurationError, load_config
from scopelens.domain.scope import ScopeViolation, WebTarget
from scopelens.execution.httpx import HTTPX_EXECUTABLE
from scopelens.execution.nuclei import NUCLEI_EXECUTABLE
from scopelens.execution.process import ExecutionError
from scopelens.storage.artifacts import ArtifactError, ArtifactStore
from scopelens.storage.database import HistoryError, database, migrate
from scopelens.storage.history import History
from scopelens.storage.operations import import_history, scan_history


def run_history(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    url = os.environ.get("SCOPELENS_DATABASE_URL")
    if not url:
        parser.error("set SCOPELENS_DATABASE_URL to your PostgreSQL connection URL")
    try:
        engine = database(url)
    except ValueError, SQLAlchemyError:
        parser.error("invalid PostgreSQL connection configuration")
    try:
        if args.command == "history-init":
            migrate(engine)
            print("History database migrated.")
            return
        history = History(engine, ArtifactStore(args.artifacts))
        if args.command in ("history-import", "history-scan"):
            print(f"Run ID: {args.run_id}", file=sys.stderr)
            config = load_config(args.config)
            target = (
                WebTarget(origin=args.origin, approved_addresses=(args.address,))
                if args.origin or args.address
                else None
            )
            if args.command == "history-import":
                report = import_history(
                    history,
                    config,
                    args.profile,
                    args.run_id,
                    args.path,
                    scanner=args.scanner,
                    web_target=target,
                    scanner_version=args.scanner_version,
                    template_bundle=args.template_revision,
                    captured_at=args.captured_at,
                )
            else:
                report = scan_history(
                    history,
                    config,
                    args.profile,
                    args.run_id,
                    scanner=args.scanner,
                    web_target=target,
                    binary=args.nuclei_binary
                    if args.scanner == "nuclei"
                    else args.httpx_binary,
                )
            print(report.model_dump_json(indent=2))
        elif args.command == "history-list":
            print(json.dumps(history.list_runs(args.project), default=str, indent=2))
        elif args.command == "history-show":
            print(history.report(args.run_id).model_dump_json(indent=2))
        elif args.command == "history-reconcile":
            print(json.dumps(history.reconcile(), indent=2))
    except (
        HistoryError,
        ArtifactError,
        ConfigurationError,
        ScopeViolation,
        ReportParseError,
        ExecutionError,
    ) as exc:
        parser.error(str(exc))
    except ValidationError:
        parser.error("invalid history input or stored domain data")
    except SQLAlchemyError:
        parser.error("database operation failed; retry or reconcile using the run ID")
    except OSError:
        parser.error(
            "artifact operation failed; retain files and reconcile using the run ID"
        )
    except KeyboardInterrupt:
        parser.exit(
            130, "operation interrupted; use history-reconcile before retrying\n"
        )
    finally:
        engine.dispose()


def add_commands(commands: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    for name, help_text in (
        ("history-init", "apply PostgreSQL history migrations"),
        ("history-import", "persist an authorized scanner report"),
        ("history-scan", "run a scanner with persistent history on Linux"),
        ("history-list", "list a project's persisted runs"),
        ("history-show", "read a persisted normalized report"),
        (
            "history-reconcile",
            "check artifact health and mark abandoned runs interrupted",
        ),
    ):
        command = commands.add_parser(name, help=help_text, allow_abbrev=False)
        command.add_argument(
            "--artifacts", type=Path, default=Path(".scopelens/history")
        )
        if name in ("history-import", "history-scan"):
            command.add_argument("config", type=Path)
            command.add_argument("--profile", required=True)
            command.add_argument("--run-id", type=UUID, required=True)
            command.add_argument(
                "--scanner", choices=("nmap", "httpx", "nuclei"), default="nmap"
            )
            command.add_argument("--origin")
            command.add_argument("--address")
        if name == "history-import":
            command.add_argument("path", type=Path)
            command.add_argument("--scanner-version")
            command.add_argument("--template-revision")
            command.add_argument("--captured-at", type=datetime.fromisoformat)
        if name == "history-scan":
            command.add_argument("--httpx-binary", default=HTTPX_EXECUTABLE)
            command.add_argument("--nuclei-binary", default=NUCLEI_EXECUTABLE)
        if name == "history-list":
            command.add_argument("--project", required=True)
        if name == "history-show":
            command.add_argument("run_id", type=UUID)
