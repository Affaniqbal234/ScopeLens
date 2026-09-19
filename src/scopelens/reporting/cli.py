import argparse
import os
from pathlib import Path
from uuid import UUID

from pydantic import ValidationError
from sqlalchemy.exc import SQLAlchemyError

from scopelens.analysis.correlation import CorrelationError
from scopelens.comparison.compare import ComparisonError
from scopelens.orchestration.store import OrchestrationStore
from scopelens.storage.artifacts import ArtifactError, ArtifactStore
from scopelens.storage.database import HistoryError, database

from .io import ReportOutputError, write_new
from .models import RecheckSelection, Report, ReportSelection, StoredRunSelection
from .render import render_html, render_json
from .service import load_assessment_report, load_comparison_report
from .snapshot import build_public_snapshot


def recheck_selection(value: str) -> RecheckSelection:
    try:
        assessment, stage = value.split(":", 1)
        return RecheckSelection(assessment_id=UUID(assessment), stage_id=UUID(stage))
    except ValueError, ValidationError:
        raise argparse.ArgumentTypeError(
            "use ASSESSMENT_UUID:STAGE_UUID for a persisted recheck"
        ) from None


def _selection(args: argparse.Namespace, side: str) -> ReportSelection:
    run_ids = getattr(args, f"{side}_run_id")
    recheck = getattr(args, f"{side}_recheck")
    if run_ids:
        return StoredRunSelection(run_ids=tuple(run_ids))
    assert isinstance(recheck, RecheckSelection)
    return recheck


def _content(report: Report, format_name: str, public_name: str) -> bytes:
    if format_name == "public-snapshot":
        return render_json(build_public_snapshot(report, display_name=public_name))
    if format_name == "html":
        return render_html(report)
    return render_json(report)


def run_report(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    url = os.environ.get("SCOPELENS_DATABASE_URL")
    if not url:
        parser.error("set SCOPELENS_DATABASE_URL to your PostgreSQL connection URL")
    try:
        engine = database(url)
    except ValueError, SQLAlchemyError:
        parser.error("invalid PostgreSQL connection configuration")
    try:
        store = OrchestrationStore(engine, ArtifactStore(args.artifacts, create=False))
        if args.command == "assessment-report":
            report: Report = load_assessment_report(store, args.assessment_id)
        else:
            report = load_comparison_report(
                store,
                args.project,
                _selection(args, "baseline"),
                _selection(args, "current"),
            )
        write_new(args.output, _content(report, args.format, args.public_name))
        print(f"Report written to {args.output}")
    except (
        ArtifactError,
        CorrelationError,
        ComparisonError,
        HistoryError,
        ReportOutputError,
    ) as exc:
        parser.error(str(exc))
    except ValidationError:
        parser.error("stored data could not produce a valid report")
    except ValueError:
        parser.error("report inputs are invalid")
    except SQLAlchemyError:
        parser.error("report data could not be read")
    finally:
        engine.dispose()


def add_report_commands(
    commands: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    assessment = commands.add_parser(
        "assessment-report",
        help="export one explicit durable assessment",
        allow_abbrev=False,
    )
    assessment.add_argument("assessment_id", type=UUID)
    comparison = commands.add_parser(
        "comparison-report",
        help="export an explicit coverage-aware comparison",
        allow_abbrev=False,
    )
    comparison.add_argument("--project", required=True)
    for side in ("baseline", "current"):
        group = comparison.add_mutually_exclusive_group(required=True)
        group.add_argument(
            f"--{side}-run-id", type=UUID, action="append", dest=f"{side}_run_id"
        )
        group.add_argument(
            f"--{side}-recheck", type=recheck_selection, dest=f"{side}_recheck"
        )
    for command in (assessment, comparison):
        command.add_argument(
            "--format", choices=("json", "html", "public-snapshot"), required=True
        )
        command.add_argument("--output", type=Path, required=True)
        command.add_argument(
            "--public-name",
            default="ScopeLens recorded demo",
            help="public display name used only by sanitized snapshots",
        )
        command.add_argument(
            "--artifacts", type=Path, default=Path(".scopelens/history")
        )
