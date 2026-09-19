import argparse
import os

import uvicorn
from sqlalchemy.exc import SQLAlchemyError

from scopelens.api.app import create_app
from scopelens.config import ConfigurationError, load_config
from scopelens.orchestration.store import OrchestrationStore
from scopelens.orchestration.worker import AssessmentWorker
from scopelens.storage.artifacts import ArtifactError, ArtifactStore
from scopelens.storage.database import HistoryError, database


def local_port(value: str) -> int:
    try:
        port = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("port must be an integer") from None
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return port


def run_api(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    url = os.environ.get("SCOPELENS_DATABASE_URL")
    token = os.environ.get("SCOPELENS_API_TOKEN")
    if not url:
        parser.error("set SCOPELENS_DATABASE_URL to your PostgreSQL connection URL")
    if not token:
        parser.error("set SCOPELENS_API_TOKEN to a private local API token")
    engine = None
    try:
        config = load_config(args.config)
        engine = database(url)
        store = OrchestrationStore(engine, ArtifactStore(args.artifacts))
        app = create_app(
            config,
            store,
            AssessmentWorker(store),
            token=token,
            allowed_origins=tuple(args.cors_origin),
        )
        host = "0.0.0.0" if args.container_bind else "127.0.0.1"
        uvicorn.run(app, host=host, port=args.port)
    except (
        ArtifactError,
        ConfigurationError,
        HistoryError,
        SQLAlchemyError,
        ValueError,
    ) as exc:
        parser.error(str(exc))
    finally:
        if engine is not None:
            engine.dispose()
