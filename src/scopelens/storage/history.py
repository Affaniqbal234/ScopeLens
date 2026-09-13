import json
from hashlib import sha256
from uuid import UUID, uuid4

from sqlalchemy import Connection, Engine, func, insert, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from scopelens.adapters.base import ImportContext, ParsedReport
from scopelens.adapters.nmap import NmapAdapter
from scopelens.config import ProjectConfig
from scopelens.domain.evidence import EvidenceReference, Observation
from scopelens.domain.scope import NetworkTarget, ScanProfile, ScopeViolation
from scopelens.domain.services import ServiceEndpoint
from scopelens.storage import schema as s
from scopelens.storage.artifacts import ArtifactError, ArtifactStore
from scopelens.storage.database import HistoryError, locked_run


def _digest(value: object) -> str:
    return sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


class History:
    def __init__(self, engine: Engine, artifacts: ArtifactStore) -> None:
        self.engine = engine
        self.artifacts = artifacts

    def begin(
        self,
        connection: Connection,
        run_id: UUID,
        config: ProjectConfig,
        profile_id: str,
        *,
        kind: str,
    ) -> None:
        config = ProjectConfig.model_validate(config.model_dump())
        profile = next((p for p in config.profiles if p.id == profile_id), None)
        if profile is None or kind not in ("scan", "import"):
            raise HistoryError("invalid run profile or kind")
        scope = config.project.scope.model_dump(mode="json")
        snapshot_id = _digest([config.project.id, scope])
        revision = sha256(profile.model_dump_json().encode()).hexdigest()
        with connection.begin():
            existing = (
                connection.execute(select(s.runs).where(s.runs.c.id == run_id))
                .mappings()
                .first()
            )
            if existing:
                if (
                    existing["project_id"],
                    existing["scope_snapshot_id"],
                    existing["profile_revision"],
                    existing["kind"],
                ) != (config.project.id, snapshot_id, revision, kind):
                    raise HistoryError(
                        "run identifier already belongs to different input"
                    )
                return
            connection.execute(
                pg_insert(s.projects)
                .values(id=config.project.id, name=config.project.name)
                .on_conflict_do_nothing()
            )
            connection.execute(
                pg_insert(s.scope_snapshots)
                .values(id=snapshot_id, project_id=config.project.id, scope=scope)
                .on_conflict_do_nothing()
            )
            connection.execute(
                insert(s.runs).values(
                    id=run_id,
                    project_id=config.project.id,
                    scope_snapshot_id=snapshot_id,
                    profile=profile.model_dump(mode="json"),
                    profile_revision=revision,
                    status="running",
                    kind=kind,
                )
            )
            connection.execute(
                insert(s.stages).values(
                    id=run_id,
                    run_id=run_id,
                    project_id=config.project.id,
                    scanner="nmap",
                    status="running",
                )
            )

    def ingest(
        self, connection: Connection, run_id: UUID, raw: bytes, stderr: bytes = b""
    ) -> ParsedReport:
        with connection.begin():
            run = (
                connection.execute(
                    select(s.runs).where(s.runs.c.id == run_id).with_for_update()
                )
                .mappings()
                .one()
            )
            profile = ScanProfile.model_validate(run["profile"])
            if (
                len(raw) + len(stderr) > profile.max_artifact_bytes
                or len(stderr) > 65536
            ):
                raise ArtifactError("run output exceeds its profile limit")
            report = NmapAdapter().parse(
                raw,
                ImportContext(
                    profile_id=profile.id, profile_revision=run["profile_revision"]
                ),
            )
            scope_data = connection.scalar(
                select(s.scope_snapshots.c.scope).where(
                    s.scope_snapshots.c.id == run["scope_snapshot_id"]
                )
            )
            from scopelens.domain.scope import AuthorizedScope

            scope = AuthorizedScope.model_validate(scope_data)
            allowed = {target.address for target in scope.network_targets}
            for observation in report.observations:
                subject = observation.subject
                if isinstance(subject, ServiceEndpoint):
                    if (
                        subject.transport != "tcp"
                        or subject.port not in profile.tcp_ports
                    ):
                        raise ScopeViolation("imported service exceeds run port scope")
                    scope.authorize_network(
                        NetworkTarget(address=subject.address, ports=(subject.port,))
                    )
                elif subject not in allowed:
                    raise ScopeViolation("imported host exceeds run scope")
            if run["status"] == "succeeded":
                expected = {
                    row.role: row.sha256
                    for row in connection.execute(
                        select(s.artifacts.c.role, s.artifacts.c.sha256).where(
                            s.artifacts.c.stage_id == run_id
                        )
                    )
                }
                if expected != {
                    "stdout": sha256(raw).hexdigest(),
                    "stderr": sha256(stderr).hexdigest(),
                }:
                    raise HistoryError(
                        "completed run cannot ingest different artifacts"
                    )
                for filename, data in (("stdout.xml", raw), ("stderr.txt", stderr)):
                    if self.artifacts.read(f"{run_id}/{filename}") != data:
                        raise ArtifactError("stored artifact is corrupt")
                return report
            if run["status"] != "running":
                raise HistoryError(
                    "terminal run cannot be retried; use a new run identifier"
                )
            artifact_ids = {}
            for role, filename, data in (
                ("stdout", "stdout.xml", raw),
                ("stderr", "stderr.txt", stderr),
            ):
                relative, digest, size = self.artifacts.publish(run_id, filename, data)
                artifact_id = uuid4()
                artifact_ids[role] = artifact_id
                connection.execute(
                    insert(s.artifacts).values(
                        id=artifact_id,
                        stage_id=run_id,
                        role=role,
                        relative_path=relative,
                        sha256=digest,
                        size_bytes=size,
                        health="ready",
                    )
                )
            evidence_ids: dict[str, UUID] = {}
            for reference in (
                report.evidence,
                *(
                    ref
                    for observation in report.observations
                    for ref in observation.evidence
                ),
            ):
                locator = reference.record_locator
                if locator not in evidence_ids:
                    evidence_id = uuid4()
                    evidence_ids[locator] = evidence_id
                    connection.execute(
                        insert(s.evidence).values(
                            id=evidence_id,
                            stage_id=run_id,
                            artifact_id=artifact_ids["stdout"],
                            record_locator=locator,
                            metadata=reference.model_dump(mode="json"),
                        )
                    )
            for ordinal, observation in enumerate(report.observations):
                subject = observation.subject
                if isinstance(subject, ServiceEndpoint):
                    identity, kind, address, transport, port = (
                        f"{subject.transport}:{subject.address}:{subject.port}",
                        "service",
                        subject.address,
                        subject.transport,
                        subject.port,
                    )
                else:
                    identity, kind, address, transport, port = (
                        subject,
                        "host",
                        subject,
                        None,
                        None,
                    )
                entity_id = connection.scalar(
                    pg_insert(s.entities)
                    .values(
                        id=uuid4(),
                        project_id=run["project_id"],
                        identity=identity,
                        kind=kind,
                        address=address,
                        transport=transport,
                        port=port,
                    )
                    .on_conflict_do_nothing(index_elements=["project_id", "identity"])
                    .returning(s.entities.c.id)
                )
                if entity_id is None:
                    entity_id = connection.scalar(
                        select(s.entities.c.id).where(
                            s.entities.c.project_id == run["project_id"],
                            s.entities.c.identity == identity,
                        )
                    )
                observation_id = uuid4()
                connection.execute(
                    insert(s.observations).values(
                        id=observation_id,
                        stage_id=run_id,
                        project_id=run["project_id"],
                        entity_id=entity_id,
                        ordinal=ordinal,
                        key=observation.key,
                        value=observation.value,
                    )
                )
                for reference in observation.evidence:
                    connection.execute(
                        insert(s.observation_evidence).values(
                            observation_id=observation_id,
                            evidence_id=evidence_ids[reference.record_locator],
                            stage_id=run_id,
                        )
                    )
            self._finish(connection, run_id, "succeeded")
            connection.execute(
                update(s.stages)
                .where(s.stages.c.id == run_id)
                .values(reported_exit=report.reported_exit)
            )
        return report

    @staticmethod
    def _finish(
        connection: Connection, run_id: UUID, status: str, error_code: str | None = None
    ) -> None:
        values = {
            "status": status,
            "finished_at": func.now(),
            "error_code": error_code,
        }
        connection.execute(
            update(s.runs)
            .where(s.runs.c.id == run_id, s.runs.c.status == "running")
            .values(**values)
        )
        connection.execute(
            update(s.stages)
            .where(s.stages.c.id == run_id, s.stages.c.status == "running")
            .values(**values)
        )

    def list_runs(self, project_id: str) -> list[dict[str, object]]:
        with self.engine.connect() as connection:
            return [
                dict(row)
                for row in connection.execute(
                    select(s.runs)
                    .where(s.runs.c.project_id == project_id)
                    .order_by(s.runs.c.created_at, s.runs.c.id)
                ).mappings()
            ]

    def report(self, run_id: UUID) -> ParsedReport:
        with self.engine.connect() as connection:
            stage = (
                connection.execute(select(s.stages).where(s.stages.c.id == run_id))
                .mappings()
                .one()
            )
            if stage["status"] != "succeeded":
                raise HistoryError("run has no completed report")
            evidence = {
                row.id: EvidenceReference.model_validate(row.metadata)
                for row in connection.execute(
                    select(s.evidence).where(s.evidence.c.stage_id == run_id)
                )
            }
            root = next(
                item for item in evidence.values() if item.record_locator == "/nmaprun"
            )
            observations = []
            query = (
                select(
                    s.observations.c.id,
                    s.observations.c.key,
                    s.observations.c.value,
                    s.entities.c.kind,
                    s.entities.c.address,
                    s.entities.c.transport,
                    s.entities.c.port,
                )
                .join(s.entities, s.entities.c.id == s.observations.c.entity_id)
                .where(s.observations.c.stage_id == run_id)
                .order_by(s.observations.c.ordinal)
            )
            for row in connection.execute(query):
                refs = connection.scalars(
                    select(s.observation_evidence.c.evidence_id).where(
                        s.observation_evidence.c.observation_id == row.id
                    )
                ).all()
                subject = (
                    ServiceEndpoint(
                        address=row.address, transport=row.transport, port=row.port
                    )
                    if row.kind == "service"
                    else row.address
                )
                observations.append(
                    Observation(
                        subject=subject,
                        key=row.key,
                        value=row.value,
                        evidence=tuple(evidence[ref] for ref in refs),
                    )
                )
            return ParsedReport(
                evidence=root,
                reported_exit=stage["reported_exit"],
                observations=tuple(observations),
            )

    def reconcile(self) -> list[dict[str, str]]:
        self.artifacts._directory(self.artifacts.root)
        issues: list[dict[str, str]] = []
        with self.engine.connect() as connection:
            run_ids = connection.scalars(select(s.runs.c.id)).all()
        for run_id in run_ids:
            try:
                with locked_run(self.engine, run_id) as connection, connection.begin():
                    status = connection.scalar(
                        select(s.runs.c.status).where(s.runs.c.id == run_id)
                    )
                    if status == "running":
                        self._finish(
                            connection, run_id, "interrupted", "owner_disconnected"
                        )
                        issues.append({"run_id": str(run_id), "issue": "interrupted"})
                    known = set()
                    for artifact in connection.execute(
                        select(s.artifacts).where(s.artifacts.c.stage_id == run_id)
                    ).mappings():
                        relative = artifact["relative_path"]
                        known.add(relative)
                        health = "ready"
                        try:
                            raw = self.artifacts.read(relative)
                            if (
                                len(raw) != artifact["size_bytes"]
                                or sha256(raw).hexdigest() != artifact["sha256"]
                            ):
                                health = "corrupt"
                        except FileNotFoundError:
                            health = "missing"
                        except OSError, ArtifactError:
                            health = "corrupt"
                        connection.execute(
                            update(s.artifacts)
                            .where(s.artifacts.c.id == artifact["id"])
                            .values(health=health)
                        )
                        if health != "ready":
                            issues.append(
                                {
                                    "run_id": str(run_id),
                                    "issue": health,
                                    "path": relative,
                                }
                            )
                    directory = self.artifacts.root / str(run_id)
                    if directory.is_dir() and not directory.is_symlink():
                        for path in directory.iterdir():
                            relative = f"{run_id}/{path.name}"
                            if relative not in known:
                                issues.append(
                                    {
                                        "run_id": str(run_id),
                                        "issue": "unreferenced",
                                        "path": relative,
                                    }
                                )
            except HistoryError:
                issues.append({"run_id": str(run_id), "issue": "busy"})
        known_runs = {str(run_id) for run_id in run_ids}
        for path in self.artifacts.root.iterdir():
            if path.name not in known_runs:
                try:
                    candidate = UUID(path.name)
                except ValueError:
                    candidate = None
                if candidate is not None:
                    with self.engine.connect() as connection:
                        if (
                            connection.scalar(
                                select(s.runs.c.id).where(s.runs.c.id == candidate)
                            )
                            is not None
                        ):
                            continue
                issues.append({"issue": "unreferenced", "path": path.name})
        return issues
