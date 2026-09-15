from uuid import UUID

from sqlalchemy import Connection, select

from scopelens.adapters.base import ParsedReport
from scopelens.adapters.registry import adapter_for
from scopelens.domain.evidence import EvidenceReference, Observation
from scopelens.domain.findings import ScannerMatch
from scopelens.domain.services import HttpEndpoint, ServiceEndpoint
from scopelens.storage import schema as s
from scopelens.storage.database import HistoryError


def read_report(connection: Connection, run_id: UUID) -> ParsedReport:
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
        item
        for item in evidence.values()
        if item.record_locator == adapter_for(stage["scanner"]).root_locator
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
            ServiceEndpoint(address=row.address, transport=row.transport, port=row.port)
            if row.kind == "service"
            else HttpEndpoint(origin=row.address)
            if row.kind == "origin"
            else row.address
        )
        observations.append(
            Observation(
                subject=subject,
                key=row.key,
                value=row.value,
                evidence=tuple(
                    sorted(
                        (evidence[ref] for ref in refs),
                        key=lambda ref: ref.model_dump_json(),
                    )
                ),
            )
        )
    return ParsedReport(
        evidence=root,
        reported_exit=stage["reported_exit"],
        observations=tuple(observations),
        matches=tuple(
            ScannerMatch.model_validate(value)
            for value in connection.scalars(
                select(s.scanner_matches.c.metadata)
                .where(s.scanner_matches.c.stage_id == run_id)
                .order_by(s.scanner_matches.c.ordinal)
            )
        ),
    )
