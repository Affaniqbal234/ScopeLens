import json
from hashlib import sha256

from scopelens.config import ProjectConfig


def scope_snapshot(config: ProjectConfig) -> tuple[str, dict[str, object]]:
    scope = config.project.scope.model_dump(mode="json")
    encoded = json.dumps(
        [config.project.id, scope], sort_keys=True, separators=(",", ":")
    ).encode()
    return sha256(encoded).hexdigest(), scope
