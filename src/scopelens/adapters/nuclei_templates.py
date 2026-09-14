import json
from dataclasses import dataclass
from hashlib import sha256
from importlib.resources import files

NUCLEI_VERSION = "3.11.1"


@dataclass(frozen=True)
class ReviewedTemplate:
    filename: str
    id: str
    matcher: str
    severity: str
    path: str
    sha256: str


def reviewed_templates() -> tuple[ReviewedTemplate, ...]:
    root = files("scopelens").joinpath("templates")
    manifest = json.loads(root.joinpath("manifest.json").read_text(encoding="utf-8"))
    templates = tuple(ReviewedTemplate(**entry) for entry in manifest)
    for template in templates:
        if template.filename not in (
            "directory-listing.yaml",
            "exposed-git-config.yaml",
        ):
            raise ValueError("unapproved template file")
        if (
            sha256(root.joinpath(template.filename).read_bytes()).hexdigest()
            != template.sha256
        ):
            raise ValueError("reviewed template digest mismatch")
    if len(templates) != 2 or len({template.id for template in templates}) != 2:
        raise ValueError("invalid reviewed template manifest")
    return templates


def template_revision() -> str:
    return sha256(
        "\n".join(template.sha256 for template in reviewed_templates()).encode()
    ).hexdigest()
