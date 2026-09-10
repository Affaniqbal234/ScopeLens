# ScopeLens

ScopeLens is being developed for authorized security assessments. The current
package provides command-line help and version information. Scanning is not
available yet.

## Setup

Install Python 3.14 and [uv](https://docs.astral.sh/uv/getting-started/installation/),
then run these commands from the repository root. Development and CI use uv 0.12.7.

```sh
uv sync --locked
uv run --locked scopelens --help
uv run --locked scopelens --version
```

The package also supports `uv run --locked python -m scopelens --help`.
Docker and external scanners are not required for the current package.

## Development

```sh
uv run --locked ruff check .
uv run --locked ruff format --check .
uv run --locked mypy
uv run --locked pytest
uv build
```

CI runs these checks on Windows and Linux with Python 3.14 and verifies that the
built wheel can be installed and its command-line entry points run.
