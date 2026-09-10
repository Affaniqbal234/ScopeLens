# ScopeLens

ScopeLens defines authorized assessment scopes, scan profiles, and evidence
contracts. Its command-line interface validates local configuration files.
Scanning is not available yet.

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

## Scope configuration

Save this example as `scope.local.toml`. Files ending in `.local.toml` are ignored
by Git.

```toml
[project]
id = "local-lab"
name = "Local lab"

[[project.scope.network_targets]]
address = "127.0.0.1"
ports = [8000]

[[project.scope.web_targets]]
origin = "http://localhost:8000"
approved_addresses = ["127.0.0.1"]

[[profiles]]
id = "conservative"
tcp_ports = [8000]
```

```sh
uv run --locked scopelens validate-config scope.local.toml
```

Validation reads the file without resolving DNS or contacting targets. A valid
configuration records the operator's declared scope; it does not prove ownership
or permission to test.

Network permission covers an exact IPv4 address and explicit TCP ports. Web
permission covers an exact HTTP(S) origin and its approved destination addresses.
Neither grants the other. Scope checks require every supplied DNS answer to be
approved, but do not pin DNS or enforce network traffic.

Origins use ASCII hostnames or IPv4 addresses. Hostnames are lowercased and default
ports are omitted. Credentials, paths other than `/`, queries, fragments,
wildcards, trailing-dot hostnames, CIDRs, and IPv6 are rejected. Loopback and private
addresses require explicit authorization. Unspecified, multicast, reserved, and
link-local destinations are rejected.

Each profile is checked against the entire configured scope. Its TCP ports must
be authorized for every network target. Profiles allow at most 16 target entries
and 16 distinct destination addresses, 64 TCP ports per target, 5 HTTP requests
per second, and a 30-second request timeout. The default timeout is 10 seconds.
These are validated settings; no requests are executed.

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

## License

ScopeLens source code is licensed under the [MIT License](LICENSE).
