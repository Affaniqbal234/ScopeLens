# ScopeLens

ScopeLens validates authorized assessment scopes, runs bounded Nmap and httpx probes
on Linux, and stores normalized observations with source evidence in PostgreSQL.

## Setup

Install Python 3.14 and [uv](https://docs.astral.sh/uv/getting-started/installation/),
then run these commands from the repository root. Development and CI use uv 0.12.7.

```sh
uv sync --locked
uv run --locked scopelens --help
uv run --locked scopelens --version
```

The package also supports `uv run --locked python -m scopelens --help`.
Offline validation and report parsing work without Docker or scanner binaries.

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
approved. Live httpx execution pins one supplied approved address without resolving
the origin hostname.

Origins use ASCII hostnames or IPv4 addresses. Hostnames are lowercased and default
ports are omitted. Credentials, paths other than `/`, queries, fragments,
wildcards, trailing-dot hostnames, CIDRs, and IPv6 are rejected. Loopback and private
addresses require explicit authorization. Unspecified, multicast, reserved, and
link-local destinations are rejected.

Each profile is checked against the entire configured scope. Its TCP ports must
be authorized for every network target. Profiles allow at most 16 target entries
and 16 distinct destination addresses, 64 TCP ports per target, 5 HTTP requests
per second, and a 30-second request timeout. The default timeout is 10 seconds.
httpx uses the HTTP request settings. Nmap uses `probes_per_second` (1–5,
default 5), `scan_timeout_seconds` (1–120, default 30), and `max_artifact_bytes`
(1 KiB–8 MiB, default 1 MiB).

## Nmap XML import

Import an existing [Nmap XML report](https://nmap.org/book/output-formats-xml-output.html)
and print normalized JSON:

```sh
uv run --locked scopelens import-nmap tests/fixtures/nmap/services.xml --profile-id fixture --profile-revision 1
```

Importing reads one local file without running Nmap, resolving DNS, or contacting
targets. Profile metadata is supplied by the importer; importing does not verify
that profile was used or grant scanning permission.

Observations retain reported host and port states, service metadata, and source
references containing the file's SHA-256 hash, XML record location, scanner and
adapter versions, profile metadata, and timestamp. Host completion time is used
when present, otherwise report completion time. Keep the original XML to inspect
the referenced evidence; import does not store it.

Missing metadata produces no observation. Summarized port counts remain counts,
without assigning states to unlisted ports. Service name lookup and probe results
remain distinct. An error exit or missing exit status is preserved in the JSON.

Imports support IPv4 hosts and TCP, UDP, and SCTP ports from 1 to 65535, subject to
the address restrictions above. Reports must include a completion timestamp.
Malformed XML, internal DTDs, duplicate host/service records, and inputs over
8 MiB, 32 nesting levels, or 50,000 elements are rejected. External DTDs,
stylesheets, and XInclude references are never loaded. NSE, OS detection, and
unrecognized XML sections are not normalized. Fixtures use synthetic lab data.

## Controlled execution

Live Nmap scanning requires Linux with `/usr/bin/nmap`. On Windows, use a Linux
distribution under WSL2 or Docker with Linux containers. Run from the Linux
filesystem so private artifact permissions can be enforced.

```sh
uv run --locked scopelens scan-nmap scope.local.toml --profile conservative
```

Only explicitly authorized network addresses and the selected profile's TCP ports
are scanned. Nmap uses TCP connect scans with DNS, host discovery, scripts, OS
detection, and version probing disabled. The probe rate is Nmap's rate setting,
not a packet-level firewall guarantee. Host state from `-Pn` can be reported as
`up` with reason `user-set`; it is not independent proof of reachability.

The process deadline includes output collection; termination drains pipes and
kills the process group, with a separate cleanup deadline. Ctrl+C cancels the run.
Output is parsed only after a successful process exit, then checked for scope and
coverage. Missing ports, missing hosts, and timeout reports are failures.

Raw XML/JSONL and stderr are retained in unique directories under `.scopelens/artifacts/`
(ignored by Git). Directories use mode 0700 and files use 0600. Each run limits
combined output to `max_artifact_bytes`, with stderr additionally capped at 64 KiB.
Failed runs retain bounded partial files. No total retention quota is applied;
remove old run directories when they are no longer needed. An alternative
`--artifacts` root must be private and owned by the current Linux user.

## HTTP discovery

Use [ProjectDiscovery httpx v1.12.0](https://github.com/projectdiscovery/httpx/releases/tag/v1.12.0),
not the Python HTTP client with the same name. Install the verified Linux release
at `/usr/local/bin/httpx`, or pass its absolute path with `--httpx-binary`.
ScopeLens checks the binary's reported identity and version before probing.

```sh
uv run --locked scopelens scan-httpx scope.local.toml --profile conservative --origin http://localhost:8000 --address 127.0.0.1
uv run --locked scopelens import-httpx report.jsonl --origin http://localhost:8000 --address 127.0.0.1 --scanner-version 1.12.0 --profile-id conservative --profile-revision 1
```

Each invocation probes `/` on one approved origin and one approved IPv4 address,
with the origin's Host header and TLS SNI. Redirects and HTTP/HTTPS fallback are
disabled. Redirect locations remain evidence and never grant permission to scan.
No crawling, screenshots, or secondary-domain probes are enabled. Requests use the
selected profile's time and output limits; response bodies are read up to 64 KiB
and omitted from raw JSONL. Like httpx, these probes accept untrusted TLS
certificates; a successful response does not establish certificate validity.

The parser records response status, optional title, technology labels, selected
headers, and probe failures. Missing fields remain absent. A failed probe is not
proof that a port is closed; a technology label is not a vulnerability finding.
HTTP endpoints retain their origin identity separately from IP/transport/port
services. Raw headers can contain sensitive data and remain private.

Imports require the declared scanner version and origin/address context because
JSONL alone does not establish either the tool version or the original virtual
host. They never contact targets. Malformed, duplicate, partial, or out-of-scope
records reject the whole import. JSONL has no completion marker; live execution
also requires a successful process exit and evidence for the selected address.

## Controlled lab

The lab exposes a harmless sample backup through a directory listing on port
8000; port 8001 is closed. Containers run as non-root with dropped capabilities,
read-only filesystems, and resource limits. No host ports are published. The lab
uses an internal Docker network; image builds still require registry/package
access. Ensure `172.30.255.0/28` does not conflict with your existing networks.

With Docker Engine and Compose available:

```sh
docker compose -f lab/compose.yaml --profile scan config --quiet
docker compose -f lab/compose.yaml --profile scan build
docker compose -f lab/compose.yaml up -d --wait target
docker compose -f lab/compose.yaml run --rm scanner
docker compose -f lab/compose.yaml down
```

Raw artifacts remain in the lab's named volume after shutdown. To delete that lab
data, run `docker compose -f lab/compose.yaml --profile scan down --volumes`.
Keep this intentionally exposed fixture isolated.

## Persistent history

History uses PostgreSQL for projects, scope/profile snapshots, runs, stable entity
identities, observations, and evidence metadata. Raw XML/JSONL and stderr stay on a
private Linux filesystem. Offline imports remain distinct from executed scans.

Use a dedicated PostgreSQL database with a direct connection; transaction-pooling
proxies do not preserve the per-run session locks. Set `SCOPELENS_DATABASE_URL` to its connection
URL (`postgresql+psycopg://user:password@localhost:5432/scopelens`) through your
local environment; keep credentials out of source control. Then run:

```sh
uv run --locked scopelens history-init
uv run --locked scopelens history-import scope.local.toml report.xml --profile conservative --run-id 00000000-0000-4000-8000-000000000001
uv run --locked scopelens history-list --project local-lab
uv run --locked scopelens history-show 00000000-0000-4000-8000-000000000001
uv run --locked scopelens history-reconcile
```

`history-scan scope.local.toml --profile conservative --run-id <new-UUID>` runs
Nmap with history. For httpx, add `--scanner httpx --origin <approved-origin>
--address <approved-IP>`; `history-import` also requires `--scanner-version 1.12.0`.
Run `history-init` to apply migrations before using these commands. Choose a new
UUID for each scan attempt. Retrying an import with the same UUID, scanner context,
scope, profile, and bytes does not duplicate observations.
Changed input under an existing UUID is rejected. The default private root is
`.scopelens/history`; pass the same `--artifacts` root to all history commands.

Files are flushed and published without overwriting existing artifacts before
one database transaction commits evidence, observations, and successful status.
Database rollback cannot remove published files. A write failure leaves the run
pending (`running`), with bounded files retained. An import can retry the same
input before reconciliation. Check `history-show` after an uncertain commit:
acknowledgment failure does not prove that the transaction rolled back.

Reconciliation skips runs held by an active session, marks abandoned running
records `interrupted`, and reports missing, corrupted, and unreferenced files.
It never deletes files or turns an interrupted scan into a successful result.
Failed/interrupted runs require a new UUID; retained captures can be inspected
or imported separately. Completed observations remain historical facts when an
artifact goes missing; reconciliation reports the evidence availability problem.
Scanner failures retain partial capture directories without promoting them to
validated evidence. Back up the database and private root together while scans
and imports are stopped. There is no automatic retention or deletion policy.

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
Execution is type-checked for Linux. Windows runs portable control-flow tests;
real process-group and permission tests require Linux. The Docker test uses a
unique Compose project and removes its own containers and volumes afterward:

```sh
SCOPELENS_LAB_TEST=1 uv run --locked pytest tests/test_lab.py
```

The PostgreSQL suite creates a disposable container with a loopback-only port and
its own credentials and volume. It ignores operator database URLs and verifies
container ownership before cleanup. Run it on Linux with Docker available:

```sh
SCOPELENS_POSTGRES_TEST=1 uv run --locked pytest tests/test_history.py
```

Local HTTP/HTTPS integration tests also verify Host/SNI, redirect containment, and
scheme fallback with an explicitly supplied httpx binary:

```sh
SCOPELENS_HTTPX_BINARY=/usr/local/bin/httpx uv run --locked pytest tests/test_httpx_linux.py
```

## License

ScopeLens source code is licensed under the [MIT License](LICENSE).
