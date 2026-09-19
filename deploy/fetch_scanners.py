from hashlib import sha256
from pathlib import Path
from sys import argv
from urllib.request import urlopen
from zipfile import ZipFile

RELEASES = {
    "amd64": {
        "httpx": (
            "1.12.0",
            "9d8439e8b6c9aa7d1e2314817a392e00d5178da3af5652f7475f88868f418f76",
        ),
        "nuclei": (
            "3.11.1",
            "ea63d4ae232808cd7c6bc00d0142428e231fab59dae01042246097d195835ab6",
        ),
    },
    "arm64": {
        "httpx": (
            "1.12.0",
            "fd7b123c1dfbc3d69f19f524e4eebcd6ec06b9a6cbd56813c76f11645197331e",
        ),
        "nuclei": (
            "3.11.1",
            "8044e3d9768ba0a744b2872c1a87e813006f013da97ca9f50f7661a4203bec07",
        ),
    },
}
MAX_RELEASE_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_SCANNER_BINARY_BYTES = 256 * 1024 * 1024


def fetch(
    name: str, version: str, architecture: str, digest: str, output: Path
) -> None:
    url = (
        f"https://github.com/projectdiscovery/{name}/releases/download/v{version}/"
        f"{name}_{version}_linux_{architecture}.zip"
    )
    archive = output / f"{name}.zip"
    with urlopen(url, timeout=60) as response:  # noqa: S310 - fixed HTTPS release URL
        content = response.read(MAX_RELEASE_ARCHIVE_BYTES + 1)
    if len(content) > MAX_RELEASE_ARCHIVE_BYTES:
        raise RuntimeError(f"{name} release archive exceeds its build limit")
    if sha256(content).hexdigest() != digest:
        raise RuntimeError(f"{name} release digest does not match the pinned value")
    archive.write_bytes(content)
    with ZipFile(archive) as bundle:
        member = bundle.getinfo(name)
        if member.file_size > MAX_SCANNER_BINARY_BYTES:
            raise RuntimeError(f"{name} release binary exceeds its build limit")
        destination = output / name
        destination.write_bytes(bundle.read(member))
        destination.chmod(0o755)
    archive.unlink()


def main() -> None:
    if len(argv) != 3 or argv[1] not in RELEASES:
        raise SystemExit("usage: fetch_scanners.py <amd64|arm64> <output-directory>")
    architecture = argv[1]
    output = Path(argv[2])
    output.mkdir(mode=0o755, parents=True)
    for name, (version, digest) in RELEASES[architecture].items():
        fetch(name, version, architecture, digest, output)


if __name__ == "__main__":
    main()
