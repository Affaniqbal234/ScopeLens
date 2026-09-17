import os
import stat
import sys
from pathlib import Path
from uuid import uuid4

import pytest

from scopelens.cli import main
from scopelens.storage.artifacts import ArtifactError, ArtifactStore
from scopelens.storage.operations import read_input

linux = pytest.mark.skipif(
    sys.platform != "linux", reason="private artifacts require Linux"
)


def test_history_cli_dispatch_requires_database(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("SCOPELENS_DATABASE_URL", raising=False)
    with pytest.raises(SystemExit) as caught:
        main(["history-init"])
    assert caught.value.code == 2
    assert "set SCOPELENS_DATABASE_URL" in capsys.readouterr().err


@linux
def test_publish_is_private_idempotent_and_never_overwrites(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path / "private")
    run_id = uuid4()
    relative, _, size = store.publish(run_id, "stdout.xml", b"evidence")
    assert size == 8
    assert stat.S_IMODE(store.root.stat().st_mode) == 0o700
    assert stat.S_IMODE(store.path(relative).stat().st_mode) == 0o600
    assert store.publish(run_id, "stdout.xml", b"evidence")[0] == relative
    with pytest.raises(ArtifactError, match="refusing overwrite"):
        store.publish(run_id, "stdout.xml", b"different")
    assert store.read(relative) == b"evidence"
    assert len(list(store.directory(run_id).iterdir())) == 1


@linux
@pytest.mark.parametrize("kind", ["symlink", "hardlink", "fifo", "public", "oversized"])
def test_unsafe_artifacts_are_rejected(tmp_path: Path, kind: str) -> None:
    store = ArtifactStore(tmp_path / "private")
    run_id = uuid4()
    relative, _, _ = store.publish(run_id, "stdout.xml", b"evidence")
    path = store.path(relative)
    if kind == "symlink":
        path.unlink()
        path.symlink_to(tmp_path / "elsewhere")
    elif kind == "hardlink":
        os.link(path, path.parent / "alias")
    elif kind == "fifo":
        path.unlink()
        os.mkfifo(path, 0o600)
    elif kind == "public":
        path.chmod(0o644)
    else:
        with path.open("wb") as file:
            file.truncate(8 * 1024 * 1024 + 1)
    with pytest.raises((ArtifactError, OSError)):
        store.read(relative)


@linux
def test_input_rejects_links_fifo_and_oversize(tmp_path: Path) -> None:
    path = tmp_path / "input"
    os.mkfifo(path)
    with pytest.raises(ArtifactError):
        read_input(path)
    path.unlink()
    target = tmp_path / "target"
    target.write_bytes(b"data")
    path.symlink_to(target)
    with pytest.raises(OSError):
        read_input(path)
    with pytest.raises(ArtifactError):
        read_input(target, 3)


@linux
def test_failed_publication_leaves_no_final_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = ArtifactStore(tmp_path / "private")
    run_id = uuid4()

    def fail(_: int) -> None:
        raise OSError("fsync failed")

    monkeypatch.setattr(os, "fsync", fail)
    with pytest.raises(OSError, match="fsync failed"):
        store.publish(run_id, "stdout.xml", b"data")
    assert list(store.directory(run_id).iterdir()) == []


@linux
@pytest.mark.parametrize(
    "relative",
    ["../stdout.xml", "invalid/stdout.xml", "/etc/passwd", f"{uuid4()}/../../secret"],
)
def test_artifact_path_containment(tmp_path: Path, relative: str) -> None:
    store = ArtifactStore(tmp_path / "private")
    with pytest.raises(ArtifactError):
        store.path(relative)


@linux
def test_read_only_store_does_not_create_a_missing_root(tmp_path: Path) -> None:
    root = tmp_path / "missing"
    store = ArtifactStore(root, create=False)
    with pytest.raises(FileNotFoundError):
        store.read(f"{uuid4()}/stdout.jsonl")
    assert not root.exists()


@linux
def test_read_does_not_recreate_a_removed_root(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path / "private")
    store.root.rmdir()
    with pytest.raises(FileNotFoundError):
        store.read(f"{uuid4()}/stdout.jsonl")
    assert not store.root.exists()


@linux
def test_artifact_read_rejects_a_linked_parent(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path / "private")
    run_id = uuid4()
    relative, _, _ = store.publish(run_id, "stdout.xml", b"evidence")
    directory = store.path(relative).parent
    renamed = store.root / "moved"
    directory.rename(renamed)
    directory.symlink_to(renamed, target_is_directory=True)
    with pytest.raises(OSError):
        store.read(relative)
