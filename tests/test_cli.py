from importlib.metadata import version

import pytest

from scopelens.cli import main


def test_no_arguments_shows_help(capsys: pytest.CaptureFixture[str]) -> None:
    main([])

    output = capsys.readouterr()
    assert "usage: scopelens" in output.out
    assert "--version" in output.out
    assert output.err == ""


def test_help_exits_successfully(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--help"])

    assert exc.value.code == 0
    output = capsys.readouterr()
    assert "usage: scopelens" in output.out
    assert output.err == ""


def test_version_matches_installed_package(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--version"])

    assert exc.value.code == 0
    output = capsys.readouterr()
    assert output.out.strip() == f"scopelens {version('scopelens')}"
    assert output.err == ""


@pytest.mark.parametrize("argument", ["scan", "--unknown", "--ver"])
def test_unsupported_arguments_fail(
    argument: str, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as exc:
        main([argument])

    assert exc.value.code == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert "unrecognized arguments" in output.err
