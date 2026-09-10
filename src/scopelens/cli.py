import argparse
from importlib.metadata import version


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="scopelens",
        description="ScopeLens: authorized security assessment tooling.",
        allow_abbrev=False,
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {version('scopelens')}"
    )
    parser.parse_args(argv)
    parser.print_help()
