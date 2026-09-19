import argparse
from pathlib import Path

from scopelens.deployment import recorded_demo_report
from scopelens.reporting.io import write_new
from scopelens.reporting.render import render_json
from scopelens.reporting.snapshot import build_public_snapshot


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    snapshot = build_public_snapshot(
        recorded_demo_report(), display_name="ScopeLens controlled demo"
    )
    write_new(args.output, render_json(snapshot))


if __name__ == "__main__":
    main()
