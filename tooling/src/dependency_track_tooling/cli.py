"""Stage native scanner payloads using the shared staging helper."""

import argparse
from importlib.resources import as_file, files
from pathlib import Path

from k8s_stack_tooling.api.payloads import stage_payloads


def stage() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--destination", type=Path, default=Path("/work/payloads"))
    args = parser.parse_args()
    with as_file(files("dependency_track_tooling").joinpath("payloads")) as source:
        stage_payloads(
            source, ["scan-images.sh", "scan-repositories.mjs"], destination=args.destination
        )
