"""Entry point for running the AI Honeypot Barrier pipeline."""

from __future__ import annotations

import argparse
from pathlib import Path

from src.pipeline.orchestrator import BarrierPipeline


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="AI Honeypot Barrier")
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("config/defaults.yaml"),
        help="Path to the pipeline configuration file",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    pipeline = BarrierPipeline(args.config)
    pipeline.run()


if __name__ == "__main__":
    main()
