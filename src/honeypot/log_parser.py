"""Utilities for parsing Cowrie JSON logs and extracting attacker behaviour."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Sequence, Tuple

from src.utils.logger import configure_logger


@dataclass
class HoneypotSummary:
    total_events: int
    unique_ips: int
    top_commands: List[Tuple[str, int]]
    downloaded_files: List[str]


_logger = configure_logger(__name__)


def load_events(log_path: Path) -> List[dict]:
    events: List[dict] = []
    with Path(log_path).open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as exc:
                _logger.warning("Skipping invalid log line: %s", exc)
    return events


def summarize(events: Sequence[dict]) -> HoneypotSummary:
    commands: Counter[str] = Counter()
    downloads: set[str] = set()
    ips: set[str] = set()

    for event in events:
        src_ip = event.get("src_ip")
        if isinstance(src_ip, str):
            src_ip = src_ip.strip()
            if src_ip:
                ips.add(src_ip)

        event_id = event.get("eventid")
        if event_id == "cowrie.command.input":
            data = event.get("input", "")
            if isinstance(data, str) and data:
                commands[data] += 1
        elif event_id == "cowrie.session.file_download":
            url = event.get("url")
            if isinstance(url, str) and url:
                downloads.add(url)

    summary = HoneypotSummary(
        total_events=len(events),
        unique_ips=len(ips),
        top_commands=commands.most_common(10),
        downloaded_files=sorted(downloads),
    )
    return summary
