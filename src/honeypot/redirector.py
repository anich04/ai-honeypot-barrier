"""Helper for managing iptables honeypot redirection rules."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path
from shutil import which
from typing import Optional

from src.utils.logger import configure_logger


@dataclass
class RedirectRule:
    src_ip: str
    service_port: int
    honeypot_host: str
    honeypot_port: int


class IptablesRedirector:
    """Create and remove NAT rules that steer suspicious traffic to Cowrie."""

    def __init__(self, dry_run: bool = False, table: str = "nat") -> None:
        self.dry_run = dry_run
        self.table = table
        self._logger = configure_logger(__name__)
        self._iptables_path: Optional[str] = which("iptables")

        if not self._iptables_path:
            self._logger.warning(
                "iptables binary not found on PATH. Redirection will be skipped."
            )

    # ------------------------------------------------------------------
    def add_redirect(self, rule: RedirectRule) -> bool:
        command = [
            self._iptables_binary(),
            "-t",
            self.table,
            "-A",
            "PREROUTING",
            "-s",
            rule.src_ip,
            "-p",
            "tcp",
            "--dport",
            str(rule.service_port),
            "-j",
            "DNAT",
            "--to-destination",
            f"{rule.honeypot_host}:{rule.honeypot_port}",
        ]
        return self._execute(command, description="add redirect")

    def remove_redirect(self, rule: RedirectRule) -> bool:
        command = [
            self._iptables_binary(),
            "-t",
            self.table,
            "-D",
            "PREROUTING",
            "-s",
            rule.src_ip,
            "-p",
            "tcp",
            "--dport",
            str(rule.service_port),
            "-j",
            "DNAT",
            "--to-destination",
            f"{rule.honeypot_host}:{rule.honeypot_port}",
        ]
        return self._execute(command, description="remove redirect")

    def list_rules(self) -> Optional[str]:
        if not self._iptables_path:
            return None

        command = [self._iptables_binary(), "-t", self.table, "-S", "PREROUTING"]
        try:
            output = subprocess.check_output(command, text=True)
            return output
        except subprocess.CalledProcessError as exc:
            self._logger.error("Failed to list iptables rules: %s", exc)
            return None

    # ------------------------------------------------------------------
    def _iptables_binary(self) -> str:
        return self._iptables_path or "iptables"

    def _execute(self, command: list[str], description: str) -> bool:
        if not self._iptables_path:
            self._logger.error("iptables unavailable; cannot %s", description)
            return False

        if self.dry_run:
            self._logger.info("[dry-run] %s -> %s", description, " ".join(command))
            return True

        self._logger.debug("Running command: %s", " ".join(command))
        try:
            subprocess.run(command, check=True)
            self._logger.info("iptables %s succeeded", description)
            return True
        except subprocess.CalledProcessError as exc:
            self._logger.error("iptables %s failed: %s", description, exc)
            return False
