"""High-level orchestration for the AI Honeypot Barrier workflow."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set

from src.capture.sniffer import PacketSniffer
from src.clustering.analyzer import TrafficClusterer
from src.honeypot.log_parser import load_events, summarize
from src.honeypot.redirector import IptablesRedirector, RedirectRule
from src.utils.config import load_config
from src.utils.io import load_json, write_json
from src.utils.logger import configure_logger


@dataclass
class PipelineResult:
    suspicious_ips: Set[str]
    cluster_summary: Dict[str, List[dict]]
    cowrie_summary: Optional[Dict[str, object]]


class BarrierPipeline:
    def __init__(self, config_path: Path) -> None:
        self.config = load_config(Path(config_path))
        log_file: Optional[Path] = self.config.get("paths", {}).get("pipeline_log")
        self._logger = configure_logger(__name__, log_file=log_file)

    # ------------------------------------------------------------------
    def run(self) -> PipelineResult:
        self._logger.info("Starting AI Honeypot Barrier pipeline")

        raw_path: Path = self.config["paths"]["raw_capture"]
        clustered_path: Path = self.config["paths"]["clustered_output"]

        if self.config.get("capture", {}).get("enabled", True):
            self._capture(raw_path)
        else:
            self._logger.info("Capture step disabled via configuration")

        cluster_summary = self._cluster(raw_path, clustered_path)
        suspicious_ips = self._redirect_if_required(clustered_path)
        cowrie_summary = self._analyse_honeypot()

        self._logger.info(
            "Pipeline finished | suspicious_ips=%s | cowrie_events=%s",
            len(suspicious_ips),
            cowrie_summary.get("total_events") if cowrie_summary else 0,
        )
        return PipelineResult(
            suspicious_ips=suspicious_ips,
            cluster_summary=cluster_summary,
            cowrie_summary=cowrie_summary,
        )

    # ------------------------------------------------------------------
    def _capture(self, output_path: Path) -> None:
        capture_cfg = self.config.get("capture", {})
        sniffer = PacketSniffer(
            interface=capture_cfg.get("interface"),
            output_path=output_path,
            packet_count=capture_cfg.get("packet_count"),
            capture_filter=capture_cfg.get("filter"),
        )
        sniffer.start()

    def _cluster(self, input_path: Path, output_path: Path) -> Dict[str, List[dict]]:
        if not Path(input_path).exists():
            raise FileNotFoundError(
                f"Capture output not found at {input_path}. Run the capture step first."
            )

        clustering_cfg = self.config.get("clustering", {})
        clusterer = TrafficClusterer(
            n_clusters=clustering_cfg.get("n_clusters", 2),
            random_state=clustering_cfg.get("random_state", 42),
        )
        summary = clusterer.run(input_path, output_path)
        return summary

    def _redirect_if_required(self, clustered_path: Path) -> Set[str]:
        honeypot_cfg = self.config.get("honeypot", {})
        if not honeypot_cfg.get("enable_redirects", False):
            self._logger.info("iptables redirection disabled")
            return set()

        if not Path(clustered_path).exists():
            self._logger.error("Clustered output not found at %s", clustered_path)
            return set()

        records = load_json(clustered_path)
        suspicious_ips: Set[str] = {
            record["src_ip"]
            for record in records
            if record.get("classification") == "suspicious" and record.get("src_ip")
        }

        if not suspicious_ips:
            self._logger.info("No suspicious IPs identified for redirection")
            return set()

        redirector = IptablesRedirector(dry_run=honeypot_cfg.get("dry_run", True))
        for ip in suspicious_ips:
            rule = RedirectRule(
                src_ip=ip,
                service_port=honeypot_cfg.get("service_port", 22),
                honeypot_host=honeypot_cfg.get("honeypot_host", "127.0.0.1"),
                honeypot_port=honeypot_cfg.get("honeypot_port", 2222),
            )
            redirector.add_redirect(rule)

        return suspicious_ips

    def _analyse_honeypot(self) -> Optional[Dict[str, object]]:
        analysis_cfg = self.config.get("analysis", {})
        if not analysis_cfg.get("parse_cowrie", False):
            return None

        cowrie_log = self.config["paths"].get("cowrie_log")
        summary_path = self.config["paths"].get("cowrie_summary")
        if not cowrie_log or not Path(cowrie_log).exists():
            self._logger.warning("Cowrie log file not found at %s", cowrie_log)
            return None

        events = load_events(cowrie_log)
        summary = summarize(events)
        payload: Dict[str, object] = {
            "total_events": summary.total_events,
            "unique_ips": summary.unique_ips,
            "top_commands": summary.top_commands,
            "downloaded_files": summary.downloaded_files,
        }

        if summary_path:
            write_json(summary_path, payload)
        return payload
