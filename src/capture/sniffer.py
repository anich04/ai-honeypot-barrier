"""Packet capture utilities built on top of Scapy."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, List, Optional

from scapy.all import IP, TCP, UDP, sniff  # type: ignore

from src.utils.io import write_json
from src.utils.logger import configure_logger

PacketCallback = Callable[[dict], None]


@dataclass
class PacketRecord:
    """Normalized subset of packet metadata used for analytics."""

    timestamp: str
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    packet_length: int
    flags: str


class PacketSniffer:
    """Capture live traffic and persist packet metadata to JSON."""

    def __init__(
        self,
        interface: Optional[str],
        output_path: Path,
        packet_count: Optional[int] = None,
        capture_filter: Optional[str] = None,
        batch_size: int = 200,
        on_packet: Optional[PacketCallback] = None,
    ) -> None:
        self.interface = interface
        self.output_path = Path(output_path)
        self.packet_count = packet_count
        self.capture_filter = capture_filter
        self.batch_size = batch_size
        self.on_packet = on_packet

        self._records: List[PacketRecord] = []
        self._logger = configure_logger(__name__)

    def start(self) -> None:
        """Begin sniffing traffic. Requires elevated privileges."""

        sniff_kwargs = {
            "prn": self._handle_packet,
            "store": False,
        }

        if self.interface:
            sniff_kwargs["iface"] = self.interface
        if self.packet_count:
            sniff_kwargs["count"] = self.packet_count
        if self.capture_filter:
            sniff_kwargs["filter"] = self.capture_filter

        self._logger.info(
            "Starting packet capture | iface=%s | limit=%s | filter=%s",
            self.interface or "default",
            self.packet_count or "unbounded",
            self.capture_filter or "none",
        )

        try:
            sniff(**sniff_kwargs)
        finally:
            self._flush()
            self._logger.info("Packet capture finished. Total packets persisted: %s", len(self._records))

    # ------------------------------------------------------------------
    def _handle_packet(self, packet: IP) -> None:
        record = self._normalize_packet(packet)
        if not record:
            return

        self._records.append(record)
        if self.on_packet:
            self.on_packet(asdict(record))

        if len(self._records) % self.batch_size == 0:
            self._flush()

    def _normalize_packet(self, packet: IP) -> Optional[PacketRecord]:
        if not packet.haslayer(IP):
            return None

        ip_layer = packet.getlayer(IP)
        timestamp = datetime.fromtimestamp(float(packet.time)).isoformat()

        src_port: Optional[int] = None
        dst_port: Optional[int] = None
        protocol = str(ip_layer.proto)
        flags = ""

        if packet.haslayer(TCP):
            protocol = "TCP"
            tcp_layer = packet.getlayer(TCP)
            src_port = int(tcp_layer.sport)
            dst_port = int(tcp_layer.dport)
            flags = tcp_layer.sprintf("%TCP.flags%")
        elif packet.haslayer(UDP):
            protocol = "UDP"
            udp_layer = packet.getlayer(UDP)
            src_port = int(udp_layer.sport)
            dst_port = int(udp_layer.dport)

        record = PacketRecord(
            timestamp=timestamp,
            src_ip=ip_layer.src,
            dst_ip=ip_layer.dst,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            packet_length=int(len(packet)),
            flags=flags,
        )
        return record

    def _flush(self) -> None:
        if not self._records:
            return
        payload = [asdict(record) for record in self._records]
        write_json(self.output_path, payload)
        self._logger.debug("Flushed %s packets to %s", len(payload), self.output_path)


def capture_to_file(
    output_path: Path,
    interface: Optional[str] = None,
    packet_count: Optional[int] = None,
    capture_filter: Optional[str] = None,
) -> None:
    """Convenience wrapper for quick captures."""

    sniffer = PacketSniffer(
        interface=interface,
        output_path=output_path,
        packet_count=packet_count,
        capture_filter=capture_filter,
    )
    sniffer.start()
