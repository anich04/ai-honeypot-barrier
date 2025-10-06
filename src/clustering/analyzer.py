"""Unsupervised clustering pipeline for network traffic."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List

import numpy as np
import pandas as pd
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler

from src.utils.io import load_json, write_json
from src.utils.logger import configure_logger


@dataclass
class ClusterSummary:
    label: str
    size: int
    mean_packet_length: float
    unique_src_ips: int
    unique_dst_ips: int


class TrafficClusterer:
    """Cluster packet metadata and flag suspicious traffic."""

    def __init__(
        self,
        n_clusters: int = 2,
        random_state: int = 42,
        suspicious_weight: tuple[float, float, float] = (1.0, 0.75, 0.5),
    ) -> None:
        self.n_clusters = n_clusters
        self.random_state = random_state
        self.suspicious_weight = suspicious_weight
        self._logger = configure_logger(__name__)

    def run(self, input_path: Path, output_path: Path) -> Dict[str, List[Dict[str, float]]]:
        records = load_json(Path(input_path))
        if not records:
            raise ValueError("No packet data available for clustering. Capture traffic first.")

        frame = self._prepare_dataframe(records)
        labels = self._cluster(frame)
        frame["cluster"] = labels

        suspicious_cluster = self._select_suspicious_cluster(frame)
        frame["classification"] = np.where(
            frame["cluster"] == suspicious_cluster, "suspicious", "benign"
        )

        payload: List[dict] = []
        for idx, (record, classification) in enumerate(zip(records, frame["classification"])):
            enriched = dict(record)
            enriched["cluster"] = int(frame.iloc[idx]["cluster"])
            enriched["classification"] = str(classification)
            payload.append(enriched)

        write_json(Path(output_path), payload)

        summaries = [asdict(item) for item in self._summaries(frame)]
        self._logger.info("Clustered %s packets. Suspicious cluster=%s", len(frame), suspicious_cluster)
        return {"summaries": summaries}

    # ------------------------------------------------------------------
    def _prepare_dataframe(self, records: List[dict]) -> pd.DataFrame:
        frame = pd.DataFrame(records)
        frame = frame.fillna({"src_port": -1, "dst_port": -1, "flags": ""})

        frame["is_tcp"] = (frame["protocol"].str.upper() == "TCP").astype(int)
        frame["is_udp"] = (frame["protocol"].str.upper() == "UDP").astype(int)
        frame["has_flags"] = frame["flags"].apply(lambda value: 0 if not value else 1)
        frame["packet_length"] = frame["packet_length"].astype(float)
        frame["src_port"] = frame["src_port"].astype(int)
        frame["dst_port"] = frame["dst_port"].astype(int)

        return frame

    def _cluster(self, frame: pd.DataFrame) -> np.ndarray:
        feature_columns = [
            "packet_length",
            "src_port",
            "dst_port",
            "is_tcp",
            "is_udp",
            "has_flags",
        ]
        scaler = StandardScaler()
        scaled = scaler.fit_transform(frame[feature_columns])

        model = KMeans(n_clusters=self.n_clusters, random_state=self.random_state, n_init=10)
        labels = model.fit_predict(scaled)
        return labels

    def _select_suspicious_cluster(self, frame: pd.DataFrame) -> int:
        weight_len, weight_dst, weight_flags = self.suspicious_weight

        cluster_scores: Dict[int, float] = {}
        for cluster_label, group in frame.groupby("cluster"):
            score = (
                weight_len * group["packet_length"].mean()
                + weight_dst * group["dst_ip"].nunique()
                + weight_flags * group["has_flags"].mean()
            )
            cluster_scores[int(cluster_label)] = float(score)

        suspicious_cluster = max(cluster_scores, key=cluster_scores.get)
        return suspicious_cluster

    def _summaries(self, frame: pd.DataFrame) -> List[ClusterSummary]:
        summaries: List[ClusterSummary] = []
        for cluster_label, group in frame.groupby(["cluster", "classification"]):
            cluster_id, label = cluster_label
            summaries.append(
                ClusterSummary(
                    label=f"cluster_{int(cluster_id)}_{label}",
                    size=int(group.shape[0]),
                    mean_packet_length=float(group["packet_length"].mean()),
                    unique_src_ips=int(group["src_ip"].nunique()),
                    unique_dst_ips=int(group["dst_ip"].nunique()),
                )
            )
        return summaries
