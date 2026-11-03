"""
NetSentinel - Central Configuration Module
Author: Hardik
Developer / Organization: Hidden Eye Security

Loads operational parameters, buffer boundaries, BPF filters, and SQLite PRAGMAs
from environment variables with production defaults.
"""

__author__ = "Hardik"
__organization__ = "Hidden Eye Security"

import os
from dataclasses import dataclass, field
from typing import Dict, Any


@dataclass
class NetSentinelConfig:
    # Database Settings
    DB_PATH: str = os.getenv("NETSENTINEL_DB_PATH", "netsentinel.db")
    DATABASE_URL: str = os.getenv(
        "NETSENTINEL_DB_URL", f"sqlite+aiosqlite:///{os.getenv('NETSENTINEL_DB_PATH', 'netsentinel.db')}"
    )

    # SQLite WAL High-Concurrency PRAGMAs
    SQLITE_JOURNAL_MODE: str = os.getenv("SQLITE_JOURNAL_MODE", "WAL")
    SQLITE_SYNCHRONOUS: str = os.getenv("SQLITE_SYNCHRONOUS", "NORMAL")
    SQLITE_BUSY_TIMEOUT: int = int(os.getenv("SQLITE_BUSY_TIMEOUT", "5000"))
    SQLITE_TEMP_STORE: str = os.getenv("SQLITE_TEMP_STORE", "MEMORY")
    SQLITE_WAL_AUTOCHECKPOINT: int = int(os.getenv("SQLITE_WAL_AUTOCHECKPOINT", "1000"))

    # Concurrency and Ingestion Buffer Settings
    BUFFER_MAXSIZE: int = int(os.getenv("NETSENTINEL_BUFFER_MAXSIZE", "10000"))
    BATCH_SIZE: int = int(os.getenv("NETSENTINEL_BATCH_SIZE", "250"))
    BATCH_FLUSH_INTERVAL: float = float(os.getenv("NETSENTINEL_BATCH_FLUSH_INTERVAL", "0.5"))  # 500ms
    BPF_FILTER: str = os.getenv("NETSENTINEL_BPF_FILTER", "ip or vlan")
    CAPTURE_INTERFACE: str = os.getenv("NETSENTINEL_INTERFACE", "")

    # Stage 1 Heuristics Engine Thresholds
    PPS_WINDOW_SECONDS: float = float(os.getenv("PPS_WINDOW_SECONDS", "5.0"))
    PPS_THRESHOLD: float = float(os.getenv("PPS_THRESHOLD", "100.0"))  # Packets per second per IP
    BPS_THRESHOLD: float = float(os.getenv("BPS_THRESHOLD", "1048576.0"))  # Bytes per second (1MB/s)
    PORT_SCAN_WINDOW_SECONDS: float = float(os.getenv("PORT_SCAN_WINDOW_SECONDS", "5.0"))
    PORT_SCAN_THRESHOLD: int = int(os.getenv("PORT_SCAN_THRESHOLD", "20"))  # Unique ports per source IP
    SYN_FLOOD_THRESHOLD: int = int(os.getenv("SYN_FLOOD_THRESHOLD", "50"))
    SYN_ACK_RATIO_THRESHOLD: float = float(os.getenv("SYN_ACK_RATIO_THRESHOLD", "3.0"))
    RST_COUNT_THRESHOLD: int = int(os.getenv("RST_COUNT_THRESHOLD", "20"))

    # Stage 2 Statistical Baseline Engine Thresholds
    EMA_ALPHA: float = float(os.getenv("EMA_ALPHA", "0.1"))
    MAD_MODIFIED_Z_THRESHOLD: float = float(os.getenv("MAD_MODIFIED_Z_THRESHOLD", "3.5"))
    WARMUP_PACKET_COUNT: int = int(os.getenv("WARMUP_PACKET_COUNT", "500"))
    ROLLING_WINDOW_SIZE: int = int(os.getenv("ROLLING_WINDOW_SIZE", "100"))

    def get_pragmas(self) -> Dict[str, Any]:
        """Returns the dictionary of PRAGMA statements to apply to SQLite connections."""
        return {
            "journal_mode": self.SQLITE_JOURNAL_MODE,
            "synchronous": self.SQLITE_SYNCHRONOUS,
            "busy_timeout": self.SQLITE_BUSY_TIMEOUT,
            "temp_store": self.SQLITE_TEMP_STORE,
            "wal_autocheckpoint": self.SQLITE_WAL_AUTOCHECKPOINT,
        }


# Global default configuration instance
settings = NetSentinelConfig()
