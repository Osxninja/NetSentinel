"""
NetSentinel - Forensic Traffic Query Tool
Author: Hardik
Developer / Organization: Hidden Eye Security

Interfaces over SQLite flow logs to extract packet sequences, TCP flag distributions,
communication histories, and byte volumes for forensic RAG investigations.
"""

__author__ = "Hardik"
__organization__ = "Hidden Eye Security"

import re
import sqlite3
from typing import Dict, Any, List, Optional
from config import settings


class TrafficAnalysisTool:
    """
    Forensic analysis tool querying the SQLite flow_logs table.
    Translates forensic questions into optimized SQL queries.
    """

    def __init__(self, db_path: str = settings.DB_PATH):
        self.db_path = db_path

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def get_flow_summary(self, ip: str) -> Dict[str, Any]:
        """Summarizes packet count, byte volume, and peer endpoints for an IP."""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT 
                    COUNT(*) as total_packets,
                    COALESCE(SUM(packet_length), 0) as total_bytes,
                    COALESCE(AVG(packet_length), 0) as avg_packet_length,
                    MIN(timestamp) as first_seen,
                    MAX(timestamp) as last_seen,
                    COUNT(DISTINCT destination_ip) as distinct_destinations,
                    COUNT(DISTINCT destination_port) as distinct_dest_ports
                FROM flow_logs
                WHERE source_ip = ?
                """,
                (ip,),
            )
            row = cursor.fetchone()
            return dict(row) if row else {}
        except sqlite3.OperationalError:
            return {
                "total_packets": 0,
                "total_bytes": 0,
                "avg_packet_length": 0,
                "first_seen": None,
                "last_seen": None,
                "distinct_destinations": 0,
                "distinct_dest_ports": 0,
            }
        finally:
            conn.close()

    def get_tcp_flag_distribution(self, ip: str) -> Dict[str, int]:
        """Calculates counts of TCP flags (SYN, ACK, RST, FIN, PSH) for an IP."""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT tcp_flags, COUNT(*) as count
                FROM flow_logs
                WHERE source_ip = ? AND protocol = 'TCP' AND tcp_flags IS NOT NULL
                GROUP BY tcp_flags
                ORDER BY count DESC
                """,
                (ip,),
            )
            rows = cursor.fetchall()
            return {r["tcp_flags"]: r["count"] for r in rows}
        except sqlite3.OperationalError:
            return {}
        finally:
            conn.close()

    def get_targeted_ports(self, ip: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Returns top destination ports targeted by the source IP."""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT destination_port, COUNT(*) as packet_count
                FROM flow_logs
                WHERE source_ip = ? AND destination_port IS NOT NULL
                GROUP BY destination_port
                ORDER BY packet_count DESC
                LIMIT ?
                """,
                (ip, limit),
            )
            rows = cursor.fetchall()
            return [{"port": r["destination_port"], "packet_count": r["packet_count"]} for r in rows]
        except sqlite3.OperationalError:
            return []
        finally:
            conn.close()

    def query(self, question: str) -> Dict[str, Any]:
        """
        Parses natural language query for IP patterns and keywords,
        returning structured forensic telemetry facts.
        """
        ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
        found_ips = re.findall(ip_pattern, question)

        results = {}
        for ip in found_ips:
            summary = self.get_flow_summary(ip)
            flags = self.get_tcp_flag_distribution(ip)
            ports = self.get_targeted_ports(ip)
            results[ip] = {
                "summary": summary,
                "tcp_flags": flags,
                "top_targeted_ports": ports,
            }

        return {
            "query": question,
            "forensic_evidence": results,
            "provenance": f"SQLite flow_logs ({self.db_path})",
        }
