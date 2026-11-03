"""
NetSentinel - Network Topology Knowledge Graph Tool
Author: Hardik
Developer / Organization: Hidden Eye Security

Graph-based data infrastructure mapping network asset metadata, MAC addresses,
device roles, departmental subnets, and host relationships.
"""

__author__ = "Hardik"
__organization__ = "Hidden Eye Security"

import re
from typing import Dict, Any, List, Optional
import networkx as nx


class NetworkTopologyKG:
    """
    In-memory Network Topology Knowledge Graph using NetworkX.
    Supports Cypher-like node/edge traversals and natural language query resolution.
    """

    def __init__(self):
        self.graph = nx.DiGraph()
        self._seed_default_enterprise_topology()

    def _seed_default_enterprise_topology(self) -> None:
        """Populates the topology graph with a representative corporate network model."""
        # 1. Subnets
        self.graph.add_node(
            "subnet:corp_finance",
            type="Subnet",
            cidr="192.168.1.0/24",
            department="Finance",
            security_zone="Internal-Corporate",
        )
        self.graph.add_node(
            "subnet:server_farm",
            type="Subnet",
            cidr="10.0.0.0/24",
            department="IT Infrastructure",
            security_zone="Internal-Server",
        )
        self.graph.add_node(
            "subnet:dmz",
            type="Subnet",
            cidr="172.16.0.0/24",
            department="SecOps",
            security_zone="DMZ",
        )

        # 2. Critical Servers
        self.graph.add_node(
            "10.0.0.1",
            type="Host",
            hostname="dc01.corp.internal",
            mac="00:50:56:A1:00:01",
            role="Primary Domain Controller & Active Directory",
            subnet="10.0.0.0/24",
            department="IT Infrastructure",
            criticality="CRITICAL",
            os="Windows Server 2022",
            authorized_ports=[53, 88, 135, 389, 445, 636, 3268],
        )
        self.graph.add_node(
            "10.0.0.5",
            type="Host",
            hostname="db-prod-sql01.corp.internal",
            mac="00:50:56:A1:00:05",
            role="Core Production Database Server",
            subnet="10.0.0.0/24",
            department="Database Engineering",
            criticality="CRITICAL",
            os="Ubuntu 22.04 LTS",
            authorized_ports=[22, 1433, 3306, 5432],
        )
        self.graph.add_node(
            "172.16.0.1",
            type="Host",
            hostname="dmz-proxy01.corp.internal",
            mac="00:50:56:B2:00:01",
            role="DMZ Reverse Proxy & WAF",
            subnet="172.16.0.0/24",
            department="SecOps",
            criticality="HIGH",
            os="Alpine Linux",
            authorized_ports=[80, 443],
        )

        # 3. Workstations
        self.graph.add_node(
            "192.168.1.100",
            type="Host",
            hostname="fin-wkst-100.corp.internal",
            mac="F8:75:A4:12:34:56",
            role="Finance Specialist Workstation",
            subnet="192.168.1.0/24",
            department="Finance",
            criticality="MEDIUM",
            os="Windows 11 Enterprise",
            authorized_ports=[445, 3389],
        )
        self.graph.add_node(
            "192.168.1.150",
            type="Host",
            hostname="fin-wkst-150.corp.internal",
            mac="F8:75:A4:78:90:AB",
            role="Contractor Accounting Workstation",
            subnet="192.168.1.0/24",
            department="Finance",
            criticality="LOW",
            os="Windows 11 Pro",
            authorized_ports=[445],
        )

        # 4. Topology Relationships / Edges
        self.graph.add_edge("192.168.1.100", "10.0.0.1", relationship="AUTHENTICATES_TO")
        self.graph.add_edge("192.168.1.100", "10.0.0.5", relationship="QUERIES_REPORTS")
        self.graph.add_edge("172.16.0.1", "10.0.0.5", relationship="REVERSE_PROXIES")

    def get_device_info(self, ip: str) -> Dict[str, Any]:
        """Retrieves metadata and role info for a given IP."""
        if ip in self.graph.nodes:
            info = dict(self.graph.nodes[ip])
            info["ip"] = ip
            info["authorized_peers"] = list(self.graph.successors(ip))
            return info
        return {
            "ip": ip,
            "type": "Unknown Host",
            "hostname": "unmanaged-host",
            "role": "External or Unmanaged Endpoint",
            "subnet": "Unknown",
            "department": "External / Unregistered",
            "criticality": "UNKNOWN",
            "authorized_peers": [],
        }

    def query(self, natural_language_question: str) -> Dict[str, Any]:
        """
        Translates natural language questions into knowledge graph node/edge retrievals.
        Extracts IPv4 patterns from question and returns relevant contextual entity profiles.
        """
        ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
        found_ips = re.findall(ip_pattern, natural_language_question)

        results = {}
        for ip in found_ips:
            results[ip] = self.get_device_info(ip)

        # If no explicit IP, return general subnet/topology context
        if not results:
            results["topology_summary"] = {
                "total_nodes": self.graph.number_of_nodes(),
                "total_edges": self.graph.number_of_edges(),
                "managed_subnets": ["192.168.1.0/24 (Finance)", "10.0.0.0/24 (Servers)", "172.16.0.0/24 (DMZ)"],
            }

        return {
            "query": natural_language_question,
            "resolved_entities": results,
            "provenance": "NetSentinel In-Memory Knowledge Graph",
        }
