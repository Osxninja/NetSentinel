"""
NetSentinel - Host PC Telemetry & Hardware Diagnostics
Author: Hardik
Developer / Organization: Hidden Eye Security

Extracts live system metrics, active network interfaces, CPU/RAM usage,
and active listening socket processes.
"""

__author__ = "Hardik"
__organization__ = "Hidden Eye Security"

import socket
import platform
import psutil
from typing import Dict, Any, List


def get_pc_telemetry() -> Dict[str, Any]:
    """
    Returns real-time system and network diagnostics for the host machine.
    """
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
    except Exception:
        hostname = "localhost"
        local_ip = "127.0.0.1"

    # CPU & Memory
    cpu_percent = psutil.cpu_percent(interval=None)
    cpu_count = psutil.cpu_count(logical=True)
    mem = psutil.virtual_memory()

    # Network Interfaces
    interfaces = []
    net_addrs = psutil.net_if_addrs()
    net_stats = psutil.net_if_stats()

    for if_name, addrs in net_addrs.items():
        is_up = net_stats[if_name].isup if if_name in net_stats else False
        ipv4 = [a.address for a in addrs if a.family == socket.AF_INET]
        if ipv4:
            interfaces.append({
                "name": if_name,
                "ip": ipv4[0],
                "is_up": is_up,
                "speed_mbps": net_stats[if_name].speed if if_name in net_stats else 0,
            })

    # Active Connections & Top Sockets
    active_conns = 0
    top_processes: List[Dict[str, Any]] = []
    seen_pids = set()

    try:
        conns = psutil.net_connections(kind="inet")
        active_conns = len(conns)

        for c in conns:
            if c.raddr and c.pid and c.pid not in seen_pids:
                seen_pids.add(c.pid)
                try:
                    p = psutil.Process(c.pid)
                    top_processes.append({
                        "pid": c.pid,
                        "name": p.name(),
                        "local": f"{c.laddr.ip}:{c.laddr.port}",
                        "remote": f"{c.raddr.ip}:{c.raddr.port}",
                        "status": c.status,
                    })
                    if len(top_processes) >= 8:
                        break
                except Exception:
                    pass
    except Exception:
        pass

    # Global Network I/O
    try:
        io_counters = psutil.net_io_counters()
        bytes_sent = io_counters.bytes_sent
        bytes_recv = io_counters.bytes_recv
    except Exception:
        bytes_sent = 0
        bytes_recv = 0

    return {
        "hostname": hostname,
        "local_ip": local_ip,
        "os": f"{platform.system()} {platform.release()} ({platform.architecture()[0]})",
        "cpu_percent": cpu_percent,
        "cpu_count": cpu_count,
        "memory_total_gb": round(mem.total / (1024 ** 3), 2),
        "memory_used_gb": round(mem.used / (1024 ** 3), 2),
        "memory_percent": mem.percent,
        "interfaces": interfaces,
        "active_connections": active_conns,
        "top_processes": top_processes,
        "bytes_sent": bytes_sent,
        "bytes_recv": bytes_recv,
    }
