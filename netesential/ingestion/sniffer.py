"""
NetSentinel - Packet Sniffer Ingestion Engine
Author: Hardik
Developer / Organization: Hidden Eye Security

Captures raw network frames using Scapy, applies kernel-level BPF filtering,
prunes upper-layer protocol dissections, and deposits normalized flow dictionaries
into a bounded thread-safe ring buffer.
"""

__author__ = "Hardik"
__organization__ = "Hidden Eye Security"

import time
import queue
import logging
import threading
from typing import Optional, Dict, Any, List

logger = logging.getLogger("netsentinel.sniffer")

try:
    from scapy.all import conf, sniff, Ether, IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    conf = None


class PacketSnifferThread(threading.Thread):
    """
    Dedicated I/O background thread encapsulating Scapy packet capture.
    Utilizes kernel-level BPF socket offloading and protocol layer pruning
    to achieve maximum frames-per-second processing speed without GIL lockup.
    """

    def __init__(
        self,
        packet_queue: queue.Queue,
        bpf_filter: str = "ip or vlan",
        interface: Optional[str] = None,
        prune_layers: bool = True,
        name: str = "NetSentinel-Sniffer",
    ):
        super().__init__(name=name, daemon=True)
        self.packet_queue = packet_queue
        self.bpf_filter = bpf_filter
        self.interface = interface
        self.stop_event = threading.Event()

        # Telemetry metrics
        self.captured_packets: int = 0
        self.dropped_packets: int = 0

        if SCAPY_AVAILABLE and prune_layers and conf is not None:
            self._apply_protocol_layer_pruning()

    def _apply_protocol_layer_pruning(self) -> None:
        """
        Prunes upper-layer protocols from Scapy's dissection stack, restricting
        dissection to Ethernet, IP, TCP, UDP, and ICMP to eliminate high-overhead
        application payload dissection.
        """
        try:
            conf.layers.filter([Ether, IP, TCP, UDP, ICMP])
            logger.info("Scapy protocol layer pruning active: [Ether, IP, TCP, UDP, ICMP]")
        except Exception as e:
            logger.warning("Could not apply Scapy layer filter: %s", e)

    def parse_packet(self, packet: Any) -> Optional[Dict[str, Any]]:
        """
        Extracts normalized flow telemetry fields from a captured Scapy frame.
        """
        if not SCAPY_AVAILABLE:
            return None

        # Check for IP layer (IPv4)
        if not packet.haslayer(IP):
            return None

        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        pkt_len = len(packet)
        ts = float(getattr(packet, "time", time.time()))

        src_port: Optional[int] = None
        dst_port: Optional[int] = None
        tcp_flags: Optional[str] = None
        window_size: Optional[int] = None

        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            protocol = "TCP"
            src_port = int(tcp_layer.sport)
            dst_port = int(tcp_layer.dport)
            tcp_flags = str(tcp_layer.flags)
            window_size = int(tcp_layer.window)
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            protocol = "UDP"
            src_port = int(udp_layer.sport)
            dst_port = int(udp_layer.dport)
        elif packet.haslayer(ICMP):
            protocol = "ICMP"
        else:
            proto_num = getattr(ip_layer, "proto", 0)
            protocol = f"IP-{proto_num}"

        return {
            "timestamp": ts,
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "source_port": src_port,
            "destination_port": dst_port,
            "protocol": protocol,
            "packet_length": pkt_len,
            "tcp_flags": tcp_flags,
            "window_size": window_size,
        }

    def _packet_callback(self, packet: Any) -> None:
        """
        Sniff callback invoked per received packet frame.
        """
        if self.stop_event.is_set():
            return

        flow_data = self.parse_packet(packet)
        if flow_data is None:
            return

        self.captured_packets += 1
        try:
            # Non-blocking put to bounded queue; discard if full to avoid unbounded buffer growth
            self.packet_queue.put_nowait(flow_data)
        except queue.Full:
            self.dropped_packets += 1
            if self.dropped_packets % 1000 == 1:
                logger.warning(
                    "Ring buffer full! Dropped %d packets due to ingestion backpressure",
                    self.dropped_packets,
                )

    def enqueue_flow_dict(self, flow_dict: Dict[str, Any]) -> bool:
        """
        Helper method allowing direct insertion of synthetic/pre-parsed flow records.
        """
        self.captured_packets += 1
        try:
            self.packet_queue.put(flow_dict, block=True, timeout=0.5)
            return True
        except queue.Full:
            self.dropped_packets += 1
            return False

    def _run_host_live_sniffer(self) -> None:
        """
        Fallback live capture engine: Monitors real network traffic from the active host
        using OS network socket telemetry (psutil). Captures live connections, remote IPs,
        ports, and traffic without requiring kernel drivers or administrator privileges.
        """
        try:
            import psutil
            import socket
        except ImportError:
            logger.error("psutil is required for host-level live traffic monitoring.")
            return

        logger.info("Engaging Live Host Connection Telemetry Monitor for real network traffic...")
        seen_states = {}
        last_io = psutil.net_io_counters()

        while not self.stop_event.is_set():
            now = time.time()
            try:
                conns = psutil.net_connections(kind="inet")
            except Exception:
                time.sleep(0.1)
                continue

            try:
                cur_io = psutil.net_io_counters()
                bytes_delta = max(0, (cur_io.bytes_sent + cur_io.bytes_recv) - (last_io.bytes_sent + last_io.bytes_recv))
                last_io = cur_io
            except Exception:
                bytes_delta = 0

            for c in conns:
                if self.stop_event.is_set():
                    break
                if not c.raddr:
                    continue

                key = (c.laddr.ip, c.laddr.port, c.raddr.ip, c.raddr.port)
                prev_status = seen_states.get(key)

                # Capture if new connection, status changed, or every 2 seconds for active sessions
                if prev_status != c.status or (now - seen_states.get(f"{key}:time", 0)) > 2.0:
                    seen_states[key] = c.status
                    seen_states[f"{key}:time"] = now

                    proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
                    flags = "A"
                    if c.status == "SYN_SENT":
                        flags = "S"
                    elif c.status == "SYN_RECV":
                        flags = "SA"
                    elif c.status in ("CLOSE_WAIT", "FIN_WAIT1"):
                        flags = "FA"
                    elif c.status == "TIME_WAIT":
                        flags = "F"

                    length = 64
                    if bytes_delta > 0:
                        length = min(1500, max(64, bytes_delta // max(1, len(conns))))

                    flow = {
                        "timestamp": now,
                        "source_ip": c.laddr.ip,
                        "destination_ip": c.raddr.ip,
                        "source_port": c.laddr.port,
                        "destination_port": c.raddr.port,
                        "protocol": proto,
                        "packet_length": length,
                        "tcp_flags": flags,
                        "window_size": 65535,
                    }

                    self.captured_packets += 1
                    try:
                        self.packet_queue.put_nowait(flow)
                    except queue.Full:
                        self.dropped_packets += 1

            time.sleep(0.08)

    def run(self) -> None:
        """
        Main sniffer loop running on the dedicated background I/O thread.
        Attempts raw socket / Npcap kernel sniffing first, automatically
        falling back to live host network connection monitoring if kernel
        packet drivers are not installed.
        """
        logger.info(
            "Starting PacketSnifferThread (Filter: '%s', Interface: %s)",
            self.bpf_filter,
            self.interface or "default",
        )

        scapy_success = False

        if SCAPY_AVAILABLE:
            try:
                sniff(
                    filter=self.bpf_filter,
                    prn=self._packet_callback,
                    store=False,
                    iface=self.interface if self.interface else None,
                    stop_filter=lambda _: self.stop_event.is_set(),
                    timeout=1.0,
                )
                scapy_success = True
            except Exception as e:
                logger.info(
                    "Raw kernel packet sniffing unavailable (%s). Falling back to Live Host Telemetry Engine.",
                    e,
                )

        if not scapy_success and not self.stop_event.is_set():
            # Engage live host telemetry capture
            self._run_host_live_sniffer()

        logger.info(
            "PacketSnifferThread stopped. Total captured: %d, Dropped: %d",
            self.captured_packets,
            self.dropped_packets,
        )

    def stop(self, timeout: float = 2.0) -> None:
        """
        Signals the sniffer thread to stop and joins.
        """
        self.stop_event.set()
        self.join(timeout=timeout)
