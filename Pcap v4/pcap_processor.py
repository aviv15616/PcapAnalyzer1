import pyshark
from collections import Counter
import os
import asyncio


class PcapProcessor:
    def __init__(self):
        self.pcap_data = []

    def process_pcap(self, file_path):
        # Ensure the thread has an event loop
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        cap = pyshark.FileCapture(file_path, use_json=True)

        packet_count = 0
        total_size = 0
        start_time = None
        end_time = None
        http_counter = Counter()
        tcp_flags = Counter()
        ip_protocols = Counter()

        # Separate capture to count HTTP versions
        http_cap = pyshark.FileCapture(file_path, use_json=True, display_filter="http || http2 || http3")

        for packet in cap:
            packet_count += 1
            total_size += int(packet.length)

            if start_time is None:
                start_time = float(packet.sniff_time.timestamp())
            end_time = float(packet.sniff_time.timestamp())

            # TCP Flags Counting
            if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'flags'):
                flags = int(packet.tcp.flags, 16)
                if flags & 0x02: tcp_flags['SYN'] += 1
                if flags & 0x10: tcp_flags['ACK'] += 1
                if flags & 0x04: tcp_flags['RST'] += 1
                if flags & 0x08: tcp_flags['PSH'] += 1
                if flags & 0x01: tcp_flags['FIN'] += 1

            # IP Protocols Counting
            if hasattr(packet, 'ip') and hasattr(packet.ip, 'proto'):
                ip_protocols[packet.ip.proto] += 1

        # Count HTTP versions separately
        for packet in http_cap:
            if hasattr(packet, 'http'):
                http_counter['HTTP1'] += 1
            if hasattr(packet, 'http2'):
                http_counter['HTTP2'] += 1
            if hasattr(packet, 'http3'):
                http_counter['HTTP3'] += 1

        cap.close()
        http_cap.close()

        duration = (end_time - start_time) if start_time and end_time else 0
        avg_packet_size = total_size / packet_count if packet_count else 0
        avg_packet_iat = duration / packet_count if packet_count else 0

        self.pcap_data.append({
            "Pcap file": os.path.basename(file_path),
            "Flow size": packet_count,
            "Flow Volume (bytes)": total_size,
            "Flow duration (seconds)": round(duration, 2),
            "Avg Packet size (bytes)": round(avg_packet_size, 2),
            "Avg Packet IAT (seconds)": round(avg_packet_iat, 6),
            "Http Count": " ".join([f"{k}-{v}" for k, v in http_counter.items()]) or "0",
            "Tcp Flags": " ".join([f"{k}-{v}" for k, v in tcp_flags.items()]) or "N/A",
            "Ip protocols": " ".join([f"{k}-{v}" for k, v in ip_protocols.items()]) or "N/A",
        })
