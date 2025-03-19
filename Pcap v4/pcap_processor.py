import pyshark
from collections import Counter
import os
import asyncio
import tkinter as tk
from tkinter import messagebox


class PcapProcessor:
    def __init__(self, sample_mode=False):  # Add a sample mode flag
        self.pcap_data = []
        self.processed_files = set()  # Track uploaded file names
        self.sample_mode = sample_mode  # Enable/Disable sampling

    def process_pcap(self, file_path):
        file_name = os.path.basename(file_path)
        sample_limit = 1000 if self.sample_mode else None  # Limit to 1000 packets if sampling enabled

        # Prevent duplicate file uploads
        if file_name in self.processed_files:
            self.show_message("Error: PCAP file with the same name already loaded.")
            return False

        if len(self.pcap_data) >= 10:
            return False  # Limit total PCAPs

        self.processed_files.add(file_name)
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            cap = pyshark.FileCapture(file_path, use_json=True)
        except Exception:
            return False

        packet_count = 0
        total_size = 0
        start_time = None
        end_time = None
        http_counter = Counter()
        tcp_flags = Counter()
        ip_protocols = Counter()
        iat_list = []  # Store all IAT values
        timestamps_list = []  # Store all packet timestamps
        packet_sizes = []  # ✅ Store all packet sizes
        flows = {}  # Store forward and backward packet counts per flow

        prev_time = None

        for packet in cap:
            if self.sample_mode and packet_count >= sample_limit:
                break
            packet_count += 1
            packet_length = int(packet.length)
            total_size += packet_length

            # ✅ Store packet sizes for distribution analysis
            packet_sizes.append(packet_length)

            # Track first and last packet time
            current_time = float(packet.sniff_time.timestamp())
            timestamps_list.append(current_time)  # Store the timestamp

            if start_time is None:
                start_time = current_time
            end_time = current_time

            # Calculate Inter-Packet Arrival Time (IAT)
            if prev_time is not None:
                iat_list.append(current_time - prev_time)
            prev_time = current_time

            # Extract flow direction (based on source-destination pair)
            if hasattr(packet, 'ip') and hasattr(packet, 'tcp'):
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
                src_port = packet.tcp.srcport
                dst_port = packet.tcp.dstport
                proto = "TCP"
            elif hasattr(packet, 'ip') and hasattr(packet, 'udp'):
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
                src_port = packet.udp.srcport
                dst_port = packet.udp.dstport
                proto = "UDP"
            else:
                continue  # Skip non-IP packets

            flow_key = (src_ip, dst_ip, src_port, dst_port, proto)
            reverse_flow_key = (dst_ip, src_ip, dst_port, src_port, proto)

            if flow_key not in flows and reverse_flow_key not in flows:
                flows[flow_key] = {"forward": 0, "backward": 0}

            if flow_key in flows:
                flows[flow_key]["forward"] += 1
            elif reverse_flow_key in flows:
                flows[reverse_flow_key]["backward"] += 1

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

            # HTTP Counting
            if hasattr(packet, 'http'):
                http_counter['HTTP1'] += 1
            if hasattr(packet, 'http2'):
                http_counter['HTTP2'] += 1
            if hasattr(packet, 'http3'):
                http_counter['HTTP3'] += 1

        cap.close()

        duration = (end_time - start_time) if start_time and end_time else 0
        avg_packet_size = total_size / packet_count if packet_count else 0
        avg_packet_iat = duration / packet_count if packet_count else 0

        # Calculate Flow Directionality Ratio
        total_forward = sum(flow["forward"] for flow in flows.values())
        total_backward = sum(flow["backward"] for flow in flows.values())

        # Fix: Prevent `inf` by using `total_forward` if no backward packets exist
        flow_directionality_ratio = round(total_forward / total_backward, 3) if total_backward > 0 else total_forward

        self.pcap_data.append({
            "Pcap file": file_name,
            "Flow size": packet_count,
            "Flow Volume (bytes)": total_size,
            "Flow duration (seconds)": round(duration, 2),
            "Avg Packet size (bytes)": round(avg_packet_size, 2),
            "Avg Packet IAT (seconds)": round(avg_packet_iat, 6),
            "Inter-Packet Arrival Times": iat_list,
            "Packet Timestamps": timestamps_list,
            "Packet Sizes": packet_sizes,  # ✅ Added for packet size distribution
            "Flow Directionality Ratio": flow_directionality_ratio,
            "Flows": flows,  # ✅ Store the full flow dictionary
            "Http Count": " ".join([f"{k}-{v}" for k, v in http_counter.items()]) or "0",
            "Tcp Flags": " ".join([f"{k}-{v}" for k, v in tcp_flags.items()]) or "N/A",
            "Ip protocols": " ".join([f"{k}-{v}" for k, v in ip_protocols.items()]) or "N/A",
        })

        return True

    def show_message(self, message):
        root = tk.Tk()
        root.withdraw()
        messagebox.showinfo("Notification", message)
