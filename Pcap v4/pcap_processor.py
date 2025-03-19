import pyshark
from collections import Counter
import os
import asyncio
import numpy as np
import tkinter as tk
from tkinter import messagebox


class PcapProcessor:
    def __init__(self, sample_mode=False):
        self.pcap_data = []
        self.processed_files = set()
        self.sample_mode = sample_mode

    def process_pcap(self, file_path):
        file_name = os.path.basename(file_path)
        sample_limit = 1000 if self.sample_mode else None

        if file_name in self.processed_files:
            self.show_message("Error: PCAP file with the same name already loaded.")
            return False

        if len(self.pcap_data) >= 10:
            return False

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
        iat_list = []
        timestamps_list = []
        packet_sizes = []
        flows = {}

        prev_time = None

        for packet in cap:
            if self.sample_mode and packet_count >= sample_limit:
                break
            packet_count += 1
            packet_length = int(packet.length)
            total_size += packet_length

            packet_sizes.append(packet_length)

            current_time = float(packet.sniff_time.timestamp())
            timestamps_list.append(current_time)

            if start_time is None:
                start_time = current_time
            end_time = current_time

            if prev_time is not None:
                iat_list.append(current_time - prev_time)
            prev_time = current_time

            # ✅ Extract Source & Destination IPs
            if hasattr(packet, 'ip'):
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
                proto = packet.ip.proto  # Capture ALL IP protocols

                # ✅ Extract Ports (if available)
                src_port = getattr(packet, 'tcp', getattr(packet, 'udp', None))
                dst_port = getattr(packet, 'tcp', getattr(packet, 'udp', None))
                src_port = src_port.srcport if src_port else "N/A"
                dst_port = dst_port.dstport if dst_port else "N/A"

                # ✅ Store protocol counts
                ip_protocols[proto] += 1

                # ✅ Flow Tracking for All Protocols
                flow_key = (src_ip, dst_ip, src_port, dst_port, proto)
                reverse_flow_key = (dst_ip, src_ip, dst_port, src_port, proto)

                if flow_key not in flows and reverse_flow_key not in flows:
                    flows[flow_key] = {"forward": 0, "backward": 0}

                if flow_key in flows:
                    flows[flow_key]["forward"] += 1
                elif reverse_flow_key in flows:
                    flows[reverse_flow_key]["backward"] += 1

            # ✅ TCP Flag Counting (Only for TCP Packets)
            if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'flags'):
                flags = int(packet.tcp.flags, 16)
                if flags & 0x02: tcp_flags['SYN'] += 1
                if flags & 0x10: tcp_flags['ACK'] += 1
                if flags & 0x04: tcp_flags['RST'] += 1
                if flags & 0x08: tcp_flags['PSH'] += 1
                if flags & 0x01: tcp_flags['FIN'] += 1

            # ✅ HTTP Version Counting
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

        total_forward = sum(flow["forward"] for flow in flows.values())
        total_backward = sum(flow["backward"] for flow in flows.values())

        flow_directionality_ratio = round(total_forward / total_backward, 3) if total_backward > 0 else total_forward

        # ✅ **Compute Burstiness Factors**
        pmr_value = self.calculate_pmr(packet_sizes, iat_list)
        mmr_value = self.calculate_mmr(packet_sizes, timestamps_list)
        cv_value = self.calculate_cv(iat_list)

        self.pcap_data.append({
            "Pcap file": file_name,
            "Flow size": packet_count,
            "Flow Volume (bytes)": total_size,
            "Flow duration (seconds)": round(duration, 2),
            "Avg Packet size (bytes)": round(avg_packet_size, 2),
            "Avg Packet IAT (seconds)": round(avg_packet_iat, 6),
            "Inter-Packet Arrival Times": iat_list,
            "Packet Timestamps": timestamps_list,
            "Packet Sizes": packet_sizes,
            "Flow Directionality Ratio": flow_directionality_ratio,
            "Flows": flows,
            "Http Count": " ".join([f"{k}-{v}" for k, v in http_counter.items()]) or "0",
            "Tcp Flags": " ".join([f"{k}-{v}" for k, v in tcp_flags.items()]) or "N/A",
            "Ip protocols": " ".join([f"{k}-{v}" for k, v in ip_protocols.items()]) or "N/A",
            "PMR": round(pmr_value, 2),
            "MMR": round(mmr_value, 2),
            "CV": round(cv_value, 2),
        })

        return True

    def calculate_pmr(self, packet_sizes, iat_list):
        if not packet_sizes or not iat_list:
            return 0

        packet_sizes = packet_sizes[:len(iat_list)]
        iat_array = np.array(iat_list)
        packet_sizes_array = np.array(packet_sizes)
        iat_array[iat_array <= 0] = 1e-6
        throughput = packet_sizes_array / iat_array

        mean_throughput = np.mean(throughput)
        if mean_throughput == 0:
            return 0

        return np.nan_to_num(np.max(throughput) / mean_throughput, nan=0)

    def calculate_mmr(self, packet_sizes, timestamps):
        if not packet_sizes or not timestamps:
            return 0.0
        time_windows = {}
        for size, ts in zip(packet_sizes, timestamps):
            window = int(ts)
            time_windows[window] = time_windows.get(window, 0) + size
        max_rate = max(time_windows.values()) if time_windows else 0
        mean_rate = np.mean(list(time_windows.values())) if time_windows else 0
        return max_rate / mean_rate if mean_rate > 0 else 0.0

    def calculate_cv(self, iat_list):
        if len(iat_list) < 2:
            return 0.0
        return np.std(iat_list) / np.mean(iat_list) if np.mean(iat_list) > 0 else 0.0

    def show_message(self, message):
        root = tk.Tk()
        root.withdraw()
        messagebox.showinfo("Notification", message)
