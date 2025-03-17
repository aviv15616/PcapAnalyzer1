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
        sample_limit = 1000 if self.sample_mode else None  # Only process 1000 packets if sampling is enabled

        # Ensure no duplicate file uploads
        if file_name in self.processed_files:
            self.show_message("Error: PCAP file with the same name already loaded.")
            return False

        # Ensure only up to 10 files can be processed
        if len(self.pcap_data) >= 10:
            return False

        self.processed_files.add(file_name)

        # Ensure the thread has an event loop
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

        for packet in cap:
            if self.sample_mode and packet_count >= sample_limit:
                break
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

            # HTTP Counting within the same capture
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

        self.pcap_data.append({
            "Pcap file": file_name,
            "Flow size": packet_count,
            "Flow Volume (bytes)": total_size,
            "Flow duration (seconds)": round(duration, 2),
            "Avg Packet size (bytes)": round(avg_packet_size, 2),
            "Avg Packet IAT (seconds)": round(avg_packet_iat, 6),
            "Http Count": " ".join([f"{k}-{v}" for k, v in http_counter.items()]) or "0",
            "Tcp Flags": " ".join([f"{k}-{v}" for k, v in tcp_flags.items()]) or "N/A",
            "Ip protocols": " ".join([f"{k}-{v}" for k, v in ip_protocols.items()]) or "N/A",
        })

        return True

    def show_message(self, message):
        root = tk.Tk()
        root.withdraw()
        messagebox.showinfo("Notification", message)