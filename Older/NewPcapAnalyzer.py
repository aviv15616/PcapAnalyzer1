import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import matplotlib.pyplot as plt
import pandas as pd
import os
from tabulate import tabulate
import pyshark
import numpy as np
import threading
import asyncio


class PcapAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Pcap Traffic Analyzer")
        self.root.geometry("400x350")

        self.pcap_files = []
        self.max_files = 10
        self.pcap_data = pd.DataFrame()

        self.upload_button = tk.Button(root, text="Upload Pcap", command=self.upload_pcap)
        self.upload_button.pack(pady=10)

        self.progress_label = tk.Label(root, text="")
        self.progress_label.pack()

        self.progress_bar = ttk.Progressbar(root, orient=tk.HORIZONTAL, length=300, mode='determinate')
        self.progress_bar.pack(pady=10)

        self.show_table_button = tk.Button(root, text="Show Comparison Table", command=self.show_table,
                                           state=tk.DISABLED)
        self.show_table_button.pack(pady=10)

        self.show_graphs_button = tk.Button(root, text="Show Graphs", command=self.show_graphs_menu, state=tk.DISABLED)
        self.show_graphs_button.pack(pady=10)

    def upload_pcap(self):
        files = filedialog.askopenfilenames(filetypes=[("PCAP Files", "*.pcap")])
        if len(self.pcap_files) + len(files) > self.max_files:
            messagebox.showerror("Error", f"You can upload up to {self.max_files} files only.")
            return

        self.pcap_files.extend(files)
        self.upload_button.config(state=tk.DISABLED)  # Disable upload button
        self.show_table_button.config(state=tk.DISABLED)
        self.show_graphs_button.config(state=tk.DISABLED)

        self.progress_label.config(text="Processing PCAP files...")
        self.progress_bar['value'] = 0

        processing_thread = threading.Thread(target=self.process_pcap_files, daemon=True)
        processing_thread.start()

    def process_pcap_files(self):
        asyncio.set_event_loop(asyncio.new_event_loop())  # Fix for async issue in threads
        data = []
        total_files = len(self.pcap_files)

        for index, pcap_file in enumerate(self.pcap_files):
            cap = pyshark.FileCapture(pcap_file, use_json=True)
            packet_sizes = [int(pkt.length) for pkt in cap if hasattr(pkt, 'length')]
            inter_arrival_times = [float(cap[i].sniff_time.timestamp()) - float(cap[i - 1].sniff_time.timestamp()) for i
                                   in range(1, len(cap))]

            total_packets = len(packet_sizes)
            total_bytes = sum(packet_sizes)
            median_packet_size = np.median(packet_sizes) if total_packets > 0 else 0
            mean_packet_size = np.mean(packet_sizes) if total_packets > 0 else 0
            std_dev_packet_size = np.std(packet_sizes) if total_packets > 0 else 0
            variance_packet_size = np.var(packet_sizes) if total_packets > 0 else 0
            avg_inter_arrival = np.mean(inter_arrival_times) if inter_arrival_times else 0
            flow_duration = max(inter_arrival_times) if inter_arrival_times else 0
            burstiness = std_dev_packet_size / mean_packet_size if mean_packet_size > 0 else 0
            packet_loss_rate = np.random.uniform(0, 1)  # Placeholder for packet loss rate calculation
            transport_protocol = cap[0].highest_layer if len(cap) > 0 else "Unknown"

            tcp_flags_count = {"SYN": 0, "ACK": 0, "PSH": 0, "RST": 0, "FIN": 0}
            http2_count = sum(1 for pkt in cap if 'HTTP2' in pkt)
            ip_protocols = {}
            upload_packets, download_packets = 0, 0

            for pkt in cap:
                if 'IP' in pkt:
                    proto = pkt.ip.proto
                    ip_protocols[proto] = ip_protocols.get(proto, 0) + 1
                if 'TCP' in pkt:
                    for flag in tcp_flags_count.keys():
                        if hasattr(pkt.tcp, flag.lower()):
                            tcp_flags_count[flag] += 1
                if 'IP' in pkt and hasattr(pkt, 'ip') and hasattr(pkt.ip, 'src'):
                    if pkt.ip.src.startswith("192.168"):
                        upload_packets += 1
                    else:
                        download_packets += 1

            upload_download_ratio = upload_packets / download_packets if download_packets > 0 else 0

            data.append({
                "Pcap File": os.path.basename(pcap_file),
                "Avg Packet Size": mean_packet_size,
                "Avg Inter Arrival": avg_inter_arrival,
                "Median Packet Size (Bytes)": median_packet_size,
                "Std Dev Packet Size": std_dev_packet_size,
                "Variance Packet Size": variance_packet_size,
                "Flow Size": total_packets,
                "Flow Volume (MB)": total_bytes / (1024 * 1024),
                "Flow Duration (seconds)": flow_duration,
                "Burstiness": burstiness,
                "Packet Loss Rate (%)": packet_loss_rate,
                "Http2 Count": http2_count,
                "IP Protocols": str(ip_protocols),
                "TCP_Flags": str(tcp_flags_count),
                "Upload Packets": upload_packets,
                "Download Packets": download_packets,
                "Upload/Download Ratio": upload_download_ratio
            })
            cap.close()

            progress = ((index + 1) / total_files) * 100
            self.progress_bar['value'] = progress
            self.root.update_idletasks()

        self.pcap_data = pd.DataFrame(data)
        self.progress_label.config(text="Processing Complete!")
        self.progress_bar['value'] = 100
        self.upload_button.config(state=tk.NORMAL)  # Re-enable upload button
        self.show_table_button.config(state=tk.NORMAL)
        self.show_graphs_button.config(state=tk.NORMAL)
        messagebox.showinfo("Success", "All PCAP files have been successfully processed!")

    def show_graphs_menu(self):
        if self.pcap_data.empty:
            messagebox.showerror("Error", "No data available. Please upload PCAP files first.")
            return

        graph_window = tk.Toplevel(self.root)
        graph_window.title("Select Graph")
        graph_window.geometry("300x400")

        for column in self.pcap_data.columns[1:]:
            btn = tk.Button(graph_window, text=column, command=lambda g=column: self.plot_graph(g))
            btn.pack(pady=5)

    def show_table(self):
        pd.set_option('display.max_columns', None)
        pd.set_option('display.width', 1000)
        print(tabulate(self.pcap_data, headers='keys', tablefmt='grid'))
        messagebox.showinfo("Comparison Table", "Table displayed in console.")


if __name__ == "__main__":
    root = tk.Tk()
    app = PcapAnalyzerGUI(root)
    root.mainloop()