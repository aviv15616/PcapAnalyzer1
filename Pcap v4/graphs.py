import tkinter as tk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import numpy as np
from collections import Counter


class Graphs(tk.Toplevel):
    def __init__(self, master, data):
        super().__init__(master)
        self.title("PCAP Graphs")
        self.geometry("1000x800")  # Increased window size for better visualization

        self.data = data
        self.canvas = None  # Placeholder for the graph canvas

        # Create a frame for buttons to align them horizontally
        button_frame = tk.Frame(self)
        button_frame.pack(pady=10)

        self.avg_packet_size_button = tk.Button(button_frame, text="Avg Packet Size", command=self.plot_avg_packet_size)
        self.avg_packet_size_button.pack(side=tk.LEFT, padx=5)

        self.avg_iat_button = tk.Button(button_frame, text="Avg IAT", command=self.plot_avg_iat)
        self.avg_iat_button.pack(side=tk.LEFT, padx=5)

        self.ip_protocols_button = tk.Button(button_frame, text="IP Protocols Distribution", command=self.plot_ip_protocols)
        self.ip_protocols_button.pack(side=tk.LEFT, padx=5)

        self.packet_size_button = tk.Button(button_frame, text="Packet Size Distribution", command=self.plot_packet_size)
        self.packet_size_button.pack(side=tk.LEFT, padx=5)

        self.tcp_flags_button = tk.Button(button_frame, text="TCP Flags Distribution", command=self.plot_tcp_flags)
        self.tcp_flags_button.pack(side=tk.LEFT, padx=5)

        self.inter_arrival_button = tk.Button(button_frame, text="Inter Arrival Distribution", command=self.plot_inter_arrival)
        self.inter_arrival_button.pack(side=tk.LEFT, padx=5)

        self.directional_flow_button = tk.Button(button_frame, text="Directional Flow", command=self.plot_directional_flow)
        self.directional_flow_button.pack(side=tk.LEFT, padx=5)

        self.http_distribution_button = tk.Button(button_frame, text="HTTP Distribution", command=self.plot_http_distribution)
        self.http_distribution_button.pack(side=tk.LEFT, padx=5)

        self.graph_frame = tk.Frame(self)
        self.graph_frame.pack(expand=True, fill=tk.BOTH)

    def plot_avg_packet_size(self):
        self.plot_graph("Avg Packet size (bytes)", "Average Packet Size (bytes)")

    def plot_avg_iat(self):
        self.plot_graph("Avg Packet IAT (seconds)", "Average Inter-Arrival Time (seconds)")

    def plot_http_distribution(self):
        if self.canvas:
            self.canvas.get_tk_widget().destroy()

        fig, ax = plt.subplots(figsize=(10, 6))

        http_per_pcap = {}

        for entry in self.data:
            pcap_file = entry["Pcap file"]
            http_per_pcap[pcap_file] = {"HTTP1": 0, "HTTP2": 0, "HTTP3": 0}
            for http_entry in entry["Http Count"].split():
                if '-' in http_entry:
                    key, value = http_entry.split('-')
                    http_per_pcap[pcap_file][key.upper()] = int(value)

        http_versions = ["HTTP1", "HTTP2", "HTTP3"]
        x = np.arange(len(http_versions))  # Base positions for HTTP versions
        width = 0.15  # Smaller bar width for spacing

        for i, (pcap_file, http_counts) in enumerate(http_per_pcap.items()):
            y = [http_counts[version] for version in http_versions]
            ax.bar(x + (i * width), y, width=width, label=pcap_file)  # Apply offset

        ax.set_xticks(x + (width * (len(http_per_pcap) / 2)))  # Adjust tick positions
        ax.set_xticklabels(http_versions, rotation=0)
        ax.set_xlabel("HTTP Versions")
        ax.set_ylabel("Packet Count")
        ax.set_title("HTTP Packets Distribution")
        ax.legend()

        self.display_graph(fig)

    def plot_ip_protocols(self):
        self.plot_category_graph("Ip protocols", "IP Protocols Distribution")

    def plot_tcp_flags(self):
        self.plot_category_graph("Tcp Flags", "TCP Flags Distribution")

    def plot_packet_size(self):
        self.plot_graph("Avg Packet size (bytes)", "Packet Size Distribution")

    def plot_inter_arrival(self):
        self.plot_graph("Avg Packet IAT (seconds)", "Inter Arrival Time Distribution")

    def plot_directional_flow(self):
        self.plot_graph("Flow Volume (bytes)", "Directional Flow")

    def plot_graph(self, column_name, ylabel):
        if self.canvas:
            self.canvas.get_tk_widget().destroy()

        fig, ax = plt.subplots(figsize=(8, 5))
        pcap_files = [entry["Pcap file"] for entry in self.data]
        values = [entry.get(column_name, 0) for entry in self.data]

        ax.bar(pcap_files, values)
        ax.set_xlabel("Pcap File")
        ax.set_ylabel(ylabel)
        ax.set_title(ylabel)
        ax.tick_params(axis='x', rotation=45)

        self.display_graph(fig)

    def plot_category_graph(self, column_name, ylabel):
        if self.canvas:
            self.canvas.get_tk_widget().destroy()

        fig, ax = plt.subplots(figsize=(10, 6))
        category_per_pcap = {}

        for entry in self.data:
            pcap_file = entry["Pcap file"]
            category_per_pcap[pcap_file] = Counter()
            for item in entry[column_name].split():
                if '-' in item:
                    key, value = item.split('-')
                    category_per_pcap[pcap_file][key] += int(value)

        categories = sorted(set(cat for pcap in category_per_pcap.values() for cat in pcap))
        x = np.arange(len(categories))
        width = 0.2  # Adjusted bar width for visibility

        for i, (pcap_file, category_counts) in enumerate(category_per_pcap.items()):
            y = [category_counts.get(category, 0) for category in categories]
            ax.bar(x + (i * width), y, width=width, label=pcap_file)

        ax.set_xticks(x + width / 2)
        ax.set_xticklabels(categories, rotation=45)
        ax.set_xlabel("Category")
        ax.set_ylabel(ylabel)
        ax.set_title(ylabel)
        ax.legend()

        self.display_graph(fig)

    def display_graph(self, fig):
        if self.canvas:
            self.canvas.get_tk_widget().destroy()

        plt.tight_layout()

        self.canvas = FigureCanvasTkAgg(fig, master=self.graph_frame)
        self.canvas.get_tk_widget().pack(expand=True, fill=tk.BOTH)
        self.canvas.draw()