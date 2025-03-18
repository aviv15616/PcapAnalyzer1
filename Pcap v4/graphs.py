import tkinter as tk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import numpy as np
from collections import Counter
from matplotlib.widgets import CheckButtons




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

        self.packet_size_button = tk.Button(button_frame, text="Packet Size Distribution", command=self.plot_packet_size_distribution)
        self.packet_size_button.pack(side=tk.LEFT, padx=5)

        self.flow_size_vs_volume_button = tk.Button(
            button_frame, text="Flow Size vs. Volume", command=self.plot_flow_size_vs_volume
        )
        self.flow_size_vs_volume_button.pack(side=tk.LEFT, padx=5)
        self.iat_histogram_button = tk.Button(button_frame, text="IAT Histogram", command=self.plot_iat_histogram)
        self.iat_histogram_button.pack(side=tk.LEFT, padx=5)




        self.tcp_flags_button = tk.Button(button_frame, text="TCP Flags Distribution", command=self.plot_tcp_flags)
        self.tcp_flags_button.pack(side=tk.LEFT, padx=5)

        self.inter_arrival_button = tk.Button(button_frame, text="Inter Arrival Distribution", command=self.plot_inter_arrival)
        self.inter_arrival_button.pack(side=tk.LEFT, padx=5)

        self.directional_flow_button = tk.Button(button_frame, text="Directional Flow", command=self.plot_directional_flow)
        self.directional_flow_button.pack(side=tk.LEFT, padx=5)

        self.http_distribution_button = tk.Button(button_frame, text="HTTP Distribution", command=self.plot_http_distribution)
        self.http_distribution_button.pack(side=tk.LEFT, padx=5)
        self.bytes_per_second_button = tk.Button(button_frame, text="Bytes Per Second",
                                                 command=self.plot_bytes_per_second)
        self.bytes_per_second_button.pack(side=tk.LEFT, padx=5)

        self.graph_frame = tk.Frame(self)
        self.graph_frame.pack(expand=True, fill=tk.BOTH)


    def plot_avg_packet_size(self):
        self.plot_graph("Avg Packet size (bytes)", "Average Packet Size (bytes)")

    def plot_avg_iat(self):
        self.plot_graph("Avg Packet IAT (seconds)", "Average Inter-Arrival Time (seconds)")

    def plot_packet_size_distribution(self):
        if self.canvas:
            self.canvas.get_tk_widget().destroy()

        fig, ax = plt.subplots(figsize=(12, 6))

        packet_sizes_per_pcap = {}

        # Extract Packet Sizes for Each PCAP
        for entry in self.data:
            pcap_file = entry["Pcap file"]
            packet_sizes_per_pcap[pcap_file] = entry.get("Packet Sizes", [])

        # Handle cases where no valid data exists
        if all(len(sizes) == 0 for sizes in packet_sizes_per_pcap.values()):
            ax.text(0.5, 0.5, "No Packet Size Data Available", fontsize=12, ha='center', va='center')
            ax.set_xticks([])
            ax.set_yticks([])
        else:
            # Define consistent bins (cover full range of sizes across all PCAPs)
            all_sizes = [size for sizes in packet_sizes_per_pcap.values() for size in sizes]

            # Focus on a more relevant range (avoid extreme outliers)
            max_packet_size = min(max(all_sizes), 2000)  # Cut off at 2000 bytes
            bins = np.histogram_bin_edges(all_sizes, bins=30, range=(0, max_packet_size))

            # Define a **consistent color mapping** for all PCAPs
            color_map = plt.get_cmap("tab10")
            pcap_colors = {pcap: color_map(i) for i, pcap in enumerate(packet_sizes_per_pcap.keys())}

            bin_width = (bins[1] - bins[0]) / (len(packet_sizes_per_pcap) + 1)  # Adjust bar width

            for i, (pcap_file, sizes) in enumerate(packet_sizes_per_pcap.items()):
                if len(sizes) > 0:
                    hist, bin_edges = np.histogram(sizes, bins=bins)
                    bin_centers = (bin_edges[:-1] + bin_edges[1:]) / 2  # Get bin center for alignment

                    # Offset each dataset slightly in x-axis for side-by-side bars
                    ax.bar(bin_centers + (i * bin_width), hist, width=bin_width, label=pcap_file,
                           color=pcap_colors[pcap_file], edgecolor='black')

            ax.set_xlabel("Packet Size (bytes)")
            ax.set_ylabel("Frequency")
            ax.set_title("Distribution of Packet Sizes in PCAP Files")
            ax.legend()
            ax.set_xlim([0, max_packet_size])  # Limit x-axis to relevant range

        self.display_graph(fig)

    import matplotlib.pyplot as plt
    import numpy as np
    from matplotlib.widgets import CheckButtons

    def plot_bytes_per_second(self):
        if self.canvas:
            self.canvas.get_tk_widget().destroy()

        fig, ax = plt.subplots(figsize=(12, 6))

        bytes_per_second_per_pcap = {}
        pcap_lines = {}

        # Process data per PCAP
        for entry in self.data:
            pcap_file = entry["Pcap file"]
            timestamps = entry.get("Packet Timestamps", [])
            packet_sizes = entry.get("Flow Volume (bytes)", 0)

            if not timestamps or packet_sizes == 0:
                continue  # Skip empty or invalid data

            # Normalize timestamps to start at 0
            start_time = min(timestamps)
            relative_times = [t - start_time for t in timestamps]

            # Define time bins (1-second intervals)
            bins = np.arange(0, max(relative_times) + 1, 1)
            byte_counts, _ = np.histogram(relative_times, bins=bins, weights=[packet_sizes] * len(timestamps))

            bytes_per_second_per_pcap[pcap_file] = (bins[:-1], byte_counts)

        # Offset for better visualization
        colors = plt.get_cmap("tab10")

        for i, (pcap_file, (time_bins, byte_counts)) in enumerate(bytes_per_second_per_pcap.items()):
            line, = ax.plot(time_bins, byte_counts, marker='o', linestyle='-', label=pcap_file, color=colors(i))
            pcap_lines[pcap_file] = line

        ax.set_xlabel("Time (seconds)")
        ax.set_ylabel("Bytes Transferred Per Second")
        ax.set_title("Bytes Transferred Per Second Over Time for Each PCAP")
        ax.legend()
        ax.grid(True)

        # Add Check Buttons for Toggling
        rax = plt.axes([0.85, 0.4, 0.1, 0.3])  # Position the check buttons on the side
        check_labels = list(pcap_lines.keys())
        visibility = [True] * len(check_labels)

        self.check_buttons = CheckButtons(rax, check_labels,
                                          visibility)  # Store it in self to prevent garbage collection

        def toggle_visibility(label):
            line = pcap_lines[label]
            line.set_visible(not line.get_visible())
            fig.canvas.draw_idle()  # Force UI refresh

        self.check_buttons.on_clicked(toggle_visibility)

        self.display_graph(fig)

    def plot_iat_histogram(self):
        if self.canvas:
            self.canvas.get_tk_widget().destroy()

        fig, ax = plt.subplots(figsize=(10, 6))

        # Extract IAT values for each PCAP
        iat_data_per_pcap = {}
        for entry in self.data:
            pcap_file = entry["Pcap file"]
            iat_data_per_pcap[pcap_file] = entry.get("Inter-Packet Arrival Times", [])

        # Check if any IAT data exists
        if all(len(iat) == 0 for iat in iat_data_per_pcap.values()):
            ax.text(0.5, 0.5, "No IAT Data Available", fontsize=12, ha='center', va='center')
            ax.set_xticks([])
            ax.set_yticks([])
            return self.display_graph(fig)

        # Define bins for IAT range (0 to 0.09 seconds)
        bins = np.linspace(0, 0.09, 30)
        bin_width = (bins[1] - bins[0]) / (len(iat_data_per_pcap) + 1)  # Adjust bar width

        # Define color mapping for each PCAP
        color_map = plt.get_cmap("tab10")
        pcap_colors = {pcap: color_map(i) for i, pcap in enumerate(iat_data_per_pcap.keys())}

        # Plot histogram with offset bars (side by side)
        for i, (pcap_file, iat_data) in enumerate(iat_data_per_pcap.items()):
            if len(iat_data) > 0:
                ax.hist(
                    iat_data, bins=bins - (i * bin_width), alpha=0.7, label=pcap_file,
                    color=pcap_colors[pcap_file], edgecolor='black', width=bin_width
                )

        ax.set_xlabel("Inter-Packet Arrival Time (seconds)")
        ax.set_ylabel("Frequency")
        ax.set_title("IAT Distribution Across All PCAPs (Side by Side)")
        ax.legend()

        self.display_graph(fig)

    def plot_flow_size_vs_volume(data):
        if not data:
            print("No data available for plotting.")
            return

        fig, ax = plt.subplots(figsize=(10, 6))

        # Extract flow size and flow volume data
        flow_sizes = [entry["Flow size"] for entry in data]
        flow_volumes = [entry["Flow Volume (bytes)"] for entry in data]
        labels = [entry["Pcap file"] for entry in data]

        # Assign colors based on PCAP file
        unique_pcaps = list(set(labels))
        color_map = plt.get_cmap("tab10")
        pcap_colors = {pcap: color_map(i) for i, pcap in enumerate(unique_pcaps)}

        # Scatter plot with colors
        for i, pcap_file in enumerate(labels):
            ax.scatter(
                flow_sizes[i], flow_volumes[i],
                color=pcap_colors[pcap_file],
                edgecolors='black',
                alpha=0.7,
                label=pcap_file if pcap_file not in pcap_colors else ""
            )

        ax.set_xlabel("Flow Size (Number of Packets)")
        ax.set_ylabel("Flow Volume (Total Bytes Transferred)")
        ax.set_title("Flow Size vs. Flow Volume (Traffic Types)")

        # Show unique legend
        handles = [plt.Line2D([0], [0], marker='o', color='w', markerfacecolor=pcap_colors[pcap], markersize=10)
                   for pcap in unique_pcaps]
        ax.legend(handles, unique_pcaps, title="Traffic Type", loc="upper right")

        ax.grid(True)
        plt.show()

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