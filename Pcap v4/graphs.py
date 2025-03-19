import tkinter as tk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import numpy as np
from collections import Counter
from matplotlib.widgets import CheckButtons,RadioButtons




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
        self.flow_size_over_pcap_button = tk.Button(
            button_frame, text="Flow Size Over PCAP", command=self.plot_flow_size_over_pcap
        )
        self.flow_size_over_pcap_button.pack(side=tk.LEFT, padx=5)

        self.flow_volume_over_pcap_button = tk.Button(
            button_frame, text="Flow Volume Over PCAP", command=self.plot_flow_volume_over_pcap
        )
        self.flow_volume_over_pcap_button.pack(side=tk.LEFT, padx=5)

        self.flow_dir_button = tk.Button(button_frame, text="Flow Dir",
                                            command=self.plot_flow_dir)
        self.flow_dir_button.pack(side=tk.LEFT, padx=5)
        self.burstiness_button = tk.Button(
            button_frame, text="Burstiness", command=self.plot_burstiness
        )
        self.burstiness_button.pack(side=tk.LEFT, padx=5)



        self.http_distribution_button = tk.Button(button_frame, text="HTTP Distribution", command=self.plot_http_distribution)
        self.http_distribution_button.pack(side=tk.LEFT, padx=5)
        self.bytes_per_second_button = tk.Button(button_frame, text="Bytes Per Second",
                                                 command=self.plot_bytes_per_second)
        self.bytes_per_second_button.pack(side=tk.LEFT, padx=5)

        self.graph_frame = tk.Frame(self)
        self.graph_frame.pack(expand=True, fill=tk.BOTH)

    import matplotlib.pyplot as plt
    import numpy as np
    from matplotlib.widgets import RadioButtons

    def plot_burstiness(self):
        if self.canvas:
            self.canvas.get_tk_widget().destroy()

        fig, ax = plt.subplots(figsize=(10, 6))

        # Extract PCAP names and values
        pcap_files = [entry["Pcap file"] for entry in self.data]
        pmr_values = np.array([entry.get("PMR", 0) for entry in self.data])
        mmr_values = np.array([entry.get("MMR", 0) for entry in self.data])
        cv_values = np.array([entry.get("CV", 0) for entry in self.data])

        # Define colors for each PCAP
        unique_pcaps = list(set(pcap_files))
        color_map = plt.get_cmap("tab10")
        pcap_colors = {pcap: color_map(i) for i, pcap in enumerate(unique_pcaps)}

        # Set default factor as PMR
        selected_factor = "PMR"
        values = pmr_values
        max_value = max(values) * 1.1  # Add 10% padding for visibility
        y_ticks = np.linspace(0, max_value, 5)  # Dynamically scale Y-axis

        # Plot with PMR as default
        bars = ax.bar(pcap_files, values, color=[pcap_colors[pcap] for pcap in pcap_files])
        ax.set_ylabel("Burstiness Value")
        ax.set_xlabel("PCAP Files")
        ax.set_title("Burstiness Factors (PMR, MMR, CV)")
        ax.set_xticklabels(pcap_files, rotation=45, ha="right")
        ax.set_ylim(0, max_value)
        ax.set_yticks(y_ticks)

        # Draggable legend
        legend_labels = [plt.Line2D([0], [0], marker='o', color='w', markerfacecolor=pcap_colors[pcap], markersize=10)
                         for pcap in unique_pcaps]
        legend = ax.legend(legend_labels, unique_pcaps, title="PCAPs", loc="upper right", frameon=True)
        legend.set_draggable(True)

        # Radio Buttons for selecting PMR, MMR, or CV
        rax = plt.axes([0.8, 0.4, 0.15, 0.2], frameon=True, facecolor="lightgray")
        self.radio_buttons_burstiness = RadioButtons(rax, ["PMR", "MMR", "CV"], active=0)

        def update_plot(label):
            """ Update the bar graph based on selected burstiness metric. """
            nonlocal values, max_value, y_ticks

            if label == "PMR":
                values = pmr_values
            elif label == "MMR":
                values = mmr_values
            else:  # CV
                values = cv_values

            max_value = max(values) * 1.1  # Scale max value with padding
            y_ticks = np.linspace(0, max_value, 5)  # Adjust Y-axis tick levels

            # Update bar heights
            for bar, value in zip(bars, values):
                bar.set_height(value)

            # Adjust Y-axis dynamically
            ax.set_ylim(0, max_value)
            ax.set_yticks(y_ticks)
            fig.canvas.draw_idle()

        self.radio_buttons_burstiness.on_clicked(update_plot)  # ✅ Persistent event binding

        self.display_graph(fig)

    def plot_avg_packet_size(self):
        self.plot_graph("Avg Packet size (bytes)", "Average Packet Size (bytes)")

    def plot_avg_iat(self):
        self.plot_graph("Avg Packet IAT (seconds)", "Average Inter-Arrival Time (seconds)")

    import tkinter as tk


    class Graphs(tk.Toplevel):
        def __init__(self, master, data):
            super().__init__(master)
            self.title("PCAP Graphs")
            self.geometry("1000x800")

            self.data = data
            self.canvas = None  # Placeholder for graph canvas
            self.radio_buttons = None  # Reference storage for buttons
            self.legend = None  # Store the legend reference

            button_frame = tk.Frame(self)
            button_frame.pack(pady=10)

            self.packet_size_button = tk.Button(button_frame, text="Packet Size Distribution",
                                                command=self.plot_packet_size_distribution)
            self.packet_size_button.pack(side=tk.LEFT, padx=5)

            self.graph_frame = tk.Frame(self)
            self.graph_frame.pack(expand=True, fill=tk.BOTH)

    def plot_packet_size_distribution(self):
        if self.canvas:
            self.canvas.get_tk_widget().destroy()

        fig, ax = plt.subplots(figsize=(12, 6))

        packet_sizes_per_pcap = {entry["Pcap file"]: entry.get("Packet Sizes", []) for entry in self.data}

        if all(len(sizes) == 0 for sizes in packet_sizes_per_pcap.values()):
            ax.text(0.5, 0.5, "No Packet Size Data Available", fontsize=12, ha='center', va='center')
            ax.set_xticks([])
            ax.set_yticks([])
            return self.display_graph(fig)

        selected_pcap = next((pcap for pcap, sizes in packet_sizes_per_pcap.items() if sizes), None)

        def update_histogram(pcap_name):
            ax.clear()
            sizes = packet_sizes_per_pcap.get(pcap_name, [])

            if not sizes:
                ax.text(0.5, 0.5, f"No Packet Size Data for {pcap_name}", fontsize=12, ha='center', va='center')
                ax.set_xticks([])
                ax.set_yticks([])
            else:
                bins = np.linspace(0, max(sizes), 30)
                ax.hist(sizes, bins=bins, color="royalblue", edgecolor="black", alpha=0.7)
                ax.set_xlabel("Packet Size (Bytes)")
                ax.set_ylabel("Packet Count")
                ax.set_title(f"Packet Size Distribution for {pcap_name}")

            fig.canvas.draw_idle()

        update_histogram(selected_pcap)

        # Properly frame radio buttons and make them draggable
        rax = plt.axes([0.7, 0.4, 0.2, 0.3], facecolor="lightgray", frameon=True)  # Wider box for text to fit properly
        self.radio_buttons_packet_size = RadioButtons(rax, list(packet_sizes_per_pcap.keys()),
                                                      active=list(packet_sizes_per_pcap.keys()).index(selected_pcap))

        def on_pcap_select(label):
            update_histogram(label)

        self.radio_buttons_packet_size.on_clicked(on_pcap_select)

        self.display_graph(fig)

    def plot_iat_histogram(self):
        if self.canvas:
            self.canvas.get_tk_widget().destroy()

        fig, ax = plt.subplots(figsize=(10, 6))

        # Extract IAT values for each PCAP
        iat_data_per_pcap = {entry["Pcap file"]: entry.get("Inter-Packet Arrival Times", []) for entry in self.data}

        if all(len(iat) == 0 for iat in iat_data_per_pcap.values()):
            ax.text(0.5, 0.5, "No IAT Data Available", fontsize=12, ha='center', va='center')
            ax.set_xticks([])
            ax.set_yticks([])
            return self.display_graph(fig)

        # Get the first available PCAP as the default selection
        selected_pcap = next((pcap for pcap, iat in iat_data_per_pcap.items() if iat), None)

        def update_histogram(pcap_name):
            ax.clear()
            iat_data = iat_data_per_pcap.get(pcap_name, [])

            if not iat_data:
                ax.text(0.5, 0.5, f"No IAT Data for {pcap_name}", fontsize=12, ha='center', va='center')
                ax.set_xticks([])
                ax.set_yticks([])
            else:
                bins = np.linspace(0, 0.09, 30)  # Set fixed bin range (0 to 90ms)
                ax.hist(iat_data, bins=bins, color="royalblue", edgecolor="black", alpha=0.7)
                ax.set_xlabel("Inter-Packet Arrival Time (seconds)")
                ax.set_ylabel("Frequency")
                ax.set_title(f"IAT Histogram for {pcap_name}")

            fig.canvas.draw_idle()

        # Initialize with the first valid PCAP
        update_histogram(selected_pcap)

        # ✅ Store Radio Buttons in `self.radio_buttons_iat` to prevent garbage collection
        rax = plt.axes([0.85, 0.4, 0.1, 0.3])
        self.radio_buttons_iat = RadioButtons(rax, list(iat_data_per_pcap.keys()),
                                              active=list(iat_data_per_pcap.keys()).index(selected_pcap))

        def on_pcap_select(label):
            update_histogram(label)

        self.radio_buttons_iat.on_clicked(on_pcap_select)  # ✅ Persistent event binding

        self.display_graph(fig)





    def plot_ip_protocols(self):
        self.plot_category_graph("Ip protocols", "IP Protocols Distribution")

    def plot_tcp_flags(self):
        self.plot_category_graph("Tcp Flags", "TCP Flags Distribution")

    def plot_flow_dir(self):
        if self.canvas:
            self.canvas.get_tk_widget().destroy()

        fig, ax = plt.subplots(figsize=(10, 6))

        forward_counts = []
        backward_counts = []
        pcap_files = []

        # Extract forward and backward packet counts from the processed PCAP data
        for entry in self.data:
            pcap_file = entry["Pcap file"]
            flows = entry.get("Flows", {})

            if not flows:  # Debugging: Check if flows exist
                print(f"⚠️ No flow data found for {pcap_file}")
                continue

            # Sum up all forward and backward packets in the flows
            total_forward = sum(flow["forward"] for flow in flows.values())
            total_backward = sum(flow["backward"] for flow in flows.values())

            # Debugging output
            print(f"📊 {pcap_file}: Forward = {total_forward}, Backward = {total_backward}")

            pcap_files.append(pcap_file)
            forward_counts.append(total_forward)
            backward_counts.append(total_backward)

        # Check if any valid data exists
        if not pcap_files:
            ax.text(0.5, 0.5, "No Flow Data Available", fontsize=12, ha='center', va='center')
            ax.set_xticks([])
            ax.set_yticks([])
        else:
            # Create bar width and x locations
            x = np.arange(len(pcap_files))
            width = 0.3  # Adjust width for side-by-side bars

            # Plot bars
            ax.bar(x - width / 2, forward_counts, width=width, label="Forward Packets", color="royalblue",
                   edgecolor="black")
            ax.bar(x + width / 2, backward_counts, width=width, label="Backward Packets", color="tomato",
                   edgecolor="black")

            # Format axes
            ax.set_xticks(x)
            ax.set_xticklabels(pcap_files, rotation=45, ha="right")
            ax.set_xlabel("PCAP Files")
            ax.set_ylabel("Packet Count")
            ax.set_title("Forward vs Backward Packets per PCAP")

            # ✅ Make the legend draggable
            legend = ax.legend(loc="upper right", frameon=True)
            legend.set_draggable(True)

            ax.grid(axis="y", linestyle="--", alpha=0.7)

        self.display_graph(fig)


    def plot_flow_size_vs_volume(self):
        if not self.data:
            print("No data available for plotting.")
            return

        fig, ax = plt.subplots(figsize=(10, 6))

        # Extract flow size and flow volume data
        flow_sizes = [entry.get("Flow size", 0) for entry in self.data]
        flow_volumes = [entry.get("Flow Volume (bytes)", 0) for entry in self.data]
        labels = [entry["Pcap file"] for entry in self.data]

        # Assign colors based on PCAP file
        unique_pcaps = list(set(labels))
        color_map = plt.get_cmap("tab10")
        pcap_colors = {pcap: color_map(i) for i, pcap in enumerate(unique_pcaps)}

        # Scatter plot with colors
        for i, (size, volume, pcap_file) in enumerate(zip(flow_sizes, flow_volumes, labels)):
            ax.scatter(
                size, volume,
                color=pcap_colors[pcap_file],
                edgecolors='black',
                alpha=0.7,
                label=pcap_file if pcap_file not in pcap_colors else ""
            )

        ax.set_xlabel("Flow Size (Number of Packets)")
        ax.set_ylabel("Flow Volume (Total Bytes Transferred)")
        ax.set_title("Flow Size vs. Flow Volume (Traffic Types)")

        # Show unique legend & make it draggable
        handles = [plt.Line2D([0], [0], marker='o', color='w', markerfacecolor=pcap_colors[pcap], markersize=10)
                   for pcap in unique_pcaps]
        legend = ax.legend(handles, unique_pcaps, title="Traffic Type", loc="upper right", frameon=True)
        legend.set_draggable(True)  # ✅ Make legend draggable

        ax.grid(True)
        self.display_graph(fig)

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

        # Show legend & make it draggable
        legend = ax.legend(frameon=True)
        legend.set_draggable(True)

        self.display_graph(fig)

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

    def plot_flow_volume_over_pcap(self):
        if self.canvas:
            self.canvas.get_tk_widget().destroy()

        fig, ax = plt.subplots(figsize=(10, 6))

        # Extract flow volume data
        pcap_files = [entry["Pcap file"] for entry in self.data]
        flow_volumes = [entry.get("Flow Volume (bytes)", 0) for entry in self.data]

        if not pcap_files:
            ax.text(0.5, 0.5, "No Flow Volume Data Available", fontsize=12, ha='center', va='center')
            ax.set_xticks([])
            ax.set_yticks([])
        else:
            # Create a bar chart
            bars = ax.bar(pcap_files, flow_volumes, color="tomato", edgecolor="black", alpha=0.7)

            # Format axes
            ax.set_xticks(range(len(pcap_files)))
            ax.set_xticklabels(pcap_files, rotation=45, ha="right")
            ax.set_xlabel("PCAP Files")
            ax.set_ylabel("Flow Volume (Bytes)")
            ax.set_title("Flow Volume Over PCAP")

            # Add legend and make it draggable
            legend = ax.legend([bars], ["Flow Volume"], loc="upper right", frameon=True)
            legend.set_draggable(True)

            ax.grid(axis="y", linestyle="--", alpha=0.7)

        self.display_graph(fig)

    def plot_flow_size_over_pcap(self):
        if self.canvas:
            self.canvas.get_tk_widget().destroy()

        fig, ax = plt.subplots(figsize=(10, 6))

        pcap_files = [entry["Pcap file"] for entry in self.data]
        flow_sizes = [entry.get("Flow size", 0) for entry in self.data]

        # Assign a unique color to each PCAP file
        unique_pcaps = list(set(pcap_files))
        color_map = plt.get_cmap("tab10")
        pcap_colors = {pcap: color_map(i % 10) for i, pcap in enumerate(unique_pcaps)}

        bars = ax.bar(pcap_files, flow_sizes, color=[pcap_colors[pcap] for pcap in pcap_files], edgecolor='black')

        ax.set_xlabel("PCAP File")
        ax.set_ylabel("Flow Size (Total Packets)")
        ax.set_title("Flow Size Over PCAPs")
        ax.tick_params(axis='x', rotation=45)

        # Create a draggable legend
        legend_patches = [plt.Line2D([0], [0], color=pcap_colors[pcap], lw=4, label=pcap) for pcap in unique_pcaps]
        legend = ax.legend(handles=legend_patches, title="PCAP Files", loc="upper right", frameon=True)
        legend.set_draggable(True)

        self.display_graph(fig)

    def plot_flow_volume_over_pcap(self):
        if self.canvas:
            self.canvas.get_tk_widget().destroy()

        fig, ax = plt.subplots(figsize=(10, 6))

        pcap_files = [entry["Pcap file"] for entry in self.data]
        flow_volumes = [entry.get("Flow Volume (bytes)", 0) for entry in self.data]

        # Assign a unique color to each PCAP file
        unique_pcaps = list(set(pcap_files))
        color_map = plt.get_cmap("tab10")
        pcap_colors = {pcap: color_map(i % 10) for i, pcap in enumerate(unique_pcaps)}

        bars = ax.bar(pcap_files, flow_volumes, color=[pcap_colors[pcap] for pcap in pcap_files], edgecolor='black')

        ax.set_xlabel("PCAP File")
        ax.set_ylabel("Flow Volume (Bytes)")
        ax.set_title("Flow Volume Over PCAPs")
        ax.tick_params(axis='x', rotation=45)

        # Create a draggable legend
        legend_patches = [plt.Line2D([0], [0], color=pcap_colors[pcap], lw=4, label=pcap) for pcap in unique_pcaps]
        legend = ax.legend(handles=legend_patches, title="PCAP Files", loc="upper right", frameon=True)
        legend.set_draggable(True)

        self.display_graph(fig)

    def display_graph(self, fig):
        if self.canvas:
            self.canvas.get_tk_widget().destroy()

        plt.tight_layout()
        self.canvas = FigureCanvasTkAgg(fig, master=self.graph_frame)
        self.canvas.get_tk_widget().pack(expand=True, fill=tk.BOTH)
        self.canvas.draw()

    def plot_graph(self, column_name, ylabel):
        if self.canvas:
            self.canvas.get_tk_widget().destroy()

        fig, ax = plt.subplots(figsize=(8, 5))

        pcap_files = [entry["Pcap file"] for entry in self.data]
        values = [entry.get(column_name, 0) for entry in self.data]

        # Assign a unique color to each PCAP file
        unique_pcaps = list(set(pcap_files))
        color_map = plt.get_cmap("tab10")
        pcap_colors = {pcap: color_map(i % 10) for i, pcap in enumerate(unique_pcaps)}

        bars = ax.bar(pcap_files, values, color=[pcap_colors[pcap] for pcap in pcap_files], edgecolor='black')

        ax.set_xlabel("PCAP File")
        ax.set_ylabel(ylabel)
        ax.set_title(ylabel)
        ax.tick_params(axis='x', rotation=45)

        # Create a draggable legend
        legend_patches = [plt.Line2D([0], [0], color=pcap_colors[pcap], lw=4, label=pcap) for pcap in unique_pcaps]
        legend = ax.legend(handles=legend_patches, title="PCAP Files", loc="upper right", frameon=True)
        legend.set_draggable(True)

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

        # ✅ Make the legend draggable
        legend = ax.legend(loc="upper right", frameon=True)
        legend.set_draggable(True)

        self.display_graph(fig)

