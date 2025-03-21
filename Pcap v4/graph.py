import tkinter as tk
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from collections import Counter
import matplotlib.pyplot as plt
import numpy as np



class Graph(tk.Toplevel):
    def __init__(self, master, data):
        super().__init__(master)
        self.title("PCAP Graphs")
        self.geometry("1000x800")
        self.checkbox_widgets = {}
        self.checkbox_frame = None

        self.data = data
        self.canvas = None

        button_frame = tk.Frame(self)
        button_frame.pack(pady=10)

        buttons = [
            ("Avg Packet Size", self.plot_avg_packet_size),
            ("Avg IAT", self.plot_avg_iat),
            ("Packet Size Distribution", self.plot_packet_size_distribution),
            ("IAT Distribution", self.plot_iat_histogram),
            ("Flow Volume Per Sec", self.plot_bytes_per_second),
            ("Flow Size vs. Volume", self.plot_flow_size_vs_volume),
            ("Flow Size Per PCAP", self.plot_flow_size_over_pcap),
            ("Flow Volume Per PCAP", self.plot_flow_volume_over_pcap),
            ("Flow Direction", self.plot_flow_dir),
            ("IP Protocols Distribution", self.plot_ip_protocols),
            ("TCP Flags Distribution", self.plot_tcp_flags),
            ("HTTP Distribution", self.plot_http_distribution),

        ]

        for text, command in buttons:
            tk.Button(button_frame, text=text, command=command).pack(side=tk.LEFT, padx=5)

        self.graph_frame = tk.Frame(self)
        self.graph_frame.pack(expand=True, fill=tk.BOTH)

    # ==============================
    # ✅ PLOT FUNCTIONS (FULLY INTEGRATED)
    # ==============================

    def plot_tcp_flags(self):
        """ Displays TCP flag distribution. """
        self.plot_category_graph("Tcp Flags", "TCP Flags Distribution")

    def plot_avg_packet_size(self):
        self.plot_bar_chart(
            [entry["Pcap file"] for entry in self.data],
            [entry.get("Avg Packet size (bytes)", 0) for entry in self.data],
            "Average Packet Size (bytes)",
            "Average Packet Size"
        )

    def plot_avg_iat(self):
        self.plot_bar_chart(
            [entry["Pcap file"] for entry in self.data],
            [entry.get("Avg Packet IAT (seconds)", 0) for entry in self.data],
            "Average Inter-Arrival Time (seconds)",
            "Average IAT"
        )

    def plot_iat_histogram(self):
        """ Displays a histogram of inter-arrival times per PCAP file with dynamically adjusted x-axis. """
        if self.canvas:
            self.canvas.get_tk_widget().destroy()

        fig, ax = plt.subplots(figsize=(12, 6))  # Increased figure width

        iat_data_per_pcap = {entry["Pcap file"]: entry.get("Inter-Packet Arrival Times", []) for entry in self.data}
        pcap_files = list(iat_data_per_pcap.keys())

        selected_pcap = next((pcap for pcap, iat in iat_data_per_pcap.items() if iat),
                             pcap_files[0] if pcap_files else None)

        def update_histogram():
            """ Updates the histogram dynamically based on the selected PCAP file. """
            ax.clear()
            pcap_name = self.radio_var.get()
            iat_data = iat_data_per_pcap.get(pcap_name, [])

            if not iat_data:
                ax.text(0.5, 0.5, f"No IAT Data for {pcap_name}", fontsize=12, ha='center', va='center')
            else:
                # Dynamically set bins to zoom in based on data distribution
                min_iat, max_iat = min(iat_data), max(iat_data)
                bin_count = 50 if max_iat - min_iat < 0.1 else 30  # More bins for smaller values
                bins = np.linspace(min_iat, max_iat, bin_count)

                ax.hist(iat_data, bins=bins, color="royalblue", edgecolor="black", alpha=0.7)
                ax.set_xlabel("Inter-Packet Arrival Time (seconds)")
                ax.set_ylabel("Frequency")
                ax.set_title(f"IAT Histogram for {pcap_name}")

                ax.set_xlim(min_iat, max_iat)  # Zoom into the data range

            fig.canvas.draw_idle()

        self.display_graph(fig)

        # ✅ Ensure the control frame exists before setting `self.radio_var`
        self.create_control_frame(
            title="Select PCAP for IAT Histogram",
            radio_options=pcap_files,
            radio_callback=update_histogram
        )

        if selected_pcap:
            self.radio_var.set(selected_pcap)
            update_histogram()

    def plot_packet_size_distribution(self):
        """ Displays a histogram of packet sizes per PCAP file with dynamically adjusted x-axis. """
        if self.canvas:
            self.canvas.get_tk_widget().destroy()

        fig, ax = plt.subplots(figsize=(12, 6))  # Increased figure width

        packet_sizes_per_pcap = {entry["Pcap file"]: entry.get("Packet Sizes", []) for entry in self.data}
        pcap_files = list(packet_sizes_per_pcap.keys())

        selected_pcap = next((pcap for pcap, sizes in packet_sizes_per_pcap.items() if sizes),
                             pcap_files[0] if pcap_files else None)

        def update_histogram():
            """ Updates the histogram dynamically based on the selected PCAP file. """
            ax.clear()
            pcap_name = self.radio_var.get()
            sizes = packet_sizes_per_pcap.get(pcap_name, [])

            if not sizes:
                ax.text(0.5, 0.5, f"No Packet Size Data for {pcap_name}", fontsize=12, ha='center', va='center')
            else:
                min_size, max_size = min(sizes), max(sizes)
                bin_count = 50 if max_size - min_size < 500 else 30  # More bins for smaller packet sizes
                bins = np.linspace(min_size, max_size, bin_count)

                ax.hist(sizes, bins=bins, color="royalblue", edgecolor="black", alpha=0.7)
                ax.set_xlabel("Packet Size (Bytes)")
                ax.set_ylabel("Packet Count")
                ax.set_title(f"Packet Size Distribution for {pcap_name}")

                ax.set_xlim(min_size, max_size)  # Zoom into the packet size range

            fig.canvas.draw_idle()

        self.display_graph(fig)

        # ✅ Ensure the control frame exists before setting `self.radio_var`
        self.create_control_frame(
            title="Select PCAP for Packet Size Histogram",
            radio_options=pcap_files,
            radio_callback=update_histogram
        )

        if selected_pcap:
            self.radio_var.set(selected_pcap)
            update_histogram()

    def plot_flow_size_vs_volume(self):
        """ Scatter plot of flow size vs. flow volume with a draggable legend. """
        # ✅ Destroy the existing control frame before displaying a new graph
        if hasattr(self, "checkbox_frame") and self.checkbox_frame:
            self.checkbox_frame.destroy()
            self.checkbox_frame = None

        fig, ax = plt.subplots(figsize=(10, 6))

        flow_sizes = [entry.get("Flow size", 0) for entry in self.data]
        flow_volumes = [entry.get("Flow Volume (bytes)", 0) for entry in self.data]
        labels = [entry["Pcap file"] for entry in self.data]

        color_map = plt.get_cmap("tab10")
        pcap_colors = {pcap: color_map(i) for i, pcap in enumerate(set(labels))}

        # ✅ Scatter plot with labeled points
        scatter_points = []
        for size, volume, pcap_file in zip(flow_sizes, flow_volumes, labels):
            point = ax.scatter(size, volume, color=pcap_colors[pcap_file], edgecolors='black', alpha=0.7,
                               label=pcap_file)
            scatter_points.append(point)  # ✅ Store points for legend

        ax.set_xlabel("Flow Size (Packets)")
        ax.set_ylabel("Flow Volume (Bytes)")
        ax.set_title("Flow Size vs. Flow Volume")

        # ✅ Create legend based on stored scatter points
        legend = ax.legend(loc="upper right", frameon=True)
        legend.set_draggable(True)  # ✅ Allow user to move the legend

        self.display_graph(fig)

    def plot_flow_size_over_pcap(self):
        """ Displays the flow size per PCAP file. """
        self.plot_bar_chart(
            [entry["Pcap file"] for entry in self.data],
            [entry.get("Flow size", 0) for entry in self.data],
            "Flow Size (Packets)",
            "Flow Size Over PCAP"
        )

    def plot_flow_volume_over_pcap(self):
        self.plot_bar_chart(
            [entry["Pcap file"] for entry in self.data],
            [entry.get("Flow Volume (bytes)", 0) for entry in self.data],
            "Flow Volume (Bytes)",
            "Flow Volume Over PCAP"
        )

    def plot_ip_protocols(self):
        """ Displays IP protocol distribution across PCAP files. """
        self.plot_category_graph("Ip protocols", "IP Protocols Distribution")

    def plot_flow_dir(self):
        """Plots the number of forward vs backward packets per PCAP file with Tkinter check buttons below."""
        if self.canvas:
            self.canvas.get_tk_widget().destroy()

        fig, ax = plt.subplots(figsize=(10, 6))

        forward_counts = []
        backward_counts = []
        pcap_files = []

        for entry in self.data:
            pcap_file = entry["Pcap file"]
            flows = entry.get("Flows", {})

            if not flows:
                continue

            total_forward = sum(flow["forward"] for flow in flows.values())
            total_backward = sum(flow["backward"] for flow in flows.values())

            pcap_files.append(pcap_file)
            forward_counts.append(total_forward)
            backward_counts.append(total_backward)

        if not pcap_files:
            ax.text(0.5, 0.5, "No Flow Data Available", fontsize=12, ha='center', va='center')
            ax.set_xticks([])
            ax.set_yticks([])
            bars_forward = []
            bars_backward = []
        else:
            x = np.arange(len(pcap_files))
            width = 0.3

            # ✅ Store individual bars inside lists for correct toggling
            bars_forward = ax.bar(x - width / 2, forward_counts, width=width, label="Forward Packets",
                                  color="royalblue", edgecolor="black")
            bars_backward = ax.bar(x + width / 2, backward_counts, width=width, label="Backward Packets",
                                   color="tomato", edgecolor="black")

            ax.set_xticks(x)
            ax.set_xticklabels(pcap_files, rotation=45, ha="right")
            ax.set_xlabel("PCAP Files")
            ax.set_ylabel("Packet Count")
            ax.set_title("Forward vs Backward Packets per PCAP")

            legend = ax.legend(loc="upper right", frameon=True)
            legend.set_draggable(True)
            ax.grid(axis="y", linestyle="--", alpha=0.7)

        self.display_graph(fig)

        # ✅ Store bars in a dictionary for reference
        self.bar_references = {
            "Forward": bars_forward,
            "Backward": bars_backward,
        }

        # ✅ Callback function for toggling visibility
        def toggle_visibility(_=None):
            """Toggle visibility of Forward/Backward bars and individual PCAP bars."""
            forward_visible = self.check_vars["Forward"].get()
            backward_visible = self.check_vars["Backward"].get()

            # ✅ Toggle Forward and Backward bars visibility
            for bar in bars_forward:
                bar.set_visible(forward_visible)
            for bar in bars_backward:
                bar.set_visible(backward_visible)

            # ✅ Toggle PCAP-specific bars
            for pcap, var in self.check_vars.items():
                if pcap in pcap_files:
                    index = pcap_files.index(pcap)
                    bars_forward[index].set_visible(var.get() and forward_visible)
                    bars_backward[index].set_visible(var.get() and backward_visible)

            fig.canvas.draw_idle()

        # ✅ Create UI using `create_control_frame`
        self.create_control_frame(
            title="Flow Direction Controls",
            check_options=["Forward", "Backward"] + pcap_files,
            check_callback=toggle_visibility
        )

        # ✅ Ensure visibility is correctly set at the start
        toggle_visibility()

    def plot_http_distribution(self):
        self.plot_category_graph("Http Count", "HTTP Distribution")

    def plot_bytes_per_second(self):
        """Plots bytes transferred per second for each PCAP file over time with toggleable checkboxes."""
        if self.canvas:
            self.canvas.get_tk_widget().destroy()
        if hasattr(self, "checkbox_frame") and self.checkbox_frame is not None:
            self.checkbox_frame.destroy()

        fig, ax = plt.subplots(figsize=(12, 6))
        bytes_per_second_per_pcap = {}
        pcap_lines = {}

        for entry in self.data:
            pcap_file = entry["Pcap file"]
            timestamps = entry.get("Packet Timestamps", [])
            packet_sizes = entry.get("Packet Sizes", [])

            if not timestamps or not packet_sizes:
                continue

            start_time = min(timestamps)
            relative_times = [t - start_time for t in timestamps]
            bins = np.arange(0, max(relative_times) + 1, 1)
            byte_counts, _ = np.histogram(relative_times, bins=bins, weights=packet_sizes)

            bytes_per_second_per_pcap[pcap_file] = (bins[:-1], byte_counts)

        colors = plt.get_cmap("tab10")

        for i, (pcap_file, (time_bins, byte_counts)) in enumerate(bytes_per_second_per_pcap.items()):
            line, = ax.plot(time_bins, byte_counts, marker='o', linestyle='-', label=pcap_file, color=colors(i))
            pcap_lines[pcap_file] = line

        ax.set_xlabel("Time (seconds)")
        ax.set_ylabel("Bytes Transferred Per Second")
        ax.set_title("Bytes Transferred Per Second Over Time for Each PCAP")
        ax.grid(True)

        legend = ax.legend(loc="upper right", frameon=True)
        legend.set_draggable(True)

        self.display_graph(fig)

        # ✅ Tkinter Checkbutton Frame BELOW the graph
        self.checkbox_frame = tk.Frame(self.graph_frame, bg="white", relief=tk.RIDGE, bd=2)
        self.checkbox_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=5)

        tk.Label(self.checkbox_frame, text="Toggle Visibility:", bg="white", font=("Arial", 10, "bold")).pack(
            side=tk.LEFT, padx=5)

        self.pcap_visibility = {}

        def toggle_visibility():
            """ Toggle visibility of each PCAP. """
            for pcap, var in self.pcap_visibility.items():
                pcap_lines[pcap].set_visible(var.get())
            fig.canvas.draw_idle()

        for label in pcap_lines.keys():
            var = tk.BooleanVar(value=True)
            cb = tk.Checkbutton(self.checkbox_frame, text=label, variable=var, command=toggle_visibility, bg="white")
            cb.pack(side=tk.LEFT, padx=5)
            self.pcap_visibility[label] = var

    def add_draggable_legend(self, ax, pcap_colors=None, unique_pcaps=None):
        if pcap_colors and unique_pcaps:
            legend_patches = [plt.Line2D([0], [0], color=pcap_colors[pcap], lw=4, label=pcap) for pcap in unique_pcaps]
            legend = ax.legend(handles=legend_patches, title="PCAP Files", loc="upper right", frameon=True)
        else:
            legend = ax.legend(loc="upper right", frameon=True)

        legend.set_draggable(True)

    def plot_bar_chart(self, x_labels, values, ylabel, title):
        """Generalized bar graph with Tkinter checkboxes to toggle PCAP visibility correctly."""
        if self.canvas:
            self.canvas.get_tk_widget().destroy()

        fig, ax = plt.subplots(figsize=(8, 5))

        unique_pcaps = list(set(x_labels))  # Unique PCAP names
        color_map = plt.get_cmap("tab10")
        pcap_colors = {pcap: color_map(i % 10) for i, pcap in enumerate(unique_pcaps)}

        bars = ax.bar(x_labels, values, color=[pcap_colors[pcap] for pcap in x_labels], edgecolor='black')

        ax.set_xlabel("PCAP File")
        ax.set_ylabel(ylabel)
        ax.set_title(title)
        ax.tick_params(axis='x', rotation=45)

        self.add_draggable_legend(ax, pcap_colors, unique_pcaps)
        self.display_graph(fig)

        # ✅ **Create a mapping of PCAP names to bars**
        self.pcap_bar_map = {x_labels[i]: bars[i] for i in range(len(x_labels))}

        # ✅ **Modify update function to reference the actual PCAP name**
        def update_visibility():
            """ Toggle visibility based on selected checkboxes. """
            for pcap, var in self.check_vars.items():
                if pcap in self.pcap_bar_map:
                    self.pcap_bar_map[pcap].set_visible(var.get())  # ✅ Correct mapping
            fig.canvas.draw_idle()

        # ✅ Create UI using `create_control_frame`
        self.create_control_frame(
            title=f"{title} Controls",
            check_options=unique_pcaps,  # Ensure correct PCAP names are used
            check_callback=update_visibility  # Callback to toggle bars
        )

        # ✅ Ensure all checkboxes are initially set to visible
        for var in self.check_vars.values():
            var.set(True)
        update_visibility()  # Apply visibility settings

    def plot_category_graph(self, column_name, ylabel):
        """Generalized category-based bar graph with Tkinter checkboxes below the graph."""
        if self.canvas:
            self.canvas.get_tk_widget().destroy()

        fig, ax = plt.subplots(figsize=(10, 6))
        category_per_pcap = {}

        # Process categories from data
        for entry in self.data:
            pcap_file = entry["Pcap file"]
            category_per_pcap[pcap_file] = Counter()
            for item in entry[column_name].split():
                if '-' in item:
                    key, value = item.split('-')
                    category_per_pcap[pcap_file][key] += int(value)

        categories = sorted(set(cat for pcap in category_per_pcap.values() for cat in pcap))
        num_pcaps = len(category_per_pcap)

        x = np.arange(len(categories)) * 2
        width = 0.2
        bars_dict = {}

        for i, (pcap_file, category_counts) in enumerate(category_per_pcap.items()):
            y = [category_counts.get(category, 0) for category in categories]
            bars_dict[pcap_file] = ax.bar(x + (i * width) - (num_pcaps * width / 2), y, width=width, label=pcap_file)

        ax.set_xticks(x)
        ax.set_xticklabels(categories, rotation=45)
        ax.set_xlabel("Category")
        ax.set_ylabel(ylabel)
        ax.set_title(ylabel)

        legend = ax.legend(loc="upper right", frameon=True)
        legend.set_draggable(True)

        self.display_graph(fig)

        # ✅ Create UI using `create_control_frame`
        def toggle_visibility(_=None):
            """ Toggle visibility of each PCAP. """
            for pcap, var in self.check_vars.items():
                for bar in bars_dict[pcap]:
                    bar.set_visible(var.get())
            fig.canvas.draw_idle()

        self.create_control_frame(
            title=f"{ylabel} Controls",
            check_options=list(bars_dict.keys()),
            check_callback=toggle_visibility
        )

    def display_graph(self, fig):
        if self.canvas:
            self.canvas.get_tk_widget().destroy()
        plt.tight_layout()
        self.canvas = FigureCanvasTkAgg(fig, master=self.graph_frame)
        self.canvas.get_tk_widget().pack(expand=True, fill=tk.BOTH)
        self.canvas.draw()
    def create_control_frame(self, title, check_options=None, check_callback=None, radio_options=None,
                             radio_callback=None):
        """Creates a Tkinter frame below the graph with checkboxes and radio buttons (if provided)."""

        print(f"Creating control frame: {title}")  # ✅ Debugging Statement

        # ✅ Destroy old frame before creating a new one
        if hasattr(self, "checkbox_frame") and self.checkbox_frame:
            self.checkbox_frame.destroy()

        # ✅ Attach control frame to `self.graph_frame` instead of `self.master`
        self.checkbox_frame = tk.Frame(self.graph_frame, bg="white")
        self.checkbox_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=5)

        tk.Label(self.checkbox_frame, text=title, font=("Arial", 10, "bold"), bg="white").pack()

        self.check_vars = {}  # ✅ Store BooleanVars for checkboxes
        if not hasattr(self, "radio_var"):  # ✅ Ensure `radio_var` exists
            self.radio_var = tk.StringVar()

        control_wrapper = tk.Frame(self.checkbox_frame, bg="white")
        control_wrapper.pack(fill=tk.X)

        # ✅ Radio Button Section (Horizontal Layout)
        if radio_options:
            if not self.radio_var.get():
                self.radio_var.set(radio_options[0])

            radio_frame = tk.Frame(control_wrapper, bg="white")
            radio_frame.grid(row=0, column=0, sticky="w", padx=5)

            tk.Label(radio_frame, text="Select Option:", font=("Arial", 9, "bold"), bg="white").grid(row=0, column=0,
                                                                                                     sticky="w")

            max_columns = 5  # ✅ Adjust column limit before wrapping
            row, col = 1, 0

            for option in radio_options:
                rb = tk.Radiobutton(radio_frame, text=option, variable=self.radio_var, value=option,
                                    command=radio_callback, bg="white", anchor="w", wraplength=150)
                rb.grid(row=row, column=col, padx=5, pady=2, sticky="w")
                col += 1
                if col >= max_columns:  # ✅ Move to next row if column limit reached
                    col = 0
                    row += 1

        # ✅ Checkbox Section (Wraps automatically)
        if check_options:
            check_frame = tk.Frame(control_wrapper, bg="white")
            check_frame.grid(row=1, column=0, sticky="w", padx=5)

            tk.Label(check_frame, text="Toggle Visibility:", font=("Arial", 9, "bold"), bg="white").grid(row=0,
                                                                                                         column=0,
                                                                                                         sticky="w")

            max_columns = 5
            row, col = 1, 0

            for option in check_options:
                var = tk.BooleanVar(value=True)
                self.check_vars[option] = var

                cb = tk.Checkbutton(check_frame, text=option, variable=var, command=check_callback, bg="white",
                                    anchor="w", wraplength=150)
                cb.grid(row=row, column=col, padx=5, pady=2, sticky="w")
                col += 1
                if col >= max_columns:
                    col = 0
                    row += 1

