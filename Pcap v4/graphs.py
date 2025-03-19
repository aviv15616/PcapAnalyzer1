import tkinter as tk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import numpy as np
from collections import Counter
from matplotlib.widgets import RadioButtons, CheckButtons


class Graphs(tk.Toplevel):
    def __init__(self, master, data):
        super().__init__(master)
        self.title("PCAP Graphs")
        self.geometry("1000x800")

        self.data = data
        self.canvas = None

        button_frame = tk.Frame(self)
        button_frame.pack(pady=10)

        buttons = [
            ("Avg Packet Size", self.plot_avg_packet_size),
            ("Avg IAT", self.plot_avg_iat),
            ("IP Protocols", self.plot_ip_protocols),
            ("Packet Size Distribution", self.plot_packet_size_distribution),
            ("Flow Size vs. Volume", self.plot_flow_size_vs_volume),
            ("IAT Histogram", self.plot_iat_histogram),
            ("TCP Flags Distribution", self.plot_tcp_flags),
            ("Flow Size Over PCAP", self.plot_flow_size_over_pcap),
            ("Flow Volume Over PCAP", self.plot_flow_volume_over_pcap),
            ("Flow Direction", self.plot_flow_dir),
            ("Burstiness", self.plot_burstiness),
            ("HTTP Distribution", self.plot_http_distribution),
            ("Bytes Per Second", self.plot_bytes_per_second)
        ]

        for text, command in buttons:
            tk.Button(button_frame, text=text, command=command).pack(side=tk.LEFT, padx=5)

        self.graph_frame = tk.Frame(self)
        self.graph_frame.pack(expand=True, fill=tk.BOTH)


    # ==============================
    # ✅ PLOT FUNCTIONS (FULLY INTEGRATED)
    # ==============================

    def plot_iat_histogram(self):
        """ Displays a histogram of inter-arrival times per PCAP file. """
        fig, ax = plt.subplots(figsize=(10, 6))

        iat_data_per_pcap = {entry["Pcap file"]: entry.get("Inter-Packet Arrival Times", []) for entry in self.data}
        selected_pcap = next((pcap for pcap, iat in iat_data_per_pcap.items() if iat), None)

        def update_histogram(pcap_name):
            ax.clear()
            iat_data = iat_data_per_pcap.get(pcap_name, [])

            if not iat_data:
                ax.text(0.5, 0.5, f"No IAT Data for {pcap_name}", fontsize=12, ha='center', va='center')
            else:
                bins = np.linspace(0, 0.09, 30)
                ax.hist(iat_data, bins=bins, color="royalblue", edgecolor="black", alpha=0.7)
                ax.set_xlabel("Inter-Packet Arrival Time (seconds)")
                ax.set_ylabel("Frequency")
                ax.set_title(f"IAT Histogram for {pcap_name}")

            fig.canvas.draw_idle()

        update_histogram(selected_pcap)
        self.display_graph(fig)

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

    def plot_packet_size_distribution(self):
        """ Displays a histogram of packet sizes per PCAP file. """
        fig, ax = plt.subplots(figsize=(10, 6))

        packet_sizes_per_pcap = {entry["Pcap file"]: entry.get("Packet Sizes", []) for entry in self.data}
        selected_pcap = next((pcap for pcap, sizes in packet_sizes_per_pcap.items() if sizes), None)

        def update_histogram(pcap_name):
            ax.clear()
            sizes = packet_sizes_per_pcap.get(pcap_name, [])

            if not sizes:
                ax.text(0.5, 0.5, f"No Packet Size Data for {pcap_name}", fontsize=12, ha='center', va='center')
            else:
                bins = np.linspace(0, max(sizes), 30)
                ax.hist(sizes, bins=bins, color="royalblue", edgecolor="black", alpha=0.7)
                ax.set_xlabel("Packet Size (Bytes)")
                ax.set_ylabel("Packet Count")
                ax.set_title(f"Packet Size Distribution for {pcap_name}")

            fig.canvas.draw_idle()

        update_histogram(selected_pcap)
        self.display_graph(fig)

    def plot_flow_size_vs_volume(self):
        """ Scatter plot of flow size vs. flow volume. """
        fig, ax = plt.subplots(figsize=(10, 6))

        flow_sizes = [entry.get("Flow size", 0) for entry in self.data]
        flow_volumes = [entry.get("Flow Volume (bytes)", 0) for entry in self.data]
        labels = [entry["Pcap file"] for entry in self.data]

        color_map = plt.get_cmap("tab10")
        pcap_colors = {pcap: color_map(i) for i, pcap in enumerate(set(labels))}

        for size, volume, pcap_file in zip(flow_sizes, flow_volumes, labels):
            ax.scatter(size, volume, color=pcap_colors[pcap_file], edgecolors='black', alpha=0.7)

        ax.set_xlabel("Flow Size (Packets)")
        ax.set_ylabel("Flow Volume (Bytes)")
        ax.set_title("Flow Size vs. Flow Volume")
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

    from matplotlib.widgets import CheckButtons, RadioButtons
    import matplotlib.pyplot as plt
    import numpy as np
    from matplotlib.widgets import CheckButtons

    import matplotlib.pyplot as plt
    import numpy as np
    from matplotlib.widgets import CheckButtons

    import matplotlib.pyplot as plt
    import numpy as np
    from matplotlib.widgets import CheckButtons

    def plot_flow_dir(self):
        """Plots Forward vs. Backward packets per PCAP file with a single persistent checkbox box."""
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

            # ✅ Apply Top Flows Fix (Ensures sorting / selection logic)
            top_flows = sorted(flows.items(), key=lambda x: sum(x[1].values()), reverse=True)[:10]

            total_forward = sum(flow["forward"] for _, flow in top_flows)
            total_backward = sum(flow["backward"] for _, flow in top_flows)

            pcap_files.append(pcap_file)
            forward_counts.append(total_forward)
            backward_counts.append(total_backward)

        if not pcap_files:
            ax.text(0.5, 0.5, "No Flow Data Available", fontsize=12, ha='center', va='center')
            ax.set_xticks([])
            ax.set_yticks([])
            self.display_graph(fig)
            return

        x = np.arange(len(pcap_files))
        width = 0.3

        # ✅ Create bars with label references
        bars_forward = ax.bar(x - width / 2, forward_counts, width=width, label="Forward Packets", color="royalblue",
                              edgecolor="black")
        bars_backward = ax.bar(x + width / 2, backward_counts, width=width, label="Backward Packets", color="tomato",
                               edgecolor="black")

        ax.set_xticks(x)
        ax.set_xticklabels(pcap_files, rotation=45, ha="right")
        ax.set_xlabel("PCAP Files")
        ax.set_ylabel("Packet Count")
        ax.set_title("Forward vs Backward Packets per PCAP")

        legend = ax.legend(loc="upper right", frameon=True)
        legend.set_draggable(True)
        ax.grid(axis="y", linestyle="--", alpha=0.7)

        self.display_graph(fig)

        # ✅ Store CheckButtons in `self` to prevent garbage collection
        if not hasattr(self, "checkbox_widgets"):
            self.checkbox_widgets = {}

        # ✅ Create a well-placed checkbox box (Semi-transparent, Positioned Bottom-Right)
        check_ax = fig.add_axes([0.75, 0.05, 0.22, 0.3], facecolor=(1, 1, 1, 0.7),
                                frameon=True)  # 🔥 Adjusted position & alpha
        check_ax.set_xticks([])
        check_ax.set_yticks([])
        check_ax.text(0.05, 1.05, "Toggle Visibility", fontsize=10, fontweight="bold")

        # ✅ Define checkboxes for Forward/Backward Packets + PCAPs
        check_labels = ["Forward", "Backward"] + pcap_files
        visibility = [True] * len(check_labels)

        self.checkbox_widgets["flow_dir"] = CheckButtons(check_ax, check_labels, visibility)

        def toggle_visibility(label):
            """Toggle visibility of Forward/Backward bars and PCAP bars."""
            if label == "Forward":
                for bar in bars_forward:
                    bar.set_visible(not bar.get_visible())
            elif label == "Backward":
                for bar in bars_backward:
                    bar.set_visible(not bar.get_visible())
            elif label in pcap_files:  # Handle per-PCAP visibility
                idx = pcap_files.index(label)
                bars_forward[idx].set_visible(not bars_forward[idx].get_visible())
                bars_backward[idx].set_visible(not bars_backward[idx].get_visible())

            fig.canvas.draw_idle()

        self.checkbox_widgets["flow_dir"].on_clicked(toggle_visibility)


    def plot_burstiness(self):
        """ Displays burstiness factors (PMR, MMR, CV) with radio buttons & PCAP checkboxes inside the graph. """
        if self.canvas:
            self.canvas.get_tk_widget().destroy()

        fig, ax = plt.subplots(figsize=(10, 6))

        pcap_files = [entry["Pcap file"] for entry in self.data]
        pmr_values = np.array([entry.get("PMR", 0) for entry in self.data])
        mmr_values = np.array([entry.get("MMR", 0) for entry in self.data])
        cv_values = np.array([entry.get("CV", 0) for entry in self.data])

        unique_pcaps = list(set(pcap_files))
        color_map = plt.get_cmap("tab10")
        pcap_colors = {pcap: color_map(i) for i, pcap in enumerate(unique_pcaps)}

        values = pmr_values
        max_value = max(values) * 1.1
        y_ticks = np.linspace(0, max_value, 5)

        bars = ax.bar(pcap_files, values, color=[pcap_colors[pcap] for pcap in pcap_files])
        ax.set_ylabel("Burstiness Value")
        ax.set_xlabel("PCAP Files")
        ax.set_title("Burstiness Factors (PMR, MMR, CV)")
        ax.set_xticklabels(pcap_files, rotation=45, ha="right")
        ax.set_ylim(0, max_value)
        ax.set_yticks(y_ticks)

        legend_labels = [plt.Line2D([0], [0], marker='o', color='w', markerfacecolor=pcap_colors[pcap], markersize=10)
                         for pcap in unique_pcaps]
        legend = ax.legend(legend_labels, unique_pcaps, title="PCAPs", loc="upper right", frameon=True)
        legend.set_draggable(True)

        self.display_graph(fig)

        # ✅ Place radio buttons and checkboxes inside the graph
        radio_ax = fig.add_axes([0.8, 0.25, 0.18, 0.25], facecolor="lightgray")  # Box inside graph
        radio_ax.set_xticks([])
        radio_ax.set_yticks([])
        radio_ax.set_frame_on(True)

        # ✅ Radio Buttons for PMR/MMR/CV
        radio_ax.text(0.05, 0.9, "Burstiness", fontsize=10, fontweight="bold")
        self.burstiness_var = plt.axes([0.82, 0.75, 0.12, 0.12])
        self.radio_buttons = RadioButtons(self.burstiness_var, ["PMR", "MMR", "CV"], active=0)

        def update_plot(label):
            """ Update the bar graph based on selected burstiness metric. """
            nonlocal values, max_value, y_ticks

            values = {"PMR": pmr_values, "MMR": mmr_values, "CV": cv_values}[label]

            max_value = max(values) * 1.1
            y_ticks = np.linspace(0, max_value, 5)

            for bar, value in zip(bars, values):
                bar.set_height(value)

            ax.set_ylim(0, max_value)
            ax.set_yticks(y_ticks)
            fig.canvas.draw_idle()

        self.radio_buttons.on_clicked(update_plot)

        # ✅ PCAP Checkboxes
        check_positions = np.linspace(0.6, 0.05, len(pcap_files))
        self.pcap_checkboxes = []

        for pcap, pos in zip(pcap_files, check_positions):
            cb = plt.axes([0.82, pos, 0.12, 0.03])
            check = CheckButtons(cb, [pcap], [True])

            def toggle_pcap_visibility(label=pcap):
                idx = pcap_files.index(label)
                bars[idx].set_visible(not bars[idx].get_visible())
                fig.canvas.draw_idle()

            check.on_clicked(toggle_pcap_visibility)
            self.pcap_checkboxes.append(check)

    def plot_http_distribution(self):
        self.plot_category_graph("Http Count", "HTTP Distribution")

    def plot_bytes_per_second(self):
        """Plots bytes transferred per second for each PCAP file over time with toggleable checkboxes."""
        if self.canvas:
            self.canvas.get_tk_widget().destroy()

        fig, ax = plt.subplots(figsize=(12, 6))

        bytes_per_second_per_pcap = {}
        pcap_lines = {}

        # Process data per PCAP
        for entry in self.data:
            pcap_file = entry["Pcap file"]
            timestamps = entry.get("Packet Timestamps", [])
            packet_sizes = entry.get("Packet Sizes", [])

            if not timestamps or not packet_sizes:
                continue  # Skip empty or invalid data

            # Normalize timestamps to start at 0
            start_time = min(timestamps)
            relative_times = [t - start_time for t in timestamps]

            # Define time bins (1-second intervals)
            bins = np.arange(0, max(relative_times) + 1, 1)
            byte_counts, _ = np.histogram(relative_times, bins=bins, weights=packet_sizes)

            bytes_per_second_per_pcap[pcap_file] = (bins[:-1], byte_counts)

        # Assign colors to each PCAP
        colors = plt.get_cmap("tab10")

        for i, (pcap_file, (time_bins, byte_counts)) in enumerate(bytes_per_second_per_pcap.items()):
            line, = ax.plot(time_bins, byte_counts, marker='o', linestyle='-', label=pcap_file, color=colors(i))
            pcap_lines[pcap_file] = line

        ax.set_xlabel("Time (seconds)")
        ax.set_ylabel("Bytes Transferred Per Second")
        ax.set_title("Bytes Transferred Per Second Over Time for Each PCAP")
        ax.grid(True)

        # ✅ Apply the semi-transparent check button box (Bottom-Right)
        check_ax = fig.add_axes([0.75, 0.05, 0.22, 0.3], facecolor=(1, 1, 1, 0.7), frameon=True)
        check_ax.set_xticks([])
        check_ax.set_yticks([])
        check_ax.text(0.05, 1.05, "Toggle Visibility", fontsize=10, fontweight="bold")

        check_labels = list(pcap_lines.keys())
        visibility = [True] * len(check_labels)

        # ✅ Store checkboxes persistently
        if not hasattr(self, "checkbox_widgets"):
            self.checkbox_widgets = {}

        self.checkbox_widgets["bytes_per_second"] = CheckButtons(check_ax, check_labels, visibility)

        def toggle_visibility(label):
            line = pcap_lines[label]
            line.set_visible(not line.get_visible())
            fig.canvas.draw_idle()

        self.checkbox_widgets["bytes_per_second"].on_clicked(toggle_visibility)

        # ✅ Ensure legend is draggable
        legend = ax.legend(loc="upper right", frameon=True)
        legend.set_draggable(True)

        self.display_graph(fig)

    # ==============================
    # ✅ HELPER FUNCTIONS
    # ==============================
    def add_draggable_legend(self, ax, pcap_colors=None, unique_pcaps=None):
        if pcap_colors and unique_pcaps:
            legend_patches = [plt.Line2D([0], [0], color=pcap_colors[pcap], lw=4, label=pcap) for pcap in unique_pcaps]
            legend = ax.legend(handles=legend_patches, title="PCAP Files", loc="upper right", frameon=True)
        else:
            legend = ax.legend(loc="upper right", frameon=True)

        legend.set_draggable(True)

    from matplotlib.widgets import CheckButtons

    def plot_bar_chart(self, x_labels, values, ylabel, title):
        """Generalized bar graph with checkboxes for toggling visibility."""
        if self.canvas:
            self.canvas.get_tk_widget().destroy()

        fig, ax = plt.subplots(figsize=(8, 5))

        # Assign colors
        unique_pcaps = list(set(x_labels))
        color_map = plt.get_cmap("tab10")
        pcap_colors = {pcap: color_map(i % 10) for i, pcap in enumerate(unique_pcaps)}

        bars = ax.bar(x_labels, values, color=[pcap_colors[pcap] for pcap in x_labels], edgecolor='black')

        ax.set_xlabel("PCAP File")
        ax.set_ylabel(ylabel)
        ax.set_title(title)
        ax.tick_params(axis='x', rotation=45)

        # ✅ Apply the semi-transparent check button box (Bottom-Right)
        check_ax = fig.add_axes([0.75, 0.05, 0.22, 0.3], facecolor=(1, 1, 1, 0.7), frameon=True)
        check_ax.set_xticks([])
        check_ax.set_yticks([])
        check_ax.text(0.05, 1.05, "Toggle Visibility", fontsize=10, fontweight="bold")

        # ✅ Store checkboxes persistently
        if not hasattr(self, "checkbox_widgets"):
            self.checkbox_widgets = {}

        self.checkbox_widgets["bar_chart"] = CheckButtons(check_ax, unique_pcaps, [True] * len(unique_pcaps))

        def toggle_bar_visibility(label):
            index = unique_pcaps.index(label)
            bars[index].set_visible(not bars[index].get_visible())
            fig.canvas.draw_idle()

        self.checkbox_widgets["bar_chart"].on_clicked(toggle_bar_visibility)

        self.add_draggable_legend(ax, pcap_colors, unique_pcaps)
        self.display_graph(fig)

    import matplotlib.pyplot as plt
    import numpy as np
    from collections import Counter
    from matplotlib.widgets import CheckButtons

    def plot_category_graph(self, column_name, ylabel):
        """Generalized category-based bar graph with checkboxes to toggle visibility."""
        if self.canvas:
            self.canvas.get_tk_widget().destroy()

        fig, ax = plt.subplots(figsize=(10, 6))
        category_per_pcap = {}

        # ✅ Process categories from data
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

        bars_dict = {}  # Store bars for toggling
        for i, (pcap_file, category_counts) in enumerate(category_per_pcap.items()):
            y = [category_counts.get(category, 0) for category in categories]
            bars_dict[pcap_file] = ax.bar(x + (i * width) - (num_pcaps * width / 2), y, width=width, label=pcap_file)

        ax.set_xticks(x)
        ax.set_xticklabels(categories, rotation=45)
        ax.set_xlabel("Category")
        ax.set_ylabel(ylabel)
        ax.set_title(ylabel)

        # ✅ Apply the semi-transparent check button box (Bottom-Right)
        check_ax = fig.add_axes([0.75, 0.05, 0.22, 0.3], facecolor=(1, 1, 1, 0.7), frameon=True)
        check_ax.set_xticks([])
        check_ax.set_yticks([])
        check_ax.text(0.05, 1.05, "Toggle Visibility", fontsize=10, fontweight="bold")

        check_labels = list(bars_dict.keys())
        visibility = [True] * len(check_labels)

        # ✅ Store checkboxes in `self` to prevent garbage collection
        if not hasattr(self, "checkbox_widgets"):
            self.checkbox_widgets = {}

        self.checkbox_widgets["category_graph"] = CheckButtons(check_ax, check_labels, visibility)

        def toggle_category_visibility(label):
            for bar in bars_dict[label]:
                bar.set_visible(not bar.get_visible())
            fig.canvas.draw_idle()

        self.checkbox_widgets["category_graph"].on_clicked(toggle_category_visibility)

        # ✅ Make the legend draggable
        legend = ax.legend(loc="upper right", frameon=True)
        legend.set_draggable(True)

        self.display_graph(fig)

    def display_graph(self, fig):
        if self.canvas:
            self.canvas.get_tk_widget().destroy()
        plt.tight_layout()
        self.canvas = FigureCanvasTkAgg(fig, master=self.graph_frame)
        self.canvas.get_tk_widget().pack(expand=True, fill=tk.BOTH)
        self.canvas.draw()



