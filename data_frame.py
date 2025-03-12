import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import pandas as pd


class DataFrame:
    def __init__(self, master, dataframe):
        self.master = master  # Parent window (from gui.py)
        self.dataframe = dataframe
        self.window = tk.Toplevel(master)
        self.window.title("Comparison Table")
        self.window.geometry("1200x600")  # Adjust as needed
        self.sort_orders = {col: True for col in self.dataframe.columns}

        # Updated tooltip dictionary including missing columns
        self.header_tooltips = {
            "PcapFile": "Name of the pcap file",
            "AvgPktSize": "Average size of packets in the flow (value: bytes)",  # ✅ Fixed
            "AvgInterArrival": "Average time between consecutive packets (value: seconds)",
            "FlowSize": "Number of packets in the flow",
            "FlowVolume": "Total volume of packets (value: Bytes)",
            "FlowDuration": "Total duration of the flow (value: seconds)",
            "PacketLossRate": "Estimated packet loss rate (value: %)",
            "Http2": "Number of HTTP/2 packets",  # ✅ Fixed
            "IP Protocols": "Distribution of IP protocols used in packets",  # ✅ Fixed
            "TCP Flags": "Counts of TCP flags (SYN, ACK, RST, etc.)",
            "SentPkts": "Number of packets sent",  # ✅ Fixed
            "ReceivedPkts": "Number of packets received",  # ✅ Fixed
            "TransportProtocol": "Highest layer transport protocol (TCP, UDP, etc.)",

        }

        # Create a frame to hold the Treeview and scrollbars
        frame = tk.Frame(self.window)
        frame.pack(fill=tk.BOTH, expand=True)

        # Create vertical and horizontal scrollbars
        vsb = ttk.Scrollbar(frame, orient="vertical")
        hsb = ttk.Scrollbar(frame, orient="horizontal")
        vsb.pack(side="right", fill="y")
        hsb.pack(side="bottom", fill="x")

        # Create the Treeview widget
        self.tree = ttk.Treeview(frame, columns=list(self.dataframe.columns), show="headings",
                                 yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        vsb.config(command=self.tree.yview)
        hsb.config(command=self.tree.xview)
        self.tree.pack(fill=tk.BOTH, expand=True)

        # Set column widths manually (using your original logic)
        scaling_factor = 6.0  # Character count to pixel width (adjust as needed)
        min_width = 100  # Minimum column width for readability

        for col in self.dataframe.columns:
            header_length = len(str(col))
            cell_lengths = self.dataframe[col].astype(str).apply(len)
            max_cell_length = cell_lengths.max() if not cell_lengths.empty else 0
            max_length = max(header_length, max_cell_length)
            col_width = max(max_length * scaling_factor, min_width)
            self.tree.column(col, width=int(col_width), anchor="w", stretch=False)  # Left-align text
            self.tree.heading(col, text=col, anchor="w", command=lambda _col=col: self.sort_column(_col))

        self.populate_table()

        # Create a frame for Export and Refresh buttons
        btn_frame = tk.Frame(self.window)
        btn_frame.pack(pady=10)

        export_button = tk.Button(btn_frame, text="Export to CSV", command=self.export_csv)
        export_button.pack(side="left", padx=5)
        refresh_button = tk.Button(btn_frame, text="Refresh", command=self.update_table)
        refresh_button.pack(side="left", padx=5)

        # Tooltip label for headers
        self.tooltip_label = tk.Label(self.window, text="", bg="lightyellow", relief="solid", borderwidth=1, padx=5,
                                      pady=2)
        self.tooltip_label.place_forget()

        # Bind header hover events
        self.tree.bind("<Motion>", self.show_tooltip)
        self.tree.bind("<Leave>", self.hide_tooltip)

    def show_tooltip(self, event):
        """Show tooltip near the cursor when hovering over column headers."""
        region = self.tree.identify_region(event.x, event.y)
        if region == "heading":
            column_id = self.tree.identify_column(event.x)
            column_index = int(column_id.replace("#", "")) - 1
            if column_index < len(self.dataframe.columns):
                column_name = self.dataframe.columns[column_index].strip()  # 🔹 Normalize
                tooltip_text = self.header_tooltips.get(column_name, f"No description available for '{column_name}'")

                self.tooltip_label.config(text=tooltip_text)
                self.tooltip_label.place(x=event.x_root + 10, y=event.y_root + 15)  # Place near cursor
        else:
            self.hide_tooltip(event)

    def hide_tooltip(self, event):
        """Hide the tooltip when the cursor moves away."""
        self.tooltip_label.place_forget()

    def sort_column(self, col):
        """Sort the table based on the selected column."""
        ascending = self.sort_orders[col]
        self.dataframe = self.dataframe.sort_values(by=col, ascending=ascending)
        self.populate_table()
        self.sort_orders[col] = not ascending

    def populate_table(self):
        """Populate the Treeview with DataFrame data."""
        for item in self.tree.get_children():
            self.tree.delete(item)
        for _, row in self.dataframe.iterrows():
            values = []
            for col in self.dataframe.columns:
                try:
                    num = float(row[col])
                    val = f"{num:.3f}"
                except (ValueError, TypeError):
                    val = str(row[col])
                values.append(val)
            self.tree.insert("", "end", values=values)

    def update_table(self):
        """Update the DataFrame and re-populate the table."""
        self.populate_table()

    def export_csv(self):
        """Export the DataFrame to a CSV file."""
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All Files", "*.*")],
            title="Save CSV as..."
        )
        if filename:
            try:
                self.dataframe.to_csv(filename, index=False)
                messagebox.showinfo("Export Successful", f"Data exported to '{filename}' successfully!")
            except Exception as e:
                messagebox.showerror("Export Error", str(e))
