import tkinter as tk
from tkinter import filedialog, messagebox
from data_frame import DataFrameWindow
from pcap_processor import PcapProcessor
from graph import Graph
import os
import threading


class PcapGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("PCAP Analyzer")
        self.root.geometry("400x350")

        self.processor = PcapProcessor(sample_mode=False)  # Initialize processor with sampling enabled for tests disabled for true results
        self.data_window = None  # No DataFrameWindow initialized yet
        self.graph_window = None

        self.load_button = tk.Button(root, text="Load PCAPs", command=self.load_pcaps)
        self.load_button.pack(pady=10)

        self.show_button = tk.Button(root, text="Show DataFrame", command=self.show_dataframe)
        self.show_button.pack(pady=10)

        self.graph_button = tk.Button(root, text="Show Graphs", command=self.show_graphs)
        self.graph_button.pack(pady=10)

        self.progress_label = tk.Label(root, text="")
        self.progress_label.pack(pady=5)

        self.current_file_label = tk.Label(root, text="")
        self.current_file_label.pack(pady=5)

        # Initialize DataFrameWindow with empty data
        self.show_dataframe(empty_init=True)

    def load_pcaps(self):
        remaining_slots = 10 - len(self.processor.pcap_data)  # ✅ Check how many slots are left

        if remaining_slots <= 0:
            messagebox.showerror("Error", "Cannot load more than 10 PCAP files.")
            return  # ✅ Prevent file selection if limit is reached

        files = filedialog.askopenfilenames(
            filetypes=[("PCAP Files", "*.pcap;*.pcapng"), ("All Files", "*.*")],
            title=f"Select up to {remaining_slots} more PCAP files"
        )

        if files:
            if len(files) > remaining_slots:
                messagebox.showerror("Error", f"You can only add {remaining_slots} more files.")
                return  # ✅ Prevent selecting too many files

            threading.Thread(target=self.process_pcaps_thread, args=(files,), daemon=True).start()

    def process_pcaps_thread(self, files):
        total_files = len(files)
        processed_files = 0
        successfully_uploaded = 0  # Track successful uploads

        for file in files:
            if len(self.processor.pcap_data) >= 10:
                messagebox.showerror("Error", "Cannot load more than 10 PCAP files.")

                return  # No message, silently ignore further uploads

            processed_files += 1
            self.root.after(0, lambda: self.progress_label.config(
                text=f"Processing PCAPs ({processed_files}/{total_files})"))
            self.root.after(0, lambda: self.current_file_label.config(text=f"Current File: {os.path.basename(file)}"))

            previous_count = len(self.processor.pcap_data)  # Track before processing
            success = self.processor.process_pcap(file)

            # Check if new data was actually added
            if success:
                successfully_uploaded += 1

            # Update DataFrame dynamically after each file is loaded
            if self.data_window:
                self.root.after(0, lambda: self.data_window.update_data(self.processor.pcap_data))

        self.root.after(0, lambda: self.progress_label.config(text="Processing Complete!"))
        self.root.after(0, lambda: self.current_file_label.config(text=""))

        # Show final status message based on upload results
        if successfully_uploaded > 0:
            self.root.after(0, lambda: messagebox.showinfo("Success", "PCAPs loaded successfully!"))
        elif processed_files > 0 and successfully_uploaded == 0:
            self.root.after(0, lambda: messagebox.showinfo("No New Files", "No new PCAPs loaded."))

    def show_dataframe(self, empty_init=False):
        if not self.data_window or not self.data_window.winfo_exists():
            self.data_window = DataFrameWindow(self.root, [] if empty_init else self.processor.pcap_data)
            self.data_window.state("zoomed")  # ✅ Maximized window with controls
        else:
            self.data_window.update_data(self.processor.pcap_data)
            self.data_window.focus()

    def show_graphs(self):
        if not self.processor.pcap_data:
            messagebox.showwarning("No Data", "No PCAP files loaded.")
            return

        if not self.graph_window or not self.graph_window.winfo_exists():
            self.graph_window = Graph(self.root, self.processor.pcap_data)
            self.graph_window.state("zoomed")  # ✅ Maximized window with controls
        else:
            self.graph_window.focus()
        # ==============================
        # ✅ HELPER FUNCTIONS
        # ==============================







