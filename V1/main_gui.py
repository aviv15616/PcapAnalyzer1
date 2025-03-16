import hashlib
import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import threading
import pandas as pd
from matplotlib.testing.compare import get_file_hash

from graphs import show_graphs_menu
from pcap_processor import process_pcap_files
from data_frame import DataFrame  # Assuming this is your table class

class MainGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Pcap Traffic Analyzer")
        self.root.geometry("400x350")
        self.root.resizable(False, False)
        self.pcap_files = []
        self.max_files = 10
        self.pcap_data = pd.DataFrame()
        self.system_status_label = tk.Label(self.root, text="PCAPs in system: 0/10")
        self.system_status_label.pack()


        self.upload_button = tk.Button(root, text="Upload Pcap", command=self.upload_pcap)
        self.upload_button.pack(pady=10)

        self.progress_label = tk.Label(root, text="")
        self.progress_label.pack()



        # Status label to display the processed PCAP message below the progress bar
        self.status_label = tk.Label(root, text="", fg="green")
        self.status_label.pack(pady=5)

        self.show_table_button = tk.Button(root, text="Show Comparison Table", command=self.show_table, state=tk.DISABLED)
        self.show_table_button.pack(pady=10)

        # Instead of using a lambda, we now call a dedicated show_graphs() method
        self.show_graphs_button = tk.Button(root, text="Show Graphs", command=self.show_graphs, state=tk.DISABLED)
        self.show_graphs_button.pack(pady=10)

        # Variable to hold the table viewer instance (if open)
        self.table_viewer = None


    def get_file_hash(file_path):
        """Compute hash for a file to detect duplicates based on content."""
        hasher = hashlib.sha256()
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        return hasher.hexdigest()



    def upload_pcap(self):
        """Strictly enforce a maximum of 10 PCAPs in the system with optimized checks and safe threading."""

        selected_files = list(filedialog.askopenfilenames(filetypes=[("PCAP Files", "*.pcap")]))

        if not selected_files:
            return  # User canceled selection

        valid_files = []
        existing_hashes = {get_file_hash(f) for f in self.pcap_files}  # Hash set for faster duplicate detection

        for file in selected_files:
            file_name = os.path.basename(file)

            # Check for duplicate filenames
            if file_name in [os.path.basename(f) for f in self.pcap_files]:
                self.root.after(0,
                                lambda: messagebox.showerror("Duplicate File", f"'{file_name}' is already selected."))
                continue  # Skip this file

            # Check for duplicate content
            file_hash = get_file_hash(file)
            if file_hash in existing_hashes:
                self.root.after(0, lambda: messagebox.showerror("Duplicate Content",
                                                                f"A file with identical content as '{file_name}' is already selected."))
                continue  # Skip this file

            valid_files.append(file)
            existing_hashes.add(file_hash)  # Add to seen hashes

        # Check if adding selected files would exceed the limit
        if len(self.pcap_files) + len(valid_files) > self.max_files:
            self.root.after(0, lambda: messagebox.showerror("Limit Reached",
                                                            f"Cannot add {len(valid_files)} files. Only {self.max_files - len(self.pcap_files)} more allowed."))
            return  # Stop upload immediately

        if valid_files:
            self.pcap_files.extend(valid_files)
            self.root.after(0,
                            lambda: self.system_status_label.config(text=f"PCAPs in system: {len(self.pcap_files)}/10"))

            # **יצירת Thread רק עבור עיבוד הקבצים, בלי גישה ישירה ל-Tkinter**
            processing_thread = threading.Thread(target=self.process_pcap_thread, daemon=True)
            processing_thread.start()
        else:
            self.root.after(0, lambda: messagebox.showwarning("No New Files", "No new files were selected."))

    # Helper function to compare file contents
    def compare_files(self, file1, file2):
        """Compares two PCAP files byte by byte to check if they are identical."""
        try:
            with open(file1, "rb") as f1, open(file2, "rb") as f2:
                return f1.read() == f2.read()
        except Exception as e:
            print(f"Error comparing files: {e}")
            return False  # If error occurs, assume files are different

    def process_pcap_thread(self):
        self.pcap_data = process_pcap_files(self.pcap_files, self.status_label, self.system_status_label, self.root)
        self.upload_button.config(state=tk.NORMAL)
        self.show_table_button.config(state=tk.NORMAL)
        self.show_graphs_button.config(state=tk.NORMAL)

        processed_count = len(self.pcap_files)
        self.status_label.config(text=f"{processed_count} PCAPs processed successfully! {processed_count}/10 in the system")

        # If the table viewer is open, update its table
        if self.table_viewer:
            self.table_viewer.dataframe = self.pcap_data
            self.table_viewer.update_table()

    def show_table(self):
        if self.pcap_data.empty:
            messagebox.showerror("Error", "No data available. Please upload PCAP files first.")
            return

        # If the table viewer is already open, update and bring it to front
        if self.table_viewer and self.table_viewer.window.winfo_exists():
            self.table_viewer.dataframe = self.pcap_data
            self.table_viewer.update_table()
            self.table_viewer.window.lift()
        else:
            self.table_viewer = DataFrame(self.root, self.pcap_data)

    def show_graphs(self):
        # New method to show graphs
        if self.pcap_data.empty:
            messagebox.showerror("Error", "No data available. Please upload PCAP files first.")
            return

        # Call the graphs function passing the current pcap_data
        show_graphs_menu(self.pcap_data)

if __name__ == "__main__":
    root = tk.Tk()
    gui = MainGUI(root)
    root.mainloop()
