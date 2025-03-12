import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import threading
import pandas as pd
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

        self.upload_button = tk.Button(root, text="Upload Pcap", command=self.upload_pcap)
        self.upload_button.pack(pady=10)

        self.progress_label = tk.Label(root, text="")
        self.progress_label.pack()

        self.progress_bar = ttk.Progressbar(root, orient=tk.HORIZONTAL, length=300, mode='determinate')
        self.progress_bar.pack(pady=10)

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

    import os
    import tkinter as tk
    from tkinter import filedialog, messagebox

    def upload_pcap(self):
        """Custom file selection to prevent duplicate filenames and contents before selection."""
        selected_files = list(filedialog.askopenfilenames(filetypes=[("PCAP Files", "*.pcap")]))

        if not selected_files:
            return  # If user cancels selection, do nothing

        valid_files = []  # Store only unique files to add

        for file in selected_files:
            file_name = os.path.basename(file)

            # Check for duplicate filenames already in list
            if file_name in [os.path.basename(f) for f in self.pcap_files]:
                messagebox.showerror("Duplicate File",
                                     f"'{file_name}' is already selected. Please choose a different file.")
                continue  # Skip this file

            # Check for duplicate contents
            if any(self.compare_files(file, existing_file) for existing_file in self.pcap_files + valid_files):
                messagebox.showerror("Duplicate Content",
                                     f"A file with identical content as '{file_name}' is already selected.")
                continue  # Skip this file

            valid_files.append(file)  # Add only unique files

        if valid_files:
            self.pcap_files.extend(valid_files)  # Add new unique files
            self.upload_button.config(state=tk.DISABLED)
            self.show_table_button.config(state=tk.DISABLED)
            self.show_graphs_button.config(state=tk.DISABLED)

            self.progress_label.config(text="Processing PCAP files...")
            self.progress_bar['value'] = 0

            processing_thread = threading.Thread(target=self.process_pcap_thread, daemon=True)
            processing_thread.start()
        else:
            messagebox.showwarning("No New Files", "No new files were selected. Please choose different PCAPs.")

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
        self.pcap_data = process_pcap_files(self.pcap_files, self.progress_bar, self.progress_label, self.status_label, self.root)
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
