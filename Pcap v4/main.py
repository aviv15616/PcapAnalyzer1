import tkinter as tk
from tkinter import filedialog, messagebox
from data_frame import DataFrameWindow
from pcap_processor import PcapProcessor
import os
import threading


class PcapGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("PCAP Analyzer")
        self.root.geometry("400x300")

        self.processor = PcapProcessor()
        self.data_window = None  # No DataFrameWindow initialized yet

        self.load_button = tk.Button(root, text="Load PCAPs", command=self.load_pcaps)
        self.load_button.pack(pady=10)

        self.show_button = tk.Button(root, text="Show DataFrame", command=self.show_dataframe)
        self.show_button.pack(pady=10)

        self.progress_label = tk.Label(root, text="")
        self.progress_label.pack(pady=5)

        self.current_file_label = tk.Label(root, text="")
        self.current_file_label.pack(pady=5)

        # Initialize DataFrameWindow with empty data
        self.show_dataframe(empty_init=True)

    def load_pcaps(self):
        files = filedialog.askopenfilenames(filetypes=[("PCAP Files", "*.pcap;*.pcapng")])
        if files:
            threading.Thread(target=self.process_pcaps_thread, args=(files,), daemon=True).start()

    def process_pcaps_thread(self, files):
        total_files = len(files)
        processed_files = 0
        for file in files:
            if len(self.processor.pcap_data) >= 10:
                self.root.after(0,
                                lambda: messagebox.showwarning("Limit Exceeded", "Only 10 PCAP files can be loaded."))
                break

            processed_files += 1
            self.root.after(0, lambda: self.progress_label.config(
                text=f"Processing PCAPs ({processed_files}/{total_files})"))
            self.root.after(0, lambda: self.current_file_label.config(text=f"Current File: {os.path.basename(file)}"))

            self.processor.process_pcap(file)

            # Update DataFrame dynamically after each file is loaded
            if self.data_window:
                self.root.after(0, lambda: self.data_window.update_data(self.processor.pcap_data))

        self.root.after(0, lambda: self.progress_label.config(text="Processing Complete!"))
        self.root.after(0, lambda: self.current_file_label.config(text=""))
        self.root.after(0, lambda: messagebox.showinfo("Success", "PCAP files loaded successfully!"))

    def show_dataframe(self, empty_init=False):
        if not self.data_window or not self.data_window.winfo_exists():
            self.data_window = DataFrameWindow(self.root, [] if empty_init else self.processor.pcap_data)
        else:
            self.data_window.update_data(self.processor.pcap_data)
            self.data_window.focus()


if __name__ == "__main__":
    root = tk.Tk()
    app = PcapGUI(root)
    root.mainloop()
