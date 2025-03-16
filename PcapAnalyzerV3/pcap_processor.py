import os
import threading
from tkinter import filedialog, messagebox
import pandas as pd
from scapy.all import rdpcap
from data_frame import update_treeview, df_pcap_summary

global tree  # Ensure tree is globally recognized

max_files = 10
pcap_files = []


def process_pcap(file_path):
    packets = rdpcap(file_path)
    if not packets:
        return

    timestamps = [pkt.time for pkt in packets]
    sizes = [len(pkt) for pkt in packets]
    duration = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0
    avg_iat = sum([timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))]) / max(len(timestamps) - 1, 1)
    avg_size = sum(sizes) / max(len(sizes), 1)
    flow_volume = sum(sizes)

    new_entry = {
        "PCAP File": os.path.basename(file_path),
        "Flow Size (Total Packets)": len(packets),
        "Duration (s)": duration,
        "Flow Volume (Bytes)": flow_volume,
        "Avg Packet IAT (ms)": avg_iat * 1000,
        "Avg Packet Size (Bytes)": avg_size,
        "TLS Versions": "N/A",
        "Cipher Suites": "N/A",
        "ALPN Protocols": "N/A",
        "Transport Protocols": "N/A",
        "IP Protocols": "N/A"
    }

    global df_pcap_summary
    df_pcap_summary = pd.concat([df_pcap_summary, pd.DataFrame([new_entry])], ignore_index=True)


def load_pcaps(loading_label):
    global pcap_files
    files = filedialog.askopenfilenames(title="Select PCAP files", filetypes=[("PCAP files", "*.pcap")])

    if not files:
        loading_label.config(text="No files selected.", fg="red")
        return

    if len(files) + len(pcap_files) > max_files:
        messagebox.showerror("Error", "Cannot load more than 10 PCAP files.")
        return

    loading_label.config(text="Loading files...", fg="blue")

    def process_files():
        total = len(files)
        for i, file in enumerate(files, start=1):
            loading_label.config(text=f"Loading {os.path.basename(file)} ({i}/{total})")
            process_pcap(file)
            pcap_files.append(file)

        loading_label.config(text="Loading complete!", fg="green")
        try:
            update_treeview()
        except NameError:
            pass  # Prevents error if tree is not initialized

    threading.Thread(target=process_files).start()
