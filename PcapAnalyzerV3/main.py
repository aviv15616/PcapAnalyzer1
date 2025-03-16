import os
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import pandas as pd
import pyshark
from scapy.all import rdpcap, IP, TCP, UDP, Raw

df_pcap_summary = pd.DataFrame(columns=[
    "PCAP File", "Flow Size (Total Packets)", "Duration (s)", "Flow Volume (Bytes)",
    "Avg Packet IAT (ms)", "Avg Packet Size (Bytes)", "TLS Version",
    "Transport Protocols", "HTTP/1 Packets", "HTTP/2 Packets", "HTTP/3 Packets"
])

global tree

pcap_files = []
max_files = 10

# TLS version mapping
TLS_VERSION_MAP = {
    (3, 3): "TLS 1.2",
    (3, 4): "TLS 1.3"
}

def count_http_versions(file_path):
    """ Uses a single filter 'http || http2 || http3' and counts occurrences of HTTP/1, HTTP/2, and HTTP/3 """
    cap = pyshark.FileCapture(file_path, display_filter="http || http2 || http3")

    total_filtered = 0
    http1_count = 0
    http2_count = 0
    http3_count = 0

    for pkt in cap:
        total_filtered += 1
        try:
            if "HTTP/1." in pkt.highest_layer:
                http1_count += 1
            elif "HTTP2" in pkt.highest_layer:
                http2_count += 1
            elif "QUIC" in pkt.highest_layer:  # HTTP/3 uses QUIC
                http3_count += 1
        except AttributeError:
            continue  # Skip packets without a valid highest_layer

    cap.close()
    return http1_count, http2_count, http3_count


def process_pcap(file_path):
    packets = rdpcap(file_path)
    if not packets:
        return

    tls_versions = []
    transport_protocols = set()

    timestamps = [pkt.time for pkt in packets]
    sizes = [len(pkt) for pkt in packets]
    duration = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0
    avg_iat = sum([timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))]) / max(len(timestamps) - 1, 1)
    avg_size = sum(sizes) / max(len(sizes), 1)
    flow_volume = sum(sizes)

    for pkt in packets:
        if TCP in pkt:
            transport_protocols.add("TCP")
        elif UDP in pkt:
            transport_protocols.add("UDP")

        if TCP in pkt and pkt.haslayer(Raw):
            raw_payload = bytes(pkt[Raw])

            # Check for TLS handshake messages (ClientHello starts with 0x16)
            if raw_payload[:1] == b'\x16' and len(raw_payload) > 2:
                major_version = raw_payload[1]  # Major version (should be 3)
                minor_version = raw_payload[2]  # Minor version (3 or 4)

                tls_version = TLS_VERSION_MAP.get((major_version, minor_version), "Unknown")
                tls_versions.append(tls_version)

    # Determine the majority TLS version
    tls_version_final = "N/A"
    if tls_versions:
        tls_version_final = max(set(tls_versions), key=tls_versions.count)  # Most frequent version
        if tls_version_final not in ["TLS 1.2", "TLS 1.3"]:
            tls_version_final = "Unknown"

    # Use optimized HTTP version filtering with pyshark
    http1_count, http2_count, http3_count = count_http_versions(file_path)

    new_entry = {
        "PCAP File": os.path.basename(file_path),
        "Flow Size (Total Packets)": len(packets),
        "Duration (s)": duration,
        "Flow Volume (Bytes)": flow_volume,
        "Avg Packet IAT (ms)": avg_iat * 1000,
        "Avg Packet Size (Bytes)": avg_size,
        "TLS Version": tls_version_final,
        "Transport Protocols": ", ".join(transport_protocols) if transport_protocols else "N/A",
        "HTTP/1 Packets": http1_count,
        "HTTP/2 Packets": http2_count,
        "HTTP/3 Packets": http3_count
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
            loading_label.config(text=f"Processing {os.path.basename(file)} ({i}/{total})")
            process_pcap(file)
            pcap_files.append(file)

        loading_label.config(text="Processing complete!", fg="green")
        if 'tree' in globals():
            update_treeview()

    threading.Thread(target=process_files).start()


def update_treeview():
    if 'tree' not in globals():
        return

    for row in tree.get_children():
        tree.delete(row)

    for _, row in df_pcap_summary.iterrows():
        tree.insert("", "end", values=row.tolist())


def show_dataframe():
    df_window = tk.Toplevel()
    df_window.title("PCAP DataFrame")
    df_window.geometry("1000x400")

    tree_frame = ttk.Frame(df_window)
    tree_frame.pack(fill="both", expand=True)

    tree_scroll = ttk.Scrollbar(tree_frame)
    tree_scroll.pack(side="right", fill="y")

    global tree
    tree = ttk.Treeview(tree_frame, yscrollcommand=tree_scroll.set, show="headings",
                        columns=list(df_pcap_summary.columns))
    tree_scroll.config(command=tree.yview)

    for col in df_pcap_summary.columns:
        tree.heading(col, text=col)
        tree.column(col, width=120)

    tree.pack(fill="both", expand=True)
    update_treeview()


root = tk.Tk()
root.title("PCAP Analyzer")
root.geometry("600x400")

frame = tk.Frame(root)
frame.pack(pady=20)

loading_label = tk.Label(frame, text="Select PCAP files to begin.")
loading_label.pack()

btn_load = ttk.Button(frame, text="Load PCAPs", command=lambda: load_pcaps(loading_label))
btn_load.pack(pady=10)

btn_df = ttk.Button(frame, text="Show DataFrame", command=show_dataframe)
btn_df.pack(pady=5)

root.mainloop()
