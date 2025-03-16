import pandas as pd
import tkinter as tk
from tkinter import ttk

df_pcap_summary = pd.DataFrame(columns=[
    "PCAP File", "Flow Size (Total Packets)", "Duration (s)", "Flow Volume (Bytes)",
    "Avg Packet IAT (ms)", "Avg Packet Size (Bytes)", "TLS Versions", "Cipher Suites",
    "ALPN Protocols", "Transport Protocols", "IP Protocols"
])


def update_treeview():
    if "tree" not in globals():
        return  # Prevents errors if tree is not initialized

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
    tree = ttk.Treeview(tree_frame, yscrollcommand=tree_scroll.set, show="headings")
    tree_scroll.config(command=tree.yview)

    default_columns = list(df_pcap_summary.columns)
    tree["columns"] = default_columns

    for col in default_columns:
        tree.heading(col, text=col)
        tree.column(col, width=120)

    tree.pack(fill="both", expand=True)

    if not df_pcap_summary.empty:
        update_treeview()
