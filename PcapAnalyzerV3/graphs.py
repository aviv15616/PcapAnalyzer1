import tkinter as tk
from tkinter import ttk, messagebox
import matplotlib.pyplot as plt


def show_graphs():
    graph_window = tk.Toplevel()
    graph_window.title("Graph Selection")
    graph_window.geometry("400x600")

    graph_titles = [
        "TLS Version Distribution", "Cipher Suite Usage", "Session Resumption",
        "ALPN Protocols Usage", "TLS Record Length Distribution", "TLS Handshake Time",
        "TLS Packet Inter-Arrival Time", "Packet Size Distribution", "Flow Rate",
        "Flow Volume", "Burstiness (CV-Based Jitter)", "Burstiness (Max/Mean IAT)",
        "Burstiness (PMR)", "HTTP Version Distribution", "Transport Protocol Usage", "IP Protocol Distribution"
    ]

    for title in graph_titles:
        ttk.Button(graph_window, text=title, command=lambda t=title: plot_graph(t)).pack(pady=5)


def plot_graph(graph_title):
    messagebox.showinfo("Plot", f"Plotting: {graph_title}")
    plt.figure()
    plt.title(graph_title)
    plt.show()
