import tkinter as tk
import matplotlib.pyplot as plt


def show_graphs_menu(pcap_data):
    graph_window = tk.Toplevel()
    graph_window.title("Select Graph")
    graph_window.geometry("300x400")

    # Exclude "TLS Distinction Score", "ECH Packet Sizes", and "ECH IPT" from the main menu
    feature_columns = [col for col in pcap_data.columns if col not in [
        "PcapFile", "TLS Fingerprint", "Cipher Suite", "TLS Version",
        "TLS Distinction Score", "ECH Packet Sizes", "ECH IPT","FlowDuration",
    ]]

    for column in feature_columns:
        btn = tk.Button(graph_window, text=column, command=lambda g=column: plot_graph(pcap_data, g))
        btn.pack(pady=5)

    tls_btn = tk.Button(graph_window, text="TLS Comparison", command=lambda: show_tls_graphs_menu(pcap_data))
    tls_btn.pack(pady=10)


def show_tls_graphs_menu(pcap_data):
    tls_graph_window = tk.Toplevel()
    tls_graph_window.title("TLS Comparison")
    tls_graph_window.geometry("300x400")

    buttons = [
        ("TLS Fingerprint per Service", plot_tls_fingerprint),
        ("TLS Distinction Score", plot_tls_distinction),
        ("Cipher Suites Distribution", plot_cipher_suites),
        ("TLS Versions per Service", plot_tls_versions),
        ("ECH Packet Size Distribution", plot_ech_packet_size),
        ("ECH Inter-Packet Time Distribution", plot_ech_ipt),
    ]

    for text, func in buttons:
        btn = tk.Button(tls_graph_window, text=text, command=lambda f=func: f(pcap_data))
        btn.pack(pady=5)


def plot_tls_fingerprint(pcap_data):
    plt.figure(figsize=(10, 6))
    y_values = pcap_data["TLS Fingerprint"].value_counts()
    plt.bar(y_values.index, y_values.values, color='b')
    plt.xlabel("TLS Fingerprint")
    plt.ylabel("Count")
    plt.xticks(rotation=45, ha="right")
    plt.title("TLS Fingerprint per Service")
    plt.tight_layout()
    plt.show()


def plot_tls_distinction(pcap_data):
    plt.figure(figsize=(10, 6))
    services = pcap_data["PcapFile"].unique()
    distinction_scores = pcap_data["TLS Distinction Score"].astype(float)
    plt.scatter(services, distinction_scores, color='r')
    plt.xlabel("Services")
    plt.ylabel("TLS Distinction Score")
    plt.xticks(rotation=45, ha="right")
    plt.title("TLS Distinction Score between Services")
    plt.tight_layout()
    plt.show()


def plot_ech_packet_size(pcap_data):
    plt.figure(figsize=(10, 6))

    all_sizes = [size for sizes in pcap_data["ECH Packet Sizes"] for size in sizes]

    plt.hist(all_sizes, bins=20, color='purple', alpha=0.7)
    plt.xlabel("Packet Size (Bytes)")
    plt.ylabel("Count")
    plt.title("ECH ClientHello Packet Size Distribution")
    plt.tight_layout()
    plt.show()


def plot_ech_ipt(pcap_data):
    plt.figure(figsize=(10, 6))

    all_ipts = [ipt for ipts in pcap_data["ECH IPT"] for ipt in ipts]

    plt.hist(all_ipts, bins=20, color='red', alpha=0.7)
    plt.xlabel("Inter-Packet Time (Seconds)")
    plt.ylabel("Count")
    plt.title("ECH ClientHello Inter-Packet Time Distribution")
    plt.tight_layout()
    plt.show()


def plot_cipher_suites(pcap_data):
    plt.figure(figsize=(10, 6))
    cipher_counts = pcap_data["Cipher Suite"].value_counts()
    plt.bar(cipher_counts.index, cipher_counts.values, color='g')
    plt.xlabel("Cipher Suite")
    plt.ylabel("Count")
    plt.xticks(rotation=45, ha="right")
    plt.title("Cipher Suites Distribution")
    plt.tight_layout()
    plt.show()


def plot_tls_versions(pcap_data):
    plt.figure(figsize=(10, 6))
    version_counts = pcap_data["TLS Version"].value_counts()
    plt.bar(version_counts.index, version_counts.values, color='c')
    plt.xlabel("TLS Version")
    plt.ylabel("Count")
    plt.xticks(rotation=45, ha="right")
    plt.title("TLS Versions per Service")
    plt.tight_layout()
    plt.show()


def plot_graph(pcap_data, feature):
    plt.figure(figsize=(10, 6))

    # Check if values are lists and explode them if needed
    if isinstance(pcap_data[feature].iloc[0], list):
        exploded_data = pcap_data.explode(feature)
        y_values = exploded_data[feature].astype(float)
    else:
        y_values = pcap_data[feature].astype(float)

    x_labels = pcap_data["PcapFile"].astype(str).str.strip()

    plt.bar(x_labels, y_values, color='b')

    plt.xlabel("PCAP File")
    plt.ylabel(feature)
    plt.xticks(rotation=45, ha="right")
    plt.title(f"Comparison of {feature} Across PCAP Files")

    plt.subplots_adjust(bottom=0.2, top=0.85)
    plt.show()
