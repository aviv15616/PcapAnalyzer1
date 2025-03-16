import tkinter as tk
from tkinter import filedialog
import pandas as pd
from scapy.layers.inet import IP, TCP, UDP
from scapy.all import rdpcap
import numpy as np
from collections import defaultdict

# Define expected burstiness ranges based on QUIC/TLS behavior
EXPECTED_BURSTINESS = {
    "Web Browsing": {
        "CV": (2.0, 5.0),
        "Max/Mean": (10, 15),
        "PMR": (2.5, 5.0),
    },
    "YouTube": {
        "CV": (7.0, 9.0),
        "Max/Mean": (25, 40),
        "PMR": (7.0, 9.0),
    },
    "Spotify": {
        "CV": (5.0, 6.5),
        "Max/Mean": (10, 20),
        "PMR": (5.0, 6.5),
    }
}


def get_expected_burstiness(pcap_file, protocol_used):
    """ Determines expected burstiness range based on PCAP filename & protocol used """
    if "youtube" in pcap_file.lower():
        expected = EXPECTED_BURSTINESS["YouTube"]
    elif "spotify" in pcap_file.lower():
        expected = EXPECTED_BURSTINESS["Spotify"]
    else:  # Assume web browsing if not explicitly YouTube or Spotify
        expected = EXPECTED_BURSTINESS["Web Browsing"]

    # Adjust ranges if QUIC is detected (increase expected burstiness slightly)
    if protocol_used == "QUIC":
        expected = {
            "CV": (expected["CV"][0] * 1.1, expected["CV"][1] * 1.1),
            "Max/Mean": (expected["Max/Mean"][0] * 1.1, expected["Max/Mean"][1] * 1.1),
            "PMR": (expected["PMR"][0] * 1.1, expected["PMR"][1] * 1.1),
        }

    return expected


def analyze_pcap(file_path):
    """ Extracts burstiness-related values from a PCAP file, detecting QUIC/TLS usage. """
    packets = rdpcap(file_path)
    if len(packets) < 2:
        return None  # Not enough packets to analyze

    # Extract timestamps and convert to floats
    timestamps = [float(pkt.time) for pkt in packets if hasattr(pkt, 'time')]
    inter_arrival_times = np.diff(timestamps).astype(float)  # Convert to float for compatibility

    if len(inter_arrival_times) == 0:
        return None  # No inter-packet times to analyze

    # Determine the exact recording duration from first and last packet timestamps
    recording_duration = max(0.000001, timestamps[-1] - timestamps[0])  # Avoid division by zero

    # Detect QUIC vs TLS usage
    quic_count, tls_count = 0, 0
    for pkt in packets:
        if pkt.haslayer(IP):
            if pkt.haslayer(UDP) and pkt[UDP].dport == 443:
                quic_count += 1  # QUIC traffic
            elif pkt.haslayer(TCP) and pkt[TCP].dport == 443:
                tls_count += 1  # TLS traffic

    protocol_used = "QUIC" if quic_count > tls_count else "TLS"

    # Core Inter-Arrival Metrics
    std_inter_arrival = float(np.std(inter_arrival_times))
    mean_inter_arrival = float(np.mean(inter_arrival_times))
    max_inter_arrival = float(np.max(inter_arrival_times))

    # Compute CV Burstiness
    cv_burstiness = round(std_inter_arrival / mean_inter_arrival, 6) if mean_inter_arrival > 0 else 0

    # Compute Max/Mean Burstiness
    max_mean_burstiness = round(max_inter_arrival / mean_inter_arrival, 6) if mean_inter_arrival > 0 else 0

    # Compute Flow Size (Total Packets in PCAP)
    flow_size = len(packets)  # Total number of packets in the capture

    # Compute Mean Packet Rate (packets per second) using actual recording duration
    mean_packet_rate = round(flow_size / recording_duration, 6) if recording_duration > 0 else 0

    # Compute Peak Packet Rate (packets per second)
    packet_counts_per_second = defaultdict(int)
    for ts in timestamps:
        second = int(ts)
        packet_counts_per_second[second] += 1
    peak_packet_rate = max(packet_counts_per_second.values()) if packet_counts_per_second else 0

    # Compute PMR Burstiness (Peak-to-Mean Ratio)
    pmr_burstiness = round(peak_packet_rate / mean_packet_rate, 6) if mean_packet_rate > 0 else 0

    # Apply QUIC adjustment
    quic_multiplier = 1.2 if protocol_used == "QUIC" else 1.0
    adjusted_cv = round(cv_burstiness * quic_multiplier, 6)
    adjusted_max_mean = round(max_mean_burstiness * quic_multiplier, 6)
    adjusted_pmr = round(pmr_burstiness * quic_multiplier, 6)

    # Get expected burstiness range
    expected_burstiness = get_expected_burstiness(file_path, protocol_used)

    # Validate whether adjusted values fall in expected range
    def check_range(value, expected_range):
        return "✅" if expected_range[0] <= value <= expected_range[1] else "❌"

    return {
        "PCAP File": file_path.split("/")[-1],
        "Protocol Used": protocol_used,
        "Recording Duration (s)": recording_duration,
        # Core Inter-Arrival Time Stats
        "Std Dev Inter-Arrival": std_inter_arrival,
        "Mean Inter-Arrival": mean_inter_arrival,
        "Max Inter-Arrival Time": max_inter_arrival,
        # Flow Statistics
        "Flow Size (Total Packets)": flow_size,
        "Mean Packet Rate (pps)": mean_packet_rate,
        "Peak Packet Rate (pps)": peak_packet_rate,
        # Original Burstiness Metrics
        "Coefficient of Variation (CV)": cv_burstiness,
        "Max/Mean Burstiness": max_mean_burstiness,
        "PMR Burstiness (Peak-to-Mean)": pmr_burstiness,
        # Adjusted Burstiness Metrics for QUIC
        "Adjusted CV": adjusted_cv,
        "Adjusted Max/Mean Burstiness": adjusted_max_mean,
        "Adjusted PMR Burstiness": adjusted_pmr,
        # Expected Ranges
        "Expected CV": expected_burstiness["CV"],
        "Expected Max/Mean": expected_burstiness["Max/Mean"],
        "Expected PMR": expected_burstiness["PMR"],
        # Validation Checks
        "CV In Range": check_range(adjusted_cv, expected_burstiness["CV"]),
        "Max/Mean In Range": check_range(adjusted_max_mean, expected_burstiness["Max/Mean"]),
        "PMR In Range": check_range(adjusted_pmr, expected_burstiness["PMR"])
    }


# GUI setup remains the same...


def select_files():
    """ Opens a GUI file selector and processes multiple PCAPs. """
    file_paths = filedialog.askopenfilenames(title="Select PCAP files", filetypes=[("PCAP files", "*.pcap;*.pcapng")])
    if not file_paths:
        return

    results = []
    for file_path in file_paths:
        result = analyze_pcap(file_path)
        if result:
            results.append(result)

    if results:
        df = pd.DataFrame(results)

        # ✅ Ensure the full table is printed properly
        pd.set_option("display.max_rows", None)  # Show all rows
        pd.set_option("display.max_columns", None)  # Show all columns
        pd.set_option("display.width", 1000)  # Increase width to avoid wrapping
        pd.set_option("display.colheader_justify", "left")  # Align headers properly
        pd.set_option("display.float_format", "{:.6f}".format)  # Show 6 decimal places

        print(df)  # Full table will now be visible
        df.to_csv("pcap_analysis_results.csv", index=False)  # Save results

# GUI Setup
root = tk.Tk()
root.title("PCAP Analyzer - QUIC/TLS Aware")
root.geometry("300x200")

btn_select = tk.Button(root, text="Select PCAP Files", command=select_files, font=("Arial", 12), padx=10, pady=5)
btn_select.pack(pady=30)

root.mainloop()
