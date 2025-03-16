import os
import numpy as np
import pandas as pd
import tkinter as tk
from tkinter import filedialog
from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP, UDP
import matplotlib.pyplot as plt

# Expected Burstiness Factor Ranges (Based on Research Findings)
EXPECTED_RANGES = {
    "Browsing Chrome (TLS)": {"PMR": (3.0, 5.0), "MMR": (80000, 250000), "CV": (1.2, 2.0)},
    "Browsing Firefox (TLS)": {"PMR": (3.0, 5.5), "MMR": (90000, 280000), "CV": (1.3, 2.2)},
    "YouTube Chrome (QUIC)": {"PMR": (2.0, 3.5), "MMR": (400000, 900000), "CV": (0.6, 1.2)},
    "YouTube Firefox (TLS)": {"PMR": (3.5, 5.0), "MMR": (500000, 1000000), "CV": (0.8, 1.4)},
    "Spotify Chrome (QUIC)": {"PMR": (1.8, 3.0), "MMR": (150000, 350000), "CV": (0.5, 1.0)},
    "Spotify Firefox (TLS)": {"PMR": (2.5, 4.0), "MMR": (200000, 400000), "CV": (0.7, 1.3)},
    "Zoom (TLS)": {"PMR": (1.2, 2.5), "MMR": (250000, 800000), "CV": (0.4, 1.0)},
}


# Function to classify PCAP based on filename
def classify_pcap(filename):
    lower_name = filename.lower()
    if "youtube" in lower_name:
        return "YouTube Chrome (QUIC)" if "chrome" in lower_name else "YouTube Firefox (TLS)"
    elif "spotify" in lower_name:
        return "Spotify Chrome (QUIC)" if "chrome" in lower_name else "Spotify Firefox (TLS)"
    elif "zoom" in lower_name:
        return "Zoom (TLS)"
    elif "firefox" in lower_name:
        return "Browsing Firefox (TLS)"
    elif "chrome" in lower_name:
        return "Browsing Chrome (TLS)"
    else:
        return "Unknown"


# Function to extract timestamps, sizes, and inter-arrival times from PCAP
def extract_pcap_features(pcap_file):
    packets = rdpcap(pcap_file)
    timestamps, sizes = [], []

    for pkt in packets:
        if IP in pkt and (TCP in pkt or UDP in pkt):
            timestamps.append(float(pkt.time))
            sizes.append(int(len(pkt)))

    if len(timestamps) < 2:
        return None

    inter_arrival_times = np.diff(timestamps)

    return {
        "timestamps": np.array(timestamps, dtype=float),
        "sizes": np.array(sizes, dtype=int),
        "inter_arrival_times": inter_arrival_times
    }


# Function to compute Peak-to-Mean Ratio (PMR)
def compute_pmr(sizes, timestamps):
    if len(sizes) < 2:
        return None

    timestamps = np.array(timestamps, dtype=float)
    sizes = np.array(sizes, dtype=int)

    time_diffs = np.diff(timestamps)

    # Replace zero intervals with a very small value to retain data integrity
    time_diffs[time_diffs == 0] = 1e-6
    throughput = sizes[:-1] / time_diffs

    return np.max(throughput) / np.mean(throughput) if np.mean(throughput) > 0 else None


# Function to compute Max Mean Rate (MMR)
def compute_mmr(sizes, timestamps, window=1.0):
    if len(sizes) < 2 or window <= 0:
        return None

    timestamps = np.array(timestamps, dtype=float)
    sizes = np.array(sizes, dtype=int)

    min_time, max_time = np.min(timestamps), np.max(timestamps)
    if min_time == max_time:
        return None

    time_bins = np.arange(min_time, max_time, window)
    throughput_per_window = []

    for t in time_bins:
        valid_mask = (timestamps >= t) & (timestamps < t + window)
        if np.any(valid_mask):
            throughput_per_window.append(np.sum(sizes[valid_mask]) / window)

    return np.max(throughput_per_window) if throughput_per_window else None


# Function to compute Coefficient of Variation (CV)
def compute_cv(inter_arrival_times):
    if len(inter_arrival_times) < 2:
        return None

    inter_arrival_times = np.array(inter_arrival_times, dtype=float)
    mean_iat = np.mean(inter_arrival_times)

    if mean_iat == 0:
        return None

    return np.std(inter_arrival_times) / mean_iat


# Function to check if value is within the expected range
def check_range(value, expected_range):
    if value is None:
        return "N/A"
    return "✅" if expected_range[0] <= value <= expected_range[1] else "❌"


# Function to process PCAP files and generate the results table
def process_pcaps(pcap_files):
    results = []

    for pcap in pcap_files:
        file_name = os.path.basename(pcap)
        category = classify_pcap(file_name)

        if category not in EXPECTED_RANGES:
            results.append([file_name, category, "Unknown Type"] + ["N/A"] * 6)
            continue

        features = extract_pcap_features(pcap)
        if features is None:
            results.append([file_name, category, "Not Enough Data"] + ["N/A"] * 6)
            continue

        pmr = compute_pmr(features["sizes"], features["timestamps"])
        mmr = compute_mmr(features["sizes"], features["timestamps"])
        cv = compute_cv(features["inter_arrival_times"])

        expected = EXPECTED_RANGES[category]
        results.append([
            file_name, category,
            len(features["sizes"]), np.mean(features["sizes"]),
            np.mean(features["inter_arrival_times"]),
            pmr, check_range(pmr, expected["PMR"]),
            mmr, check_range(mmr, expected["MMR"]),
            cv, check_range(cv, expected["CV"])
        ])

    df = pd.DataFrame(results, columns=["PCAP File", "Category", "Packet Count", "Avg Packet Size",
                                        "Avg Inter-Arrival Time", "PMR", "PMR ✅/❌", "MMR",
                                        "MMR ✅/❌", "CV", "CV ✅/❌"])

    print(df.to_string(index=False))


# Function to open file selection dialog and process PCAPs
def select_pcaps():
    root = tk.Tk()
    root.withdraw()
    file_paths = filedialog.askopenfilenames(title="Select PCAP files", filetypes=[("PCAP files", "*.pcap")])
    if file_paths:
        process_pcaps(file_paths)


if __name__ == "__main__":
    select_pcaps()
