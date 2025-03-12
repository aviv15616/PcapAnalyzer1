import pyshark
import pandas as pd
import numpy as np
import asyncio
import os

def process_pcap_files(pcap_files, progress_bar, progress_label, status_label, root):
    asyncio.set_event_loop(asyncio.new_event_loop())
    data = []
    total_files = len(pcap_files)

    for index, pcap_file in enumerate(pcap_files):
        cap = pyshark.FileCapture(pcap_file, use_json=True, include_raw=False, display_filter="")
        packets = list(cap)

        file_name = os.path.splitext(os.path.basename(pcap_file))[0]

        if len(packets) > 0:
            packet_sizes = [int(pkt.length) for pkt in packets if hasattr(pkt, 'length')]

            inter_arrival_times = [
                float(packets[i].sniff_time.timestamp()) - float(packets[i - 1].sniff_time.timestamp())
                for i in range(1, len(packets))
            ]

            total_packets = len(packet_sizes)
            total_bytes = sum(packet_sizes)
            mean_packet_size = round(np.mean(packet_sizes), 3) if total_packets > 0 else 0
            avg_inter_arrival = round(np.mean(inter_arrival_times), 6) if inter_arrival_times else 0

            tls_version, cipher_suite, tls_fingerprint, tls_distinction, sni = extract_tls_info(pcap_file)

            data.append({
                "PcapFile": file_name,
                "AvgPktSize": mean_packet_size,
                "AvgInterArrival": avg_inter_arrival,
                "FlowSize": total_packets,
                "FlowVolume": total_bytes,
                "TLS Version": tls_version,
                "Cipher Suite": cipher_suite,
                "TLS Fingerprint": tls_fingerprint,
                "TLS Distinction Score": round(tls_distinction, 3),
            })

        cap.close()
        progress = ((index + 1) / total_files) * 100
        progress_bar['value'] = progress
        root.update_idletasks()

    progress_label.config(text="Processing Complete!")
    status_label.config(text=f"{total_files} PCAPs processed successfully!")
    progress_bar['value'] = 100
    df = pd.DataFrame(data)
    df.fillna("Unknown", inplace=True)

    return df


def extract_tls_info(pcap_file):
    cap = pyshark.FileCapture(pcap_file, display_filter="tls.handshake.type == 1")

    tls_versions, cipher_suites, tls_fingerprints, sni_domains = set(), set(), [], set()

    for pkt in cap:
        try:
            if hasattr(pkt.tls, "handshake_version"):
                tls_versions.add(pkt.tls.handshake_version)

            if hasattr(pkt.tls, "handshake_ciphersuite"):
                cipher_suites.add(pkt.tls.handshake_ciphersuite)

            if hasattr(pkt.tls, "handshake_version") and hasattr(pkt.tls, "handshake_ciphersuite"):
                tls_fingerprints.append(f"{pkt.tls.handshake_version}-{pkt.tls.handshake_ciphersuite}")

            if hasattr(pkt.tls, 'handshake_extensions_server_name'):
                sni_domains.add(pkt.tls.handshake_extensions_server_name)

        except AttributeError:
            continue

    cap.close()

    return (
        ", ".join(tls_versions) if tls_versions else "Unknown",
        ", ".join(cipher_suites) if cipher_suites else "Unknown",
        ", ".join(set(tls_fingerprints)) if tls_fingerprints else "Unknown",
        np.random.uniform(0.1, 1.0),  # Simulated TLS Distinction Score
        ", ".join(sni_domains) if sni_domains else "No SNI"
    )

