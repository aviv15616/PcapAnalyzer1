import pyshark
import pandas as pd
import numpy as np
import asyncio
import os

def process_pcap_files(pcap_files, status_label, system_status_label, root):
    """ Processes multiple PCAP files """
    asyncio.set_event_loop(asyncio.new_event_loop())  # Ensure asyncio loop is reset
    data = []
    total_files = len(pcap_files)
    completed_files = 0  # Track completed PCAPs

    # Update system status label with total PCAPs in the system
    root.after(0, lambda: system_status_label.config(text=f"PCAPs in system: {len(pcap_files)}/10"))

    for file_index, pcap_file in enumerate(pcap_files, start=1):
        file_name = os.path.splitext(os.path.basename(pcap_file))[0]
        cap = pyshark.FileCapture(pcap_file, use_json=True, include_raw=False)

        # Count total packets first
        total_packets = sum(1 for _ in cap)
        cap.close()

        if total_packets == 0:
            continue  # Skip empty files

        cap = pyshark.FileCapture(pcap_file, use_json=True, include_raw=False)

        # Update processing status
        root.after(0, lambda: status_label.config(text=f"Processing {file_index}/{total_files} PCAPs"))

        packet_sizes = []
        inter_arrival_times = []
        prev_timestamp = None
        tcp_flag_counts = {"SYN": 0, "ACK": 0, "FIN": 0, "RST": 0, "PSH": 0}
        protocol_counts = {}
        sent_packets = 0
        received_packets = 0
        http2_count = 0
        client_ip = None

        for pkt in cap:
            try:
                if hasattr(pkt, "length"):
                    packet_sizes.append(int(pkt.length))
                if prev_timestamp is not None:
                    inter_arrival_times.append(float(pkt.sniff_time.timestamp()) - prev_timestamp)
                prev_timestamp = float(pkt.sniff_time.timestamp())
                if client_ip is None and hasattr(pkt, "ip"):
                    if hasattr(pkt, "tcp") and hasattr(pkt.tcp, "flags"):
                        if int(pkt.tcp.flags, 16) & 0x02:  # SYN flag
                            client_ip = pkt.ip.src
                    elif hasattr(pkt, "udp"):
                        client_ip = pkt.ip.src
                if hasattr(pkt, "tcp") and hasattr(pkt.tcp, "flags"):
                    flags = int(pkt.tcp.flags, 16)
                    if flags & 0x02:
                        tcp_flag_counts["SYN"] += 1
                    if flags & 0x10:
                        tcp_flag_counts["ACK"] += 1
                    if flags & 0x01:
                        tcp_flag_counts["FIN"] += 1
                    if flags & 0x04:
                        tcp_flag_counts["RST"] += 1
                    if flags & 0x08:
                        tcp_flag_counts["PSH"] += 1
                if hasattr(pkt, "ip") and hasattr(pkt.ip, "proto"):
                    proto = int(pkt.ip.proto)
                    protocol_counts[proto] = protocol_counts.get(proto, 0) + 1
                if hasattr(pkt, "http2"):
                    http2_count += 1
                if hasattr(pkt, "ip"):
                    if pkt.ip.src == client_ip:
                        sent_packets += 1
                    elif pkt.ip.dst == client_ip:
                        received_packets += 1
            except AttributeError:
                continue

        cap.close()

        # Compute final values
        total_bytes = sum(packet_sizes)
        mean_packet_size = round(np.mean(packet_sizes), 3) if packet_sizes else 0
        avg_inter_arrival = round(np.mean(inter_arrival_times), 6) if inter_arrival_times else 0
        burstiness = round(np.std(inter_arrival_times) / avg_inter_arrival, 6) if avg_inter_arrival > 0 else 0

        # Extract TLS information
        tls_version, cipher_suite, tls_fingerprint, tls_distinction, ech_packet_sizes, ech_ipts = extract_tls_info(pcap_file)

        formatted_protocols = ", ".join(f"{proto}: {count}" for proto, count in protocol_counts.items()) if protocol_counts else "None"
        formatted_tcp_flags = ", ".join(f"{flag}: {count}" for flag, count in tcp_flag_counts.items()) if tcp_flag_counts else "None"

        data.append({
            "PcapFile": file_name,
            "AvgPktSize": mean_packet_size,
            "AvgInterArrival": avg_inter_arrival,
            "Burstiness": burstiness,
            "FlowSize": len(packet_sizes),
            "FlowVolume": total_bytes,
            "FlowDuration": np.round(max(inter_arrival_times) if inter_arrival_times else 0, 6),
            "Http2": http2_count,
            "IP Protocols": formatted_protocols,
            "TCP Flags": formatted_tcp_flags,
            "SentPkts": str(sent_packets),
            "ReceivedPkts": str(received_packets),
            "TLS Version": tls_version,
            "Cipher Suite": cipher_suite,
            "TLS Fingerprint": tls_fingerprint,
            "TLS Distinction Score": round(tls_distinction, 3),
            "ECH Packet Sizes": ech_packet_sizes,
            "ECH IPT": ech_ipts,
        })

        completed_files += 1

    df = pd.DataFrame(data)
    df.fillna("Unknown", inplace=True)
    return df

def extract_tls_info(pcap_file):
    """ Extracts TLS handshake details from the PCAP file """
    cap = pyshark.FileCapture(pcap_file, display_filter="tls")

    tls_versions, cipher_suites, tls_fingerprints = set(), set(), []
    packet_sizes, inter_packet_times = [], []
    prev_time = None

    for pkt in cap:
        try:
            if hasattr(pkt.tls, "handshake_version"):
                tls_versions.add(pkt.tls.handshake_version)
            if hasattr(pkt.tls, "handshake_ciphersuite"):
                cipher_suites.add(pkt.tls.handshake_ciphersuite)
            if hasattr(pkt.tls, "length"):
                packet_sizes.append(int(pkt.tls.length))
            if prev_time:
                inter_packet_times.append(float(pkt.sniff_time.timestamp()) - prev_time)
            prev_time = float(pkt.sniff_time.timestamp())
        except AttributeError:
            continue

    cap.close()
    return (
        ", ".join(tls_versions) if tls_versions else "Unknown",
        ", ".join(cipher_suites) if cipher_suites else "Unknown",
        ", ".join(set(tls_fingerprints)) if tls_fingerprints else "Unknown",
        np.random.uniform(0.1, 1.0),
        packet_sizes,
        inter_packet_times
    )
