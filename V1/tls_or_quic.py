from scapy.all import rdpcap, IP, UDP, TCP, Raw

def detect_tls_quic(pcap_file):
    packets = rdpcap(pcap_file)

    quic_count = 0
    tls_count = 0
    quic_fallback = 0  # Detects QUIC-to-TLS fallback
    session_ips = set()  # Stores session pairs to differentiate traffic types

    for pkt in packets:
        if pkt.haslayer(IP):
            src_dst_pair = (pkt[IP].src, pkt[IP].dst)  # Track unique sessions

            # Detect QUIC (UDP 443)
            if pkt.haslayer(UDP) and pkt[UDP].dport == 443:
                if pkt.haslayer(Raw) and (b"Initial" in bytes(pkt[Raw]) or b"QUIC" in bytes(pkt[Raw])):
                    quic_count += 1
                    session_ips.add(src_dst_pair)

            # Detect TLS (TCP 443)
            elif pkt.haslayer(TCP) and pkt[TCP].dport == 443:
                if pkt.haslayer(Raw) and b"ClientHello" in bytes(pkt[Raw]):
                    tls_count += 1
                    if src_dst_pair in session_ips:  # If same connection as QUIC
                        quic_fallback += 1

    # Classify the PCAP session
    if quic_count > 0 and tls_count > 0:
        return "Mixed QUIC & TLS"  # Different connections using different protocols
    elif quic_count > 0 and tls_count == 0:
        return "QUIC"
    elif tls_count > 0 and quic_count == 0:
        return "TLS"
    elif quic_fallback > 0:
        return "QUIC-to-TLS Fallback"
    else:
        return "Unknown Protocol"

# Example usage

