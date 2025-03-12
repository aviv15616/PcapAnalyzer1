import pandas as pd
import pyshark
# יצירת DataFrame ריק לבדיקה
df_test = pd.DataFrame(columns=['Timestamp', 'Source_IP', 'Destination_IP', 'Protocol',
                                'Packet_Size', 'TCP_Window_Size', 'TCP_Flags',
                                'TLS_Handshake_Type', 'Inter_Arrival_Time', 'Flow_ID', 'Flow_Size'])

# מילוי ה-DataFrame עם הנתונים הראשונים מה-PCAP
cap = pyshark.FileCapture(pcap_path)
prev_timestamps = {}
flow_counts = {}

for i, packet in enumerate(cap):
    try:
        timestamp = packet.sniff_time.timestamp()
        src_ip = packet.ip.src if hasattr(packet, 'ip') else "Unknown"
        dst_ip = packet.ip.dst if hasattr(packet, 'ip') else "Unknown"
        protocol = packet.transport_layer if hasattr(packet, 'transport_layer') else "Unknown"
        packet_size = int(packet.length)
        tcp_window_size = packet.tcp.window_size if hasattr(packet, 'tcp') else None
        tcp_flags = packet.tcp.flags if hasattr(packet, 'tcp') else None
        tls_handshake = packet.tls.handshake_type if hasattr(packet, 'tls') else None

        # חישוב Inter-Arrival Time
        flow_id = f"{src_ip} -> {dst_ip}"
        inter_arrival_time = None
        if flow_id in prev_timestamps:
            inter_arrival_time = timestamp - prev_timestamps[flow_id]
        prev_timestamps[flow_id] = timestamp

        # חישוב Flow Size
        flow_counts[flow_id] = flow_counts.get(flow_id, 0) + 1

        # הוספת הנתונים לטבלה
        df_test = df_test.append({
            'Timestamp': timestamp,
            'Source_IP': src_ip,
            'Destination_IP': dst_ip,
            'Protocol': protocol,
            'Packet_Size': packet_size,
            'TCP_Window_Size': tcp_window_size,
            'TCP_Flags': tcp_flags,
            'TLS_Handshake_Type': tls_handshake,
            'Inter_Arrival_Time': inter_arrival_time,
            'Flow_ID': flow_id,
            'Flow_Size': flow_counts[flow_id]
        }, ignore_index=True)

        if i == 9:  # הצגת 10 חבילות ראשונות בלבד
            break

    except AttributeError as e:
        print(f"⚠️ שגיאה בקריאת חבילה {i+1}: {e}")
        continue

# הצגת הנתונים בצורה ברורה
import ace_tools as tools
tools.display_dataframe_to_user(name="PCAP DataFrame Test", dataframe=df_test)
