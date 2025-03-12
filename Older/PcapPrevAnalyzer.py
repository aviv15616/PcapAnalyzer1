import pyshark
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os
from tkinter import Tk, filedialog, Button, Toplevel
import subprocess
from pandastable import Table, TableModel


class PCAPAnalyzerGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("PCAP Analyzer")
        self.master.geometry("400x300")

        self.pcap_file = None  # קובץ יחיד בלבד
        self.analysis_data = None  # נתוני הניתוח

        # כפתור להעלאת קובץ PCAP
        self.btn_upload_pcap = Button(master, text="📂 הכנס קובץ PCAP", command=self.upload_pcap)
        self.btn_upload_pcap.pack(pady=10)

        # כפתורי מאפיינים (A-F)
        self.feature_buttons = {}
        for feature in ["A - IP Headers", "B - TCP Headers", "C - TLS Headers", "D - Packet Size",
                        "E - Inter-Arrival Time", "F - Flow Size"]:
            btn = Button(master, text=feature, command=lambda f=feature: self.analyze_feature(f), state="disabled")
            btn.pack(pady=5)
            self.feature_buttons[feature] = btn

        # כפתור צפייה ב-Excel
        self.btn_excel = Button(master, text="📊 צפה ב-Excel", command=self.view_excel, state="disabled")
        self.btn_excel.pack(pady=10)

        # כפתור יציאה
        self.btn_exit = Button(master, text="🚪 יציאה", command=master.quit)
        self.btn_exit.pack(pady=20)

    def upload_pcap(self):
        if self.pcap_file:
            return  # ניתן להעלות רק קובץ אחד

        pcap_path = filedialog.askopenfilename(title="בחר קובץ PCAP", filetypes=[("PCAP Files", "*.pcap")])
        if pcap_path:
            self.pcap_file = pcap_path
            self.process_pcap(pcap_path)
            self.btn_upload_pcap.config(text="📡 קובץ נטען", state="disabled")

            # הפעלת כפתורי המאפיינים
            for btn in self.feature_buttons.values():
                btn.config(state="normal")

            # הפעלת כפתור Excel
            self.btn_excel.config(state="normal")

    def process_pcap(self, pcap_path):
        cap = pyshark.FileCapture(pcap_path)
        prev_timestamps = {}
        flow_counts = {}

        # יצירת DataFrame
        df = pd.DataFrame(
            columns=['Timestamp', 'Source_IP', 'Destination_IP', 'Protocol', 'Packet_Size', 'TCP_Window_Size',
                     'TCP_Flags', 'TLS_Handshake_Type', 'Inter_Arrival_Time', 'Flow_ID', 'Flow_Size'])
        packet_data = []

        for packet in cap:
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

                # הוספת הנתונים לרשימה
                packet_data.append({
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
                })

            except AttributeError:
                continue

        # הכנסת הנתונים ל-DataFrame
        if packet_data:
            df = pd.concat([df, pd.DataFrame(packet_data)], ignore_index=True)

        self.analysis_data = df
        df.to_csv("pcap_analysis.csv", index=False)

    def analyze_feature(self, feature):
        if self.analysis_data is None:
            return

        df = self.analysis_data
        plt.figure(figsize=(10, 5))
        sns.histplot(df['Packet_Size'], bins=30, kde=True)
        plt.xlabel(feature)
        plt.title(f"ניתוח {feature}")
        plt.show()

    def view_excel(self):
        if self.analysis_data is not None and not self.analysis_data.empty:
            self.show_dataframe_window()
        else:
            print("⚠️ DataFrame ריק – אין נתונים להצגה.")

    def show_dataframe_window(self):
        """ מציג את ה-DataFrame בחלון חדש עם המאפיינים A-F """
        df_window = Toplevel(self.master)
        df_window.title("PCAP DataFrame Viewer")
        df_window.geometry("1000x500")

        frame = Table(df_window, dataframe=self.analysis_data, showtoolbar=True, showstatusbar=True)
        frame.show()

        df_window.mainloop()


# יצירת GUI
root = Tk()
app = PCAPAnalyzerGUI(root)
root.mainloop()
