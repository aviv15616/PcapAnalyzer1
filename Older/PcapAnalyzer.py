import pyshark
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from tkinter import Tk, filedialog, Button, messagebox, simpledialog, Toplevel, ttk



class PCAPAnalyzerGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("PCAP Analyzer")
        self.master.geometry("400x300")

        self.pcap_file = None
        self.analysis_data = None
        self.target_domain = None  # User-entered domain name

        self.btn_upload_pcap = Button(master, text="📂 Upload PCAP", command=self.upload_pcap)
        self.btn_upload_pcap.pack(pady=10)

        self.btn_graphs = Button(master, text="📊 View Graphs", command=self.analyze_feature, state="disabled")
        self.btn_graphs.pack(pady=10)

        self.btn_excel = Button(master, text="📋 View DataFrame", command=self.view_excel, state="disabled")
        self.btn_excel.pack(pady=10)

    def upload_pcap(self):
        """ Upload PCAP file and analyze based on user-input domain """
        pcap_path = filedialog.askopenfilename(title="Select PCAP File", filetypes=[("PCAP Files", "*.pcap")])
        if pcap_path:
            self.pcap_file = pcap_path
            self.target_domain = simpledialog.askstring("Input", "Enter domain.TLD (e.g., example.com):")

            if not self.target_domain:
                messagebox.showerror("Error", "No domain entered! Please provide a valid domain.")
                return

            self.process_pcap(pcap_path)

            if self.analysis_data is not None:
                self.btn_graphs.config(state="normal")
                self.btn_excel.config(state="normal")
            else:
                messagebox.showerror("Error", "No relevant packets found! Please check your domain and try again.")

    from tkinter import messagebox, simpledialog
    import pyshark
    import pandas as pd

    from tkinter import messagebox, simpledialog
    import pyshark
    import pandas as pd

    def process_pcap(self, pcap_path):
        """ Process PCAP file: Detect browser session, ask for domain name ONCE, filter by first Client Hello with SNI """

        # **Step 1: Detect Browsing Session (First Website Visited)**
        cap = pyshark.FileCapture(pcap_path)
        detected_session = None

        for packet in cap:
            try:
                http_host = packet.http.host if hasattr(packet, 'http') else None
                tls_sni = packet.tls.handshake_extensions_server_name if hasattr(packet, 'tls') else None
                dns_query = packet.dns.qry_name if hasattr(packet, 'dns') else None

                if http_host or tls_sni or dns_query:
                    detected_session = {
                        'host': http_host or tls_sni or dns_query
                    }
                    self.browser_session = detected_session['host']
                    print(f"🌐 **Detected browser session:** {detected_session['host']}")
                    break  # Stop at the first detected browsing session

            except AttributeError:
                continue

        cap.close()

        # **Step 2: If no browsing session is detected, show an error**
        if detected_session is None:
            messagebox.showerror("Error", "No valid browser session detected in this PCAP!")
            return

        # ✅ **Ensure domain is asked only ONCE**
        if not hasattr(self, 'target_domain') or not self.target_domain:
            self.target_domain = simpledialog.askstring("Enter Domain", "Enter domain.TLD (e.g., example.com): ")

        if not self.target_domain:
            messagebox.showerror("Error", "No domain entered!")
            return

        # **Step 3: Find the First TLS Client Hello with SNI Matching User's Input**
        cap = pyshark.FileCapture(pcap_path, display_filter="tls.handshake.type == 1")
        df = pd.DataFrame(columns=[
            'Timestamp', 'Source_IP', 'Destination_IP', 'Protocol', 'Packet_Size',
            'TLS_SNI', 'Port', 'Inter_Arrival_Time', 'Flow_ID', 'Flow_Size'
        ])

        prev_timestamps = {}
        flow_counts = {}
        session_packets = []
        tcp_stream = None

        # **Search for the first Client Hello containing the user-entered domain**
        for packet in cap:
            try:
                if hasattr(packet, 'tls') and hasattr(packet.tls, 'handshake_extensions_server_name'):
                    sni = packet.tls.handshake_extensions_server_name
                    if self.target_domain in sni:
                        tcp_stream = int(packet.tcp.stream)
                        print(f"🌐 Found Client Hello for {sni} (TCP Stream {tcp_stream})")
                        break
            except AttributeError:
                continue
        cap.close()

        if tcp_stream is None:
            messagebox.showerror("Error", "No matching Client Hello found for the domain!")
            return

        # **Step 4: Filter packets based on detected TCP stream**
        cap_filtered = pyshark.FileCapture(pcap_path, display_filter=f"tcp.stream == {tcp_stream}")

        for packet in cap_filtered:
            try:
                timestamp = packet.sniff_time.timestamp()
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
                protocol = packet.transport_layer
                packet_size = int(packet.length)
                port = packet[protocol].dstport if protocol in ['TCP', 'UDP'] else None
                flow_id = f"{src_ip} -> {dst_ip}"

                # Compute inter-arrival time
                inter_arrival_time = None
                if flow_id in prev_timestamps:
                    inter_arrival_time = timestamp - prev_timestamps[flow_id]
                prev_timestamps[flow_id] = timestamp

                # Compute flow size
                flow_counts[flow_id] = flow_counts.get(flow_id, 0) + 1

                packet_data = {
                    'Timestamp': timestamp,
                    'Source_IP': src_ip,
                    'Destination_IP': dst_ip,
                    'Protocol': protocol,
                    'Packet_Size': packet_size,
                    'TLS_SNI': self.target_domain,  # Use manually entered domain
                    'Port': port,
                    'Inter_Arrival_Time': inter_arrival_time,
                    'Flow_ID': flow_id,
                    'Flow_Size': flow_counts[flow_id]
                }

                session_packets.append(packet_data)
            except AttributeError:
                continue
        cap_filtered.close()

        if session_packets:
            self.analysis_data = pd.DataFrame(session_packets)
            self.analysis_data.to_csv("filtered_pcap_analysis.csv", index=False)
            print("📄 Filtered packets saved successfully.")
        else:
            self.analysis_data = None
            messagebox.showerror("Error", "No packets found in the selected stream!")

    def analyze_feature(self):
        """ Generate graphs for relevant packets """
        if self.analysis_data is None:
            messagebox.showerror("Error", "No data available! Upload a valid PCAP file.")
            return

        df = self.analysis_data
        plt.figure(figsize=(10, 5))
        sns.histplot(df['Packet_Size'], bins=30, kde=True)
        plt.xlabel("Packet Size")
        plt.title(f"Packet Size Distribution - {self.target_domain}")
        plt.show()


    def view_excel(self):
        """ Display DataFrame in a new Tkinter window as a table """
        if self.analysis_data is None or self.analysis_data.empty:
            messagebox.showerror("Error", "No valid data available to display.")
            return

        # Create a new top-level window
        df_window = Toplevel(self.master)
        df_window.title("PCAP Data Table")
        df_window.geometry("1000x500")

        # Create a Treeview widget for the table
        tree = ttk.Treeview(df_window)
        tree["columns"] = list(self.analysis_data.columns)
        tree["show"] = "headings"  # Hide first empty column

        # Set up column headers
        for col in self.analysis_data.columns:
            tree.heading(col, text=col)
            tree.column(col, width=100, anchor="center")

        # Insert data into the table
        for _, row in self.analysis_data.iterrows():
            tree.insert("", "end", values=list(row))

        # Pack the Treeview widget
        tree.pack(expand=True, fill="both")

        # Scrollbars for the table
        scrollbar_y = ttk.Scrollbar(df_window, orient="vertical", command=tree.yview)
        scrollbar_y.pack(side="right", fill="y")
        tree.configure(yscrollcommand=scrollbar_y.set)

        scrollbar_x = ttk.Scrollbar(df_window, orient="horizontal", command=tree.xview)
        scrollbar_x.pack(side="bottom", fill="x")
        tree.configure(xscrollcommand=scrollbar_x.set)

        # Keep the window open
        df_window.mainloop()


# Run the GUI
root = Tk()
app = PCAPAnalyzerGUI(root)
root.mainloop()
