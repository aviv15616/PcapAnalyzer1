import tkinter as tk
from tkinter import filedialog, messagebox
import pyshark


def extract_snis_from_pcap(pcap_file):
    snis = set()
    try:
        print(f"Processing PCAP file: {pcap_file}")  # Debugging output
        cap = pyshark.FileCapture(pcap_file, display_filter="tls.handshake")

        for packet in cap:
            try:
                if hasattr(packet, 'tls') and hasattr(packet.tls, 'handshake_extensions_server_name'):
                    sni = packet.tls.handshake_extensions_server_name
                    snis.add(sni)
                    print(f"Found SNI: {sni}")  # Debugging output
            except AttributeError as e:
                print(f"Skipping packet due to error: {e}")  # Debugging output
                continue
        cap.close()
    except Exception as e:
        messagebox.showerror("Error", f"Failed to process PCAP: {e}")
        print(f"Error processing PCAP: {e}")  # Debugging output
    return snis


def browse_pcap():
    file_path = filedialog.askopenfilename(title="Select a PCAP file", filetypes=[("PCAP files", "*.pcap;*.pcapng")])
    if file_path:
        snis = extract_snis_from_pcap(file_path)
        if snis:
            sni_list = "\n".join(snis)
            messagebox.showinfo("SNI List", sni_list)
            print("Extracted SNIs:")  # Debugging output
            print(sni_list)  # Debugging output
        else:
            messagebox.showinfo("SNI List", "No SNI found in the PCAP file.")
            print("No SNI found in the PCAP file.")  # Debugging output


# GUI setup
root = tk.Tk()
root.withdraw()  # Hide the main window
browse_pcap()