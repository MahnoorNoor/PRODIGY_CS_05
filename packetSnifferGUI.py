
import tkinter as tk
from tkinter import scrolledtext
from scapy.all import sniff, IP, TCP, UDP, ICMP
import threading

def packet_callback(packet, text_area):
    if IP in packet:
        ip_layer = packet[IP]
        source_ip = ip_layer.src
        destination_ip = ip_layer.dst
        
        if TCP in packet:
            protocol = "TCP"
        elif UDP in packet:
            protocol = "UDP"
        elif ICMP in packet:
            protocol = "ICMP"
        else:
            protocol = "Other"
        
        payload = bytes(packet[IP].payload)
        payload_data = payload if payload else b"No Payload Data"
        
        # Update the text area in the GUI with the captured packet details
        text_area.insert(tk.END, f"Source IP: {source_ip}\n")
        text_area.insert(tk.END, f"Destination IP: {destination_ip}\n")
        text_area.insert(tk.END, f"Protocol: {protocol}\n")
        text_area.insert(tk.END, f"Payload: {payload_data}\n\n")
        text_area.see(tk.END)  # Scroll to the end of the text area

class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Sniffer")
        
        # Create the GUI layout
        self.start_button = tk.Button(root, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.pack(pady=10)

        self.stop_button = tk.Button(root, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.pack(pady=10)
        
        self.text_area = scrolledtext.ScrolledText(root, width=80, height=20)
        self.text_area.pack(padx=10, pady=10)
        
        self.sniffing = False
        self.sniffer_thread = None
    
    def start_sniffing(self):
        self.sniffing = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.sniffer_thread = threading.Thread(target=self.sniff_packets)
        self.sniffer_thread.start()
    
    def stop_sniffing(self):
        self.sniffing = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        if self.sniffer_thread is not None:
            self.sniffer_thread.join()
    
    def sniff_packets(self):
        sniff(prn=lambda packet: packet_callback(packet, self.text_area), stop_filter=lambda x: not self.sniffing)

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()


