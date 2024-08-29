from scapy.all import sniff, IP, TCP, UDP, ICMP
def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_layer = packet[IP]
        print(f"\nSource IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        
        # Determine the protocol used
        if TCP in packet:
            protocol = "TCP"
        elif UDP in packet:
            protocol = "UDP"
        elif ICMP in packet:
            protocol = "ICMP"
        else:
            protocol = "Other"
        
        print(f"Protocol: {protocol}")
        
        # Display the payload data (if any)
        payload = bytes(packet[IP].payload)
        if payload:
            print(f"Payload: {payload}")
        else:
            print("No Payload Data")
def start_sniffing():
    print("Starting packet capture... Press Ctrl+C to stop.")
    sniff(prn=packet_callback)

if __name__ == "__main__":
    start_sniffing()

# from scapy.all import sniff, IP, TCP, UDP, ARP

# def packet_callback(packet):
#     if packet.haslayer(IP):
#         ip_layer = packet.getlayer(IP)
#         print(f"Source IP: {ip_layer.src}")
#         print(f"Destination IP: {ip_layer.dst}")
        
#         if packet.haslayer(TCP):
#             print("Protocol: TCP")
#             tcp_layer = packet.getlayer(TCP)
#             print(f"Source Port: {tcp_layer.sport}")
#             print(f"Destination Port: {tcp_layer.dport}")
#             print(f"Payload: {str(tcp_layer.payload)}")
        
#         elif packet.haslayer(UDP):
#             print("Protocol: UDP")
#             udp_layer = packet.getlayer(UDP)
#             print(f"Source Port: {udp_layer.sport}")
#             print(f"Destination Port: {udp_layer.dport}")
#             print(f"Payload: {str(udp_layer.payload)}")
        
#         print("\n---\n")
    
#     elif packet.haslayer(ARP):
#         arp_layer = packet.getlayer(ARP)
#         print(f"ARP Request from {arp_layer.psrc} to {arp_layer.pdst}")
#         print("\n---\n")

# def start_sniffing(interface=None):
#     print(f"[*] Starting packet sniffing on {interface}")
#     sniff(iface=interface, prn=packet_callback)

# if __name__ == "__main__":
#     interface = input("Enter the interface to sniff on (leave empty for default): ")
#     start_sniffing(interface if interface else None)

# from scapy.all import get_if_list

# print("Available interfaces:")
# for iface in get_if_list():
#     print(f" - {iface}")
