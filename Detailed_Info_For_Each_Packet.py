from scapy.all import sniff, IP, TCP, UDP, Raw

def packet_callback(packet):
    print("\n--- Packet Captured ---")

    if IP in packet:
        print(f"Source IP: {packet[IP].src}")
        print(f"Destination IP: {packet[IP].dst}")
        
        if TCP in packet:
            print("Protocol: TCP")
            print(f"Source Port: {packet[TCP].sport}")
            print(f"Destination Port: {packet[TCP].dport}")
        elif UDP in packet:
            print("Protocol: UDP")
            print(f"Source Port: {packet[UDP].sport}")
            print(f"Destination Port: {packet[UDP].dport}")

        if Raw in packet:
            print(f"Payload: {packet[Raw].load}")

# Capture 10 packets and apply our detailed callback
sniff(count=10, prn=packet_callback)
