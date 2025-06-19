from scapy.all import sniff, IP, TCP, UDP, Raw
from datetime import datetime

def packet_callback(packet):
    log_line = ""

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = ""
        sport = dport = "-"
        payload = ""

        if TCP in packet:
            proto = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
        elif UDP in packet:
            proto = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport
        else:
            proto = "OTHER"

        if Raw in packet:
            try:
                payload = packet[Raw].load.decode(errors="replace")
            except:
                payload = str(packet[Raw].load)

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_line = f"[{timestamp}] {proto} | {src_ip}:{sport} -> {dst_ip}:{dport} | Payload: {payload}\n"

        print(log_line.strip())

        with open("log.txt", "a", encoding="utf-8", errors="replace") as f:
            f.write(log_line)

sniff(filter="ip", prn=packet_callback, store=0, count=10)
