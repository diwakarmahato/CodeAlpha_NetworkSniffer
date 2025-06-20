from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto

        print(f"[+] {ip_src} -> {ip_dst} | Protocol: {proto}")

        if packet.haslayer(TCP):
            print("Payload:", bytes(packet[TCP].payload))
        elif packet.haslayer(UDP):
            print("Payload:", bytes(packet[UDP].payload))

print("Sniffing packets... (Press Ctrl+C to stop)")
sniff(prn=packet_callback, store=False, count=20)
