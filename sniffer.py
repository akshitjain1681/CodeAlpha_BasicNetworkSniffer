from scapy.all import *
from datetime import datetime

def process_packet(packet):

    print("\n==============================")
    print("PACKET CAPTURED")
    print("==============================")

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"Time: {timestamp}")

    if packet.haslayer(IP):

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

        print(f"Source IP      : {src_ip}")
        print(f"Destination IP : {dst_ip}")
        print(f"Protocol Number: {protocol}")

        if protocol == 6:
            print("Protocol        : TCP")

        elif protocol == 17:
            print("Protocol        : UDP")

        elif protocol == 1:
            print("Protocol        : ICMP")

    if packet.haslayer(TCP):

        print(f"Source Port    : {packet[TCP].sport}")
        print(f"Destination Port: {packet[TCP].dport}")

    if packet.haslayer(Raw):

        print("\nPayload Data:")
        print(packet[Raw].load)

    print("\nPacket Summary:")
    print(packet.summary())

    with open("captured_packets.txt", "a") as file:

        file.write("\n==============================\n")
        file.write(f"Time: {timestamp}\n")

        if packet.haslayer(IP):
            file.write(f"Source IP: {src_ip}\n")
            file.write(f"Destination IP: {dst_ip}\n")
            file.write(f"Protocol: {protocol}\n")

        file.write(packet.summary() + "\n")

print("\n[*] Starting Network Sniffer...")
print("[*] Press CTRL + C to stop.\n")

sniff(prn=process_packet, store=False)