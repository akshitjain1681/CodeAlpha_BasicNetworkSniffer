from scapy.all import *
from datetime import datetime
import socket
from collections import Counter

packet_count = 0
tcp_count = 0
udp_count = 0
icmp_count = 0

destination_ips = Counter()
applications = Counter()


def get_service(port):

    common_ports = {
        20: "FTP Data",
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        123: "NTP",
        143: "IMAP",
        443: "HTTPS",
        3306: "MySQL",
        3389: "RDP",
        8080: "HTTP Proxy"
    }

    return common_ports.get(port, "Unknown")


def resolve_hostname(ip):

    try:
        return socket.gethostbyaddr(ip)[0]

    except:
        return "Unknown"


def show_insights():

    print("\n================ NETWORK INSIGHTS ================")

    print(f"Total Packets Captured : {packet_count}")
    print(f"TCP Packets            : {tcp_count}")
    print(f"UDP Packets            : {udp_count}")
    print(f"ICMP Packets           : {icmp_count}")

    print("\nTop Destination IPs:")

    for ip, count in destination_ips.most_common(5):
        print(f"{ip} -> {count} packets")

    print("\nMost Used Applications:")

    for app, count in applications.most_common(5):
        print(f"{app} -> {count} packets")

    print("==================================================\n")


def process_packet(packet):

    global packet_count
    global tcp_count
    global udp_count
    global icmp_count

    packet_count += 1

    print("\n===================================================")
    print("                 PACKET CAPTURED")
    print("===================================================")

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(f"Time               : {timestamp}")
    print(f"Packet Size        : {len(packet)} bytes")

    if packet.haslayer(IP):

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        destination_ips[dst_ip] += 1

        protocol = packet[IP].proto

        print(f"Source IP          : {src_ip}")
        print(f"Destination IP     : {dst_ip}")

        src_host = resolve_hostname(src_ip)
        dst_host = resolve_hostname(dst_ip)

        print(f"Source Host        : {src_host}")
        print(f"Destination Host   : {dst_host}")

        if protocol == 6:

            protocol_name = "TCP"
            tcp_count += 1

        elif protocol == 17:

            protocol_name = "UDP"
            udp_count += 1

        elif protocol == 1:

            protocol_name = "ICMP"
            icmp_count += 1

        else:

            protocol_name = str(protocol)

        print(f"Protocol           : {protocol_name}")

    app_name = "Unknown"

    if packet.haslayer(TCP):

        sport = packet[TCP].sport
        dport = packet[TCP].dport

        print(f"Source Port        : {sport}")
        print(f"Destination Port   : {dport}")

        app_name = get_service(dport)

        print(f"Application        : {app_name}")

    elif packet.haslayer(UDP):

        sport = packet[UDP].sport
        dport = packet[UDP].dport

        print(f"Source Port        : {sport}")
        print(f"Destination Port   : {dport}")

        app_name = get_service(dport)

        print(f"Application        : {app_name}")

    applications[app_name] += 1

    if packet.haslayer(Raw):

        try:

            payload = packet[Raw].load.decode(errors="ignore")

            print("\nPayload Preview:")
            print(payload[:200])

        except:
            pass

    if len(packet) > 1500:

        print("\n[!] ALERT: Large packet detected")

    if app_name == "Unknown":

        print("\n[!] Warning: Unknown application traffic")

    print("\nPacket Summary:")
    print(packet.summary())

    with open("captured_packets.txt", "a", encoding="utf-8") as file:

        file.write("\n===================================================\n")
        file.write(f"Time: {timestamp}\n")

        if packet.haslayer(IP):

            file.write(f"Source IP: {src_ip}\n")
            file.write(f"Destination IP: {dst_ip}\n")
            file.write(f"Protocol: {protocol_name}\n")

        file.write(packet.summary() + "\n")

    if packet_count % 10 == 0:

        show_insights()


print("\nNetwork Sniffer Started...")
print("Capturing Live Traffic...")
print("Detailed Insights will appear every 10 packets.")
print("Press CTRL + C to stop.\n")

sniff(prn=process_packet, store=False)