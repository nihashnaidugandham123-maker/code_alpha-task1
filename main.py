from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw
from scapy.all import sniff
from collections import Counter
import csv

# Initialize a packet counter
packet_counts = Counter()


def process_packet(packet):
    """Callback function to handle packet processing."""
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        packet_counts[protocol] += 1

        if TCP in packet:
            tcp_sport = packet[TCP].sport
            tcp_dport = packet[TCP].dport
            print(f"IP: {ip_src} -> {ip_dst} | TCP: {tcp_sport} -> {tcp_dport}")

            # Print payload if exists
            if Raw in packet:
                payload = packet[Raw].load
                print(f"  Payload: {payload[:100]}")

        elif UDP in packet:
            udp_sport = packet[UDP].sport
            udp_dport = packet[UDP].dport
            print(f"IP: {ip_src} -> {ip_dst} | UDP: {udp_sport} -> {udp_dport}")

        else:
            print(f"IP Packet: {ip_src} -> {ip_dst} | Protocol: {protocol}")

        print(f"Packet Counts: {packet_counts}")


def capture_from_network():
    """Capture packets from the network and process them."""
    sniff(prn=process_packet, store=0)


def save_packets_to_file(filename='captured_packets.csv'):
    """Capture packets and save information to a CSV file."""
    with open(filename, 'w') as file:
        writer = csv.writer(file)
        writer.writerow(['Source IP', 'Destination IP', 'Protocol', 'Source Port', 'Destination Port'])

        def process_and_record_packet(packet):
            """Process packet and record its information."""
            if IP in packet:
                ip_src = packet[IP].src
                ip_dst = packet[IP].dst
                protocol = packet[IP].proto
                row = [ip_src, ip_dst, protocol, '', '']

                if TCP in packet:
                    row[3] = packet[TCP].sport
                    row[4] = packet[TCP].dport
                elif UDP in packet:
                    row[3] = packet[UDP].sport
                    row[4] = packet[UDP].dport

                writer.writerow(row)
                print(f"Captured Packet: {row}")

        sniff(prn=process_and_record_packet, store=0)


# Choose one of the following based on the desired functionality
capture_from_network()
# or
save_packets_to_file()
