import tkinter as tk
from tkinter import scrolledtext
from scapy.all import sniff, IP, TCP, UDP
from threading import Thread
from collections import defaultdict

# Initialize packet and protocol statistics
packet_count = 0
protocol_count = defaultdict(int)
suspicious_activity_count = 0

# List of known malicious IPs (for demonstration)
malicious_ips = ["192.168.1.5", "192.168.1.10"]

# Function to process each packet
def process_packet(packet):
    global packet_count, suspicious_activity_count

    if IP in packet:
        packet_count += 1
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = "Unknown"
        src_port = "N/A"
        dst_port = "N/A"

        if TCP in packet:
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        protocol_count[protocol] += 1

        # Detect suspicious activity
        if TCP in packet and packet[TCP].flags == "S":
            suspicious_activity_count += 1
            add_alert(f"Possible SYN Scan Detected from {ip_src} to {ip_dst}")
        
        if ip_src in malicious_ips or ip_dst in malicious_ips:
            suspicious_activity_count += 1
            add_alert(f"Communication with malicious IP: {ip_src if ip_src in malicious_ips else ip_dst}")

        # Add packet details to the display
        packet_info = (f"Packet #{packet_count}\n"
                       f"Source IP: {ip_src} | Destination IP: {ip_dst}\n"
                       f"Protocol: {protocol} | Source Port: {src_port} | Destination Port: {dst_port}\n"
                       f"Packet Size: {len(packet)} bytes\n"
                       "="*50)
        add_packet_info(packet_info)

# Function to display packet information in GUI
def add_packet_info(packet_info):
    output_text.config(state=tk.NORMAL)
    output_text.insert(tk.END, packet_info + "\n")
    output_text.see(tk.END)
    output_text.config(state=tk.DISABLED)

# Function to display real-time alerts in GUI
def add_alert(alert_message):
    alert_text.config(state=tk.NORMAL)
    alert_text.insert(tk.END, f"[ALERT] {alert_message}\n")
    alert_text.see(tk.END)
    alert_text.config(state=tk.DISABLED)

# Function to start packet sniffing
def start_sniffer():
    sniff(filter="ip", prn=process_packet, store=False)

# Function to run sniffer in a separate thread
def run_sniffer():
    sniffer_thread = Thread(target=start_sniffer)
    sniffer_thread.daemon = True
    sniffer_thread.start()

# GUI setup
root = tk.Tk()
root.title("Advanced Packet Sniffer")

# Packet Info Display
output_frame = tk.Frame(root)
output_frame.pack(padx=10, pady=5)

output_label = tk.Label(output_frame, text="Packet Details", font=("Arial", 12, "bold"))
output_label.pack(anchor="w")

output_text = scrolledtext.ScrolledText(output_frame, height=15, width=80, state=tk.DISABLED)
output_text.pack()

# Alert Display
alert_frame = tk.Frame(root)
alert_frame.pack(padx=10, pady=5)

alert_label = tk.Label(alert_frame, text="Real-Time Alerts", font=("Arial", 12, "bold"), fg="red")
alert_label.pack(anchor="w")

alert_text = scrolledtext.ScrolledText(alert_frame, height=8, width=80, state=tk.DISABLED, fg="red")
alert_text.pack()

# Start button
start_button = tk.Button(root, text="Start Sniffer", font=("Arial", 12), command=run_sniffer)
start_button.pack(pady=10)

# Run the GUI
root.mainloop()
