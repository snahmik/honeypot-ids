import os
import sys
from datetime import datetime
from scapy.all import sniff
from scapy.layers.dot11 import Dot11, Dot11Auth

# Define path for custom log file
RAW_PATH = "~/ids-record.log"
WIRELESS_LOG = os.path.expanduser(RAW_PATH)

handshakes = {}

def log_event(event_type, client_mac, ap_mac):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] | Event: {event_type} | Client: {client_mac} -> AP: {ap_mac}\n"

    print(f"[!] {event_type} Detected: Client {client_mac} targeting AP {ap_mac}")

    with open(WIRELESS_LOG, "a") as f:
        f.write(log_entry)

#Capture 802.11 frames
def handle_wireless_packet(packet):
    if not packet.haslayer(Dot11):
        return

    #4-way handshake
    if packet.haslayer('EAPOL'):
        try:
            destAddr = packet[Dot11].addr1
            srcAddr = packet[Dot11].addr2

            isFromDs = bool(packet[Dot11].FCfield & 2)

            #if packet has from DS(Distribution System) flag, the dest is client
            if isFromDs:
                client_mac = destAddr
                ap_mac = srcAddr
            else:
                client_mac = srcAddr
                ap_mac = destAddr

            if client_mac not in handshakes:
                handshakes[client_mac] = set()

            packet_count = len(handshakes[client_mac]) + 1
            log_event(f"EAPOL 4-way Handshake {packet_count}/4", client_mac, ap_mac)
            handshakes[client_mac].add(bytes(packet['EAPOL']))
        except Exception as e:
            print(f"[!] {e}")
            pass
    # Authentication frames
    elif packet.haslayer(Dot11Auth):
        client_mac = packet[Dot11].addr2
        ap_mac = packet[Dot11].addr3
        log_event("802.11 Authentication Frame", client_mac, ap_mac)

def main():
    INTERFACE = "mon0"
    print(f"[*] Intrusion Detection System active on {INTERFACE}...")
    print(f"[*] Logging events to {WIRELESS_LOG}")

    try:
        sniff(iface=INTERFACE, prn=handle_wireless_packet, store=0)
    except KeyboardInterrupt:
        print("\n[*] Stopping wireless monitor.")
        sys.exit(0)

if __name__ == "__main__":
    if os.getuid() != 0:
        print("[-] Error: Script must be run with sudo privileges.")
        sys.exit(1)
    main()


