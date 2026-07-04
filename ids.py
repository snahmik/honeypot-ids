import os
import sys
from datetime import datetime
from scapy.all import sniff
from scapy.layers.dot11 import Dot11, Dot11Auth, RadioTap

# Define path for custom log file
RAW_PATH = "~/ids-record.log"
WIRELESS_LOG = os.path.expanduser(RAW_PATH)

handshakes = {}


def log_event(event_type, client_mac, ap_mac, rssi):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    rssi_str = f"{rssi} dBm" if rssi is not None else "N/A"

    log_entry = f"[{timestamp}] | Event: {event_type} | Client: {client_mac} -> AP: {ap_mac} | Strength: {rssi_str}\n"

    print(f"[!] {event_type} Detected: Client {client_mac} -> AP {ap_mac} ({rssi_str})")

    with open(WIRELESS_LOG, "a") as f:
        f.write(log_entry)


def handle_wireless_packet(packet):
    if not packet.haslayer(Dot11):
        return

    rssi = None
    if packet.haslayer(RadioTap):
        rssi = packet[RadioTap].dBm_AntSignal

    # 1. 4-way handshake
    if packet.haslayer('EAPOL'):
        try:
            destAddr = packet[Dot11].addr1
            srcAddr = packet[Dot11].addr2

            isFromDs = bool(packet[Dot11].FCfield & 2)

            if isFromDs:
                clientMac = destAddr
                apMac = srcAddr
            else:
                clientMac = srcAddr
                apMac = destAddr

            if clientMac not in handshakes:
                handshakes[clientMac] = set()

            rawEapol = bytes(packet['EAPOL'])
            if rawEapol not in handshakes[clientMac]:
                handshakes[clientMac].add(rawEapol)
                packet_count = len(handshakes[clientMac])
                log_event(f"EAPOL 4-way Handshake {packet_count}/4", clientMac, apMac, rssi)
        except Exception as e:
            print(f"[!] Error processing EAPOL: {e}")
            pass

    # 2. Authentication frames
    elif packet.haslayer(Dot11Auth):
        clientMac = packet[Dot11].addr2
        apMac = packet[Dot11].addr3
        log_event("802.11 Authentication Frame", clientMac, apMac, rssi)

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