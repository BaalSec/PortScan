import socket
import concurrent.futures
from scapy.all import ARP, Ether, srp
from pywifi import PyWiFi, const, Profile
import time

def scan_wifi_networks(interface):
    wifi = PyWiFi()
    iface = wifi.interfaces()[interface]

    iface.scan()
    time.sleep(2)  # wait for scan results

    results = iface.scan_results()
    networks = []
    for network in results:
        networks.append((network.ssid, network.bssid))

    return networks

def get_devices_in_network(network_ip):
    arp_request = ARP(pdst=network_ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]

    devices = []
    for element in answered_list:
        devices.append({'ip': element[1].psrc, 'mac': element[1].hwsrc})

    return devices

def scan_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            return port if result == 0 else None
    except socket.error:
        return None

def scan_ports(ip, port_range=(1, 1024)):
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = [executor.submit(scan_port, ip, port) for port in range(port_range[0], port_range[1] + 1)]
        for future in concurrent.futures.as_completed(futures):
            port = future.result()
            if port is not None:
                open_ports.append(port)
    return open_ports

def main():
    # List all interfaces
    wifi = PyWiFi()
    interfaces = wifi.interfaces()
    
    if not interfaces:
        print("No Wi-Fi interfaces found.")
        return
    
    print("Detected interfaces:")
    for i, iface in enumerate(interfaces):
        print(f"{i}: {iface.name()}")  # List all available interfaces
    
    try:
        interface = int(input("Select the Wi-Fi interface (number): "))
        if interface < 0 or interface >= len(interfaces):
            print(f"Invalid interface selection. Please select a number between 0 and {len(interfaces) - 1}.")
            return
    except ValueError:
        print("Invalid input. Please enter a number.")
        return
    
    networks = scan_wifi_networks(interface)
    if not networks:
        print("No networks found.")
        return
    
    print("Available Wi-Fi networks:")
    for ssid, bssid in networks:
        print(f"SSID: {ssid}, BSSID: {bssid}")
    
    network_ip = input("Enter the IP range to scan (e.g., 192.168.1.0/24): ")
    devices = get_devices_in_network(network_ip)
    
    if not devices:
        print("No devices found in the network.")
        return
    
    print("Devices in the network:")
    for device in devices:
        print(f"IP: {device['ip']}, MAC: {device['mac']}")
    
    for device in devices:
        ip = device['ip']
        print(f"Scanning ports on {ip}...")
        open_ports = scan_ports(ip)
        if open_ports:
            print(f"Open ports on {ip}: {open_ports}")
        else:
            print(f"No open ports found on {ip}")

if __name__ == "__main__":
    main()
