from scapy.all import ARP, Ether, srp

def scan_local_network(ip_range):
    # Craft an ARP request packet to discover devices on the local network
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")  # Broadcast Ethernet frame
    packet = ether/arp

    # Send the packet and capture the response
    result = srp(packet, timeout=3, verbose=0)[0]

    active_hosts = []
    for sent, received in result:
        active_hosts.append({'ip': received.psrc, 'mac': received.hwsrc})

    return active_hosts

if __name__ == "__main__":
    ip_range = "192.168.1.0/24"  # Adjust to match your local network subnet

    print(f"Scanning the local network {ip_range} for active hosts...")
    active_hosts = scan_local_network(ip_range)

    if active_hosts:
        print("Active hosts on the network:")
        for host in active_hosts:
            print(f"IP Address: {host['ip']}, MAC Address: {host['mac']}")
    else:
        print("No active hosts found on the network.")
