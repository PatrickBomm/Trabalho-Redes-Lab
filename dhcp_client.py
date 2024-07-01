import socket
import struct
import random

# DHCP Constants
DHCP_DISCOVER = 1
DHCP_REQUEST = 3
DHCP_MAGIC_COOKIE = b'\x63\x82\x53\x63'

# Helper functions
def get_random_mac():
    return [random.randint(0x00, 0xff) for _ in range(6)]

def get_mac_addr(mac_bytes):
    return ':'.join(format(b, '02x') for b in mac_bytes)

def create_dhcp_discover(mac_addr, ip_for_spoof):
    # Ethernet frame
    ether_frame = struct.pack('!6s6sH', b'\xff'*6, mac_addr, 0x0800)

    # IP header
    src_ip = socket.inet_aton('0.0.0.0')  # 0.0.0.0 for DHCPDISCOVER
    dst_ip = socket.inet_aton(ip_for_spoof)
    ip_header = struct.pack('!BBHHHBBH4s4s',
                            0x45, 0x10, 0x0138, 0, 0, 64, 17, 0, src_ip, dst_ip)

    # UDP header
    udp_header = struct.pack('!HHHH', 68, 67, 0x0138, 0)

    # DHCP header
    transaction_id = random.randint(0, 0xFFFFFFFF)
    dhcp_header = struct.pack('!4B4I16s192s4s',
                              DHCP_DISCOVER, 1, 6, 0, transaction_id,
                              0, 0, 0, mac_addr, b'\x00'*192, DHCP_MAGIC_COOKIE)

    # DHCP options
    dhcp_options = struct.pack('!3B', 53, 1, DHCP_DISCOVER) + struct.pack('!B', 255)

    # Combine all parts
    packet = ether_frame + ip_header + udp_header + dhcp_header + dhcp_options
    return packet, transaction_id

def create_dhcp_request(mac_addr, offered_ip, server_ip, transaction_id):
    # Convert bytes to string for socket.inet_aton
    server_ip_str = socket.inet_ntoa(server_ip)
    offered_ip_str = socket.inet_ntoa(offered_ip)

    # Ethernet frame
    ether_frame = struct.pack('!6s6sH', b'\xff'*6, mac_addr, 0x0800)

    # IP header
    src_ip = socket.inet_aton('0.0.0.0')  # 0.0.0.0 for DHCPREQUEST
    dst_ip = socket.inet_aton(server_ip_str)
    ip_header = struct.pack('!BBHHHBBH4s4s',
                            0x45, 0x10, 0x0138, 0, 0, 64, 17, 0, src_ip, dst_ip)

    # UDP header
    udp_header = struct.pack('!HHHH', 68, 67, 0x0138, 0)

    # DHCP header
    dhcp_header = struct.pack('!4B4I16s192s4s',
                              DHCP_REQUEST, 1, 6, 0, transaction_id,
                              0, 0, 0, mac_addr, b'\x00'*192, DHCP_MAGIC_COOKIE)

    # DHCP options
    dhcp_options = (
        struct.pack('!3B', 53, 1, DHCP_REQUEST) +
        struct.pack('!2B4s', 50, 4, socket.inet_aton(offered_ip_str)) +    # Requested IP
        struct.pack('!2B4s', 54, 4, socket.inet_aton(server_ip_str)) +     # DHCP Server Identifier
        struct.pack('!B', 255)
    )

    # Combine all parts
    packet = ether_frame + ip_header + udp_header + dhcp_header + dhcp_options
    return packet

def send_dhcp_discover_and_request(sock, interface_name, ip_for_spoof, mac_addr):
    discover_packet, transaction_id = create_dhcp_discover(mac_addr, ip_for_spoof)
    sock.send(discover_packet)
    print(f"DHCP DISCOVER sent to {ip_for_spoof} from MAC {get_mac_addr(mac_addr)}")

    # Simulando a resposta do servidor DHCP
    offered_ip = socket.inet_aton(ip_for_spoof)
    server_ip = socket.inet_aton(ip_for_spoof)
    
    request_packet = create_dhcp_request(mac_addr, offered_ip, server_ip, transaction_id)
    sock.send(request_packet)
    print(f"DHCP REQUEST sent to {ip_for_spoof} from MAC {get_mac_addr(mac_addr)}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: sudo python3 dhcp_client.py <interface_name> <ip_for_spoof>")
        sys.exit(1)

    interface_name = sys.argv[1]
    ip_for_spoof = sys.argv[2]

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    sock.bind((interface_name, 0))

    mac_addr = struct.pack('!6B', *get_random_mac())

    send_dhcp_discover_and_request(sock, interface_name, ip_for_spoof, mac_addr)
