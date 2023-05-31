import socket
from socket import *
import sys
from scapy.all import *
import argparse
from scapy.layers.dns import DNS, DNSQR, UDP, IP

class DNSProxy:
    def __init__(self, remote_dns_ip, default_mappings):
        self.remote_dns_ip = remote_dns_ip
        self.default_mappings = default_mappings or {}
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_socket.bind(('', 53))

    def handle_dns_query(self, client_query):
        dns_query = IP(dst=remote_dns_ip) / UDP(sport=RandShort(), dport=53) / client_query[DNS]
        # IP(dst=remote_dns_ip): establece la dirección de destino (dst) del paquete como la dirección IP del servidor DNS remoto.
        #UDP(sport=RandShort(), dport=53):se establece el puerto de origen aleatoriamente.
        #client_query[DNS]:accede al campo DNS, viendo los registros

        if client_query[DNSQR].qname.decode() in default_mappings: #si esta mapeada la query se genera la respuesta predeterminada
            dns_response = IP() / UDP() / DNS(rd=1, id=client_query[DNS].id, qr=1, qdcount=1, ancount=1, qd=DNSQR(qname=client_query[DNSQR].qname), an=DNSRR(rrname=client_query[DNSQR].qname, ttl=10, rdata=default_mappings[client_query[DNSQR].qname]))
        else:
            dns_response = sr1(dns_query, verbose=0) #envía la consulta al servidor DNS remoto y espera la respuesta.
        
        self.server_socket.sendto(bytes(dns_response), self.client_address)

    def start_dns_proxy(self):

        print("DNS Proxy server is running...")

        while True:
            data, address = self.server_socket.recvfrom(4096)
            client_query = IP(data)
            client_address = address
            socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            self.handle_dns_query(client_query, remote_dns_ip, default_mappings)

def parse_arguments():
    parser = argparse.ArgumentParser(description="DNS Proxy Server")
    parser.add_argument('-s', '--remote-dns', help='Remote DNS server IP', required=True)
    parser.add_argument('-d', '--default-mapping', nargs="+", action='append', metavar=('domain', 'ip'), help='Default domain-to-IP mappings')
    return parser.parse_args()
    
if __name__ == "_main_":
    args = parse_arguments() #obtengo arg x linea de comando
    remote_dns_ip = args.remote_dns #Se extrae la dirección IP del servidor DNS remoto de los argumentos.
    
    default_mappings = {} #Se crea un diccionario vacío para almacenar los mapeos predeterminados de dominios a direcciones IP.
    if args.default_mapping: #Si se proporcionaron mapeos predeterminados a través de los argumentos de línea de comando, se itera sobre ellos y se agrega al diccionario
        for domain, ip in args.default_mapping:
            default_mappings[domain] = ip

    dns_proxy_server = DNSProxy(remote_dns_ip, default_mappings)#Se crea una instancia de la clase DNSProxyServer pasando la dirección IP del servidor DNS remoto y los mapeos predeterminados.
    dns_proxy_server.start_dns_proxy() #Se llama al método start() de la instancia dns_proxy_server para iniciar el servidor DNS proxy.