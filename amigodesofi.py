import socket
from socket import *
import sys
from scapy.all import *
import argparse
from scapy.layers.dns import DNS, DNSQR, UDP, IP, DNSRR

class DNSProxy:
    def _init_(self, remote_dns_ip, mapred):
        self.remote_dns_ip = remote_dns_ip
        self.mapred = mapred or {}
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_socket.bind(('', 53))

    def start_dns_proxy(self):
        print("DNS Proxy server is running...")

        while True:
            data, address = self.server_socket.recvfrom(4096)
            client_query = IP(data)
            self.client_address = address
            self.handle_dns_query(client_query[IP])

    def handle_dns_query(self, client_query):
        dns_query = IP(dst=self.remote_dns_ip) / UDP(sport=RandShort(), dport=53) / DNS()
        dns_query = dns_query / client_query[IP].payload

        if client_query.haslayer(DNSQR) and client_query[DNSQR].qname.decode() in self.mapred:
            dns_response = IP() / UDP() / DNS(rd=1, id=client_query[DNS].id, qr=1, qdcount=1, ancount=1,
                                              qd=DNSQR(qname=client_query[DNSQR].qname), an=DNSRR(rrname=client_query[DNSQR].qname,
                                             ttl=10, rdata=self.mapred[client_query[DNSQR].qname]))
        else:
            dns_response = sr1(dns_query, verbose=0)

        self.server_socket.sendto(bytes(dns_response), self.client_address)

def parse_arguments():
    parser = argparse.ArgumentParser(description="DNS Proxy Server")
    parser.add_argument('-s', '--remote-dns', help='Remote DNS server IP', required=True)
    parser.add_argument('-d', '--mapred', nargs="+", action='append', help='Default domain-to-IP mappings')

    return parser.parse_args()

def config_predet(lista: list):
    res = {}
    for direccion in lista:
        for aux in direccion:
            separador = ":"
            resultado = aux.split(separador)
            if len(resultado) == 2:
                clave, valor = resultado
                res[clave] = valor
    return res

if __name__ == "__main__":
    args = parse_arguments()
    remote_dns_ip = args.remote_dns

    mapred = {}
    if args.mapred is not None:
        mapred = config_predet(args.mapred)

    dns_proxy_server = DNSProxy(remote_dns_ip, mapred=mapred)
    dns_proxy_server.start_dns_proxy()