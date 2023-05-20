import scapy
from scapy.all import DNS, DNSQR, IP, sr1, UDP

dns_req = IP(dst='8.8.8.8')/
    UDP(dport=53)/
    DNS(rd=1, qd=DNSQR(qname='www.thepacketgeek.com'))
answer = sr1(dns_req, verbose=0)

import dns.message
import dns.query
import socketserver
import threading

class DNSProxyHandler(socketserver.BaseRequestHandler):
    def handle(self):
        # Recibir la query DNS del cliente
        data = self.request[0]
        socket = self.request[1]

        # Crear una consulta DNS basada en los datos recibidos
        query = dns.message.from_wire(data)

        # Enviar la consulta al servidor DNS legítimo remoto
        response = dns.query.tcp(query, 'IP_DEL_SERVIDOR_DNS_LEGITIMO')

        # Transmitir la respuesta del servidor DNS legítimo al cliente original
        socket.sendto(response.to_wire(), self.client_address)

class DNSProxyServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True

    def server_activate(self):
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(self.server_address)

    def finish_request(self, request, client_address):
        DNSProxyHandler(request, client_address)

    def serve_forever(self):
        self.__shutdown_request = False
        self.__is_shut_down = threading.Event()

        while not self.__shutdown_request:
            self.handle_request()

        self.__is_shut_down.set()

    def shutdown(self):
        self.__shutdown_request = True
        self.__is_shut_down.wait()

if __name__ == '__main__':
    server = DNSProxyServer(('TU_DIRECCION_IP', PUERTO), DNSProxyHandler)
    server.serve_forever()
