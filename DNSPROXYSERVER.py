from socket import *
import socketserver
import argparse
import sys
#import scapy
#from scapy.all import *
#from scapy.layers.dns import DNS, DNSQR, UDP, IP

parser = argparse.ArgumentParser(description="Servidor proxy DNS")
parser.add_argument("-s", "--server", nargs='+', dest="remote_dns_ip", required=True, help="Dirección IP del servidor DNS remoto")
parser.add_argument("-p", "--port", nargs='+',dest="local_port", default=53, help="Puerto local para escuchar las consultas DNS entrantes")
args = parser.parse_args()

#IP_servidorDNS = args.server

#def dns_proxy(remote_dns_ip, local_port):
udp_socket = socket(AF_INET, SOCK_DGRAM)
udp_socket.bind(('', 53)) #53 es predeterminado
print ("server is ready to receive")
    
while True:
    #connectionSocket = udp_socket.accept()
    '''
    data_cliente tiene la data_cliente del paquete
    clientAdress tiene la IP y el puerto del cliente
    '''
    data_cliente, addr_cliente = udp_socket.recvfrom(4096)
    #udp_socket.close()  tengo que cerrar el socket para que no me lleguen mas querys mientras proceso la actual
    data_clienteDecoded = data_cliente.decode().upper()
    '''ahora decodificamos la direccion y lo guardamos para despues responderle al cliente'''
    mapeoPredeterminado = " www.utdt.edu"
    respuestaPredeterminada = '1.1.1.1'

    if (args.port in mapeoPredeterminado):
        udp_socket.sendto(respuestaPredeterminada, addr_cliente)
        print ("1.1.1.1")
        False
        break
    else:
        udp_clientSideSocket = socket(AF_INET, SOCK_DGRAM)
        IP_servidorDNS = "8.8.8.8" #va la ip que pasamos por consola(?)
        puerto_servidorDNS = 53
        udp_clientSideSocket.sendto(data_clienteDecoded.encode(), (IP_servidorDNS, puerto_servidorDNS))
        data_servidor, addr_servidor = udp_clientSideSocket.recvfrom()
        udp_clientSideSocket.close()
        udp_socket.sendto(data_servidor, addr_cliente)
        
    False