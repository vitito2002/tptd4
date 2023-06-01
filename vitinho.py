import socket
import argparse

def dns_proxy(remote_dns_ip, local_port):
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(('', local_port))
    print("El servidor está listo para recibir consultas DNS.")

    while True:
        data_cliente, addr_cliente = udp_socket.recvfrom(4096)
        data_cliente_decoded = data_cliente.decode().upper()

        mapeo_predeterminado = {'1.1.1.1'}
        respuesta_predeterminada = "www.utdt.edu"

        if data_cliente_decoded in mapeo_predeterminado:
            udp_socket.sendto(respuesta_predeterminada.encode(), addr_cliente)
        else:
            udp_client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_client_socket.sendto(data_cliente, (remote_dns_ip, 53))
            data_servidor = udp_client_socket.recvfrom(4096)[0] # el segundo elemento de la tupla (addr del servidor DNS) no lo necesito
            udp_client_socket.close()
            udp_socket.sendto(data_servidor, addr_cliente)

def parse_arguments():
    parser = argparse.ArgumentParser(description="Servidor proxy DNS")
    parser.add_argument("-s", "--server", dest="remote_dns_ip", required=True, help="Dirección IP del servidor DNS remoto")
    parser.add_argument("-p", "--port", dest="local_port", type=int, default=53, help="Puerto local para escuchar las consultas DNS entrantes")
    parser.add_argument('-d', '--default-mapping', nargs=2, action='append', metavar=('domain', 'ip'), help='Default domain-to-IP mappings')

    return parser.parse_args()

if __name__ == "__main__":
    args = parse_arguments()
    dns_proxy(args.remote_dns_ip, args.local_port)
