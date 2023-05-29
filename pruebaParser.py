import socket
import threading
import argparse

parser = argparse.ArgumentParser(description="Servidor proxy DNS")
parser.add_argument("-s", "--server", required=True, help="Dirección IP del servidor DNS remoto")
parser.add_argument("-p", "--predeterminado",type=str, help="Puerto local para escuchar las consultas DNS entrantes")
args = parser.parse_args()
# Configura el servidor DNS remoto
REMOTE_DNS_SERVER = (args.server, 53)

#configuro la respuesta predeterminada
mapeo_predeterminado = {}
if args.predeterminado is not None:
    domain, response = args.predeterminado.split(":")
    mapeo_predeterminado[domain] = response

# Función para manejar las consultas DNS
def handle_dns_query(data, client_address):
    # Crea un socket UDP para enviar la consulta al servidor DNS remoto
    remote_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        # Envía la consulta DNS al servidor DNS remoto
        remote_socket.sendto(data, REMOTE_DNS_SERVER)

        # Recibe la respuesta del servidor DNS remoto
        response, _ = remote_socket.recvfrom(4096)
        
        # Transmite la respuesta sin modificaciones al cliente original
        server_socket.sendto(response, client_address)

    finally:
        remote_socket.close()

# Crea un socket UDP para escuchar las consultas DNS entrantes
server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_socket.bind(('0.0.0.0', 53))

print('Servidor DNS proxy en ejecución...')

while True:
    # Espera a que llegue una consulta DNS
    data, client_address = server_socket.recvfrom(4096)
    

    # Maneja la consulta DNS en un nuevo hilo para permitir conexiones simultáneas
    threading.Thread(target=handle_dns_query, args=(data, client_address)).start()