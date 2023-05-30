import socket
import threading
import argparse
#from funciones import*

def config_predet(lista:list):
    res: dict = {}
    for direccion in lista:
        separador = ":"
        resultado = direccion.split(separador)
        if len(resultado) == 2:
            clave, valor = resultado
            res[clave] = valor
    return res

parser = argparse.ArgumentParser(description="Servidor proxy DNS")
parser.add_argument("-s", "--server", required=True, help="Dirección IP del servidor DNS remoto")
parser.add_argument("-n", "--predeterminado", nargs='+', help="Respuestas DNS predeterminadas")
args = parser.parse_args()


# Configura el servidor DNS remoto
REMOTE_DNS_SERVER = (args.server, 53)

#configuro la respuesta predeterminada
if args.predeterminado is not None:
    mapeo_predeterminado = config_predet(args.predeterminado)

# Función para manejar las consultas DNS
def handle_dns_query(data, client_address):
    # Crea un socket UDP para enviar la consulta al servidor DNS remoto
    remote_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if(data.decode() in mapeo_predeterminado):
        rta_predet = mapeo_predeterminado[data.decode()]
        server_socket.sendto(rta_predet, client_address)
    else:
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