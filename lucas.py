#version 1.06
import argparse
from scapy.all import *
from scapy import *
import socket

parser = argparse.ArgumentParser(description="DNS Proxy Server")
parser.add_argument('-s', '--remote_dns', help='Remote DNS server IP', required=True)
parser.add_argument('-d', '--mapred', nargs="+", action='append', help='Default domain-to-IP mappings')
args = parser.parse_args()


def config_predet(lista:list):
    res: dict = {}
    for direccion in lista:
        for aux in direccion:
            separador = ":"
            resultado = aux.split(separador)
            if len(resultado) == 2:
                clave, valor = resultado
                res[clave] = valor
    return res
#genero el diccionario
if args.mapred is not None:
    preterminados = config_predet(args.mapred)

def handle_query(data,ip):
    """
    pre: data que extraigo del socket
    post: mensaje string que tengo que mandar al cliente
    La funcion va a devolver predeterminado o va a hablar con el servidor dns remoto y devolver su respues
    """
    paquete = IP(data)
    respuesta = ""
    #obtengo la capa dns del paquete
    dns = paquete.getlayer(DNS)
    #veo que sea de tipo A
    #if dns.qtype == 1:
    if hasattr(dns, 'qtype') and dns.qtype == 1:
        print("La query tiene registro A..")
        # Obtener el nombre de dominio consultado
        nombre_dominio = dns.qd.qname.decode('utf-8')
        if nombre_dominio in preterminados:
            print("La query es una predeterminada..")
            #si la dirección esta en predeterminados la codifico para enviarla
            respuesta = preterminados[nombre_dominio].encode()
    else:
        #manda la query al dns remoto
        socket2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        socket2.sendto(data,(ip,53)) #ip es la direccion pasada por parametro con parser
        #recibe respuesta 
        respuesta, _ = socket2.recvfrom(4096)
        socket2.close()

    return respuesta


#inicializo el server 

#creo el socket
socket1 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
socket1.bind(('0.0.0.0', 53))
print("Servidor DNS corriendo...")

#espero una query y la proceso llamando a la funcion handle_query, luego mando la respuesta
while True:
    data, addr = socket1.recvfrom(4096)
    print("Query recibida, procesando..")
    ip = args.remote_dns
    rta = handle_query(data,ip)
    socket1.sendto(rta, addr)
    




