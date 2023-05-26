import argparse
from scapy.all import *
from socket import *
from scapy.layers.dns import DNS, DNSQR

parser = argparse.ArgumentParser(description="Servidor proxy DNS")
parser.add_argument("-s", "--server", nargs='1', dest="remote_dns_ip", required=True, help="Dirección IP del servidor DNS remoto")
parser.add_argument("-p", "--port", nargs='+',dest="local_port", type=int, default=53, help="Puerto local para escuchar las consultas DNS entrantes")
args = parser.parse_args()

#def dns_proxy(remote_dns_ip, local_port):
    
udp_socket = socket(AF_INET, SOCK_DGRAM)
udp_socket.bind(('', '53')) #preguntar xq es 53
print ("server is ready to receive")
    
while True:
    '''
    message tiene la data del paquete
    clientAdress tiene la IP y el puerto del cliente
    '''
    message, clientAdress = udp_socket.recvfrom 
    mensaje_modificado = message.decode().upper()
    '''ahora decodificamos la direccion y lo guardamos para despues responderle al cliente'''

    mapeoPredeterminado = {'1.1.1.1'}
    respuestaPredeterminada = " www.utdt.edu"
    try:
        # Capturar y manejar las consultas DNS entrantes
        while True:
            data, addr = udp_socket.recvfrom(1024)
            data.decode()
            if (data == mapeoPredeterminado):
                udp_socket.sendto(respuestaPredeterminada, addr)
    except KeyboardInterrupt:
        udp_socket.close()
        print("Servidor proxy DNS detenido.")
    

        # Assign a port number (predeterminado) and Bind the socket to server address and server port
        # Listen to at most 1 connection at a time
        

    #funcion que procesa el mensaje y verifica que haya una query dns, si la hay la procesa
'''   
        def handle_dns_query(pkt):
        
        while True:            #Set up a new connection from the client
            query_and_ip = udp_socket.recvfrom() #preguntar max del datagrama
            
            packet_length_bytes = socket.recv(2)
            packet_length = struct.unpack('!H', packet_length_bytes)[0]

            # Lee el paquete DNS completo
            dns_packet = socket.recv(packet_length)

            # Analiza el paquete DNS para obtener la consulta
            dns_id = struct.unpack('!H', dns_packet[:2])[0]
            dns_flags = struct.unpack('!H', dns_packet[2:4])[0]
            # Resto de la extracción de campos DNS según la estructura del paquete

            # Devuelve la consulta DNS
            return dns_packet 
'''
'''
        if pkt.haslayer(DNSQR): #error viene de importar scapy.all creo
        # Obtener la consulta DNS del paquete recibido
            query_dns = pkt[DNSQR].qname.decode()

        # Enviar la consulta al servidor DNS remoto
        response = sr1(IP(dst=remote_dns_ip) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=query_dns)), verbose=False)
 
        if response:
            # Enviar la respuesta recibida del servidor DNS remoto al cliente original
            send(response, verbose=False)
       

   
    # crear socket salida poner en el while
    udp_socket = socket(AF_INET, SOCK_DGRAM)
    udp_socket.bind(('0.0.0.0', '53'))


    print(f"Servidor proxy DNS en ejecución. Escuchando en el puerto {local_port}...")


    mapeopredeterminado = {'1.1.1.1'}

    try:
        # Capturar y manejar las consultas DNS entrantes
        while True:
            data, addr = udp_socket.recvfrom(1024)
            pkt = IP(data)
            handle_dns_query(pkt)
    except KeyboardInterrupt:
        udp_socket.close()
        print("Servidor proxy DNS detenido.")

    
        
if __name__ == "__main__":
    dns_proxy(args.remote_dns_ip, args.local_port)
'''