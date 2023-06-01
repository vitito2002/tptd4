from socket import *
import socketserver
import argparse


parser = argparse.ArgumentParser(description="Servidor proxy DNS")
parser.add_argument("-s", "--server", required=True, help="Dirección IP del servidor DNS remoto")
parser.add_argument("-p", "--predeterminado",type=str, help="Puerto local para escuchar las consultas DNS entrantes")
args = parser.parse_args()

mapeo_predeterminado = {}

if args.predeterminado is not None:
    domain, response = args.predeterminado.split(":")
    mapeo_predeterminado[domain] = response


class MyUDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, client_address = socket.recvfrom(1024)
        data = data.strip()
        socket = self.request[1]
        print("{} wrote:".format(self.client_address[0]))
        print(data)
        print("Data recibida... procesando...")
        if data.decode() in mapeo_predeterminado:
            RtaPredeterminada = str(mapeo_predeterminado[data.decode()])
            socket.sendto(RtaPredeterminada.encode(), client_address)
        else:
            HOST, PORT = args.server, 53
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(data, (HOST, PORT))
            query_rsuelta, _ = sock.recvfrom(1024)

            print("Sent:     {}".format(query_rsuelta.decode()))
            print("Received: {}".format(query_rsuelta.decode()))

            socket.sendto(query_rsuelta, self.client_address)


if __name__ == "__main__":
    HOST, PORT = "localhost", 53
    with socketserver.UDPServer((HOST, PORT), MyUDPHandler) as server:
        print("Servidor proxy DNS iniciado en {}:{}".format(HOST, PORT))
        server.serve_forever()
