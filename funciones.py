import socket
import argparse
from funciones import*
from scapy.all import DNS, DNSQR, DNSRR, IP, send, sniff, sr1, UDP

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

#configuro la respuesta predeterminada
if args.predeterminado is not None:
    mapeo_predeterminado = config_predet(args.predeterminado)

IFACE = "lo0"   # Or your default interface
DNS_SERVER_IP = "192.168.0.17"  # Your local IP

BPF_FILTER = f"udp port 53 and ip dst {DNS_SERVER_IP}" #captura únicamente pkt UDP dirigidos a puerto 53 con IP del DNS local

# Función para manejar las consultas DNS
def dns_responder(local_ip: str):

    def forward_dns(orig_pkt: IP):
        print(f"Forwarding: {orig_pkt[DNSQR].qname}")
        response = sr1(
            ##le asigno la IP pasada por consola
            IP(dst=str(args.server))/
                UDP(sport=orig_pkt[UDP].sport)/
                DNS(rd=1, id=orig_pkt[DNS].id, qd=DNSQR(qname=orig_pkt[DNSQR].qname)),
            verbose=0,
        )
        resp_pkt = IP(dst=orig_pkt[IP].src, src=DNS_SERVER_IP)/UDP(dport=orig_pkt[UDP].sport)/DNS()
        resp_pkt[DNS] = response[DNS]
        send(resp_pkt, verbose=0)
        return f"Responding to {orig_pkt[IP].src}"

    def get_response(pkt: IP):
        if (
            DNS in pkt and
            pkt[DNS].opcode == 0 and
            pkt[DNS].ancount == 0
        ):
            for predeterkey in mapeo_predeterminado:
                if (str(predeterkey) in str(pkt["DNS Question Record"].qname) and pkt[DNSQR].qtype == 1):
                    print("Consulta DNS estándar de tipo A")
                    # Creación del paquete de respuesta 
                    ip_response = IP(dst=pkt[IP].src)  # Se establece la dirección IP de destino como la IP de origen del paquete DNS recibido
                    udp_response = UDP(dport=pkt[UDP].sport, sport=53)  # Se establecen los puertos UDP correspondientes
                    dns_response = DNS(id=pkt[DNS].id, ancount=1)  # Se establece el ID del paquete DNS y se especifica que habrá una respuesta en la sección de respuestas

                    # Creación del registro de recurso de respuesta DNS con la dirección IP asociada al nombre de dominio consultado
                    # se asigna el registro predeterminado
                    dns_rr = DNSRR(rrname=pkt[DNSQR].qname, rdata=mapeo_predeterminado[predeterkey])

                    # Creación de un registro de recurso adicional para "trailers.apple.com"
                    #COMENTADOadditional_rr = DNSRR(rrname="trailers.apple.com", rdata=local_ip)

                    # Agregar el registro de recurso de respuesta y el registro de recurso adicional al paquete DNS de respuesta
                    dns_response.an = dns_rr  # Se establece el registro de recurso de respuesta en la sección de respuestas del paquete DNS
                    #COMENTADOdns_response.ns = additional_rr  # Se establece el registro de recurso adicional en la sección de autoridad del paquete DNS

                    # Combinar los encabezados IP, UDP y DNS para formar el paquete de respuesta completo
                    spf_resp = ip_response / udp_response / dns_response

                    # Envío del paquete de respuesta
                    send(spf_resp, verbose=0, iface=IFACE)

                    # Mensaje de confirmación
                    return f"Spoofed DNS Response Sent: {pkt[IP].src}"


                else:
                    # make DNS query, capturing the answer and send the answer
                    return forward_dns(pkt)

    return get_response

sniff(filter=BPF_FILTER, prn=dns_responder(DNS_SERVER_IP), iface=IFACE)