def extraerdns ():
    '''
    message tiene la data del paquete
    clientAdress tiene la IP y el puerto del cliente
    '''
    message, clientAdress = udp_socket.recvfrom 
    mensaje_modificado = message.decode().upper()