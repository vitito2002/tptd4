import argparse

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

def parse_arguments():
    parser = argparse.ArgumentParser(description="DNS Proxy Server")
    parser.add_argument('-d', '--mappred', nargs="+", action='append',  help='Default domain-to-IP mappings')
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_arguments()
    if args.mappred is not None:

        default_mappings = {} #Se crea un diccionario vacío para almacenar los mapeos predeterminados de dominios a direcciones IP.
        default_mappings = config_predet(args.mappred)
        #if args.default_mapping: #Si se proporcionaron mapeos predeterminados a través de los argumentos de línea de comando, se itera sobre ellos y se agrega al diccionario
        #   for domain, ip in args.default_mapping: 
        #      default_mappings[domain] = ip
        print(default_mappings)
