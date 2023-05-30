def config_predet(lista:list):
    res: dict = {}
    for direccion in lista:
        separador = ":"
        resultado = direccion.split(separador)
        if len(resultado) == 2:
            clave, valor = resultado
            res[clave] = valor
    return res

