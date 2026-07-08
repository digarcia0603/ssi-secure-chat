import re

PADRAO_IDENTIFICADOR = re.compile(r"^[A-Za-z0-9_-]{3,32}$")

def identificador_valido(nome):
    return isinstance(nome, str) and bool(PADRAO_IDENTIFICADOR.fullmatch(nome))

def username_valido(nome):
    return identificador_valido(nome)

def nome_grupo_valido(nome):
    return identificador_valido(nome)
