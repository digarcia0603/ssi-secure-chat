MAX_TAMANHO_MENSAGEM = 1024 * 1024  # 1 MiB


def _receber_exactamente(sock, n):
    dados = b""
    while len(dados) < n:
        pacote = sock.recv(n - len(dados))
        if not pacote:
            return None
        dados += pacote
    return dados


def enviar_mensagem(sock, dados):
    if len(dados) > MAX_TAMANHO_MENSAGEM:
        raise ValueError(
            f"Mensagem demasiado grande: {len(dados)} bytes "
            f"(máximo {MAX_TAMANHO_MENSAGEM} bytes)"
        )

    tamanho_bytes = len(dados).to_bytes(4, byteorder='big')
    sock.sendall(tamanho_bytes + dados)


def receber_mensagem(sock):
    tamanho_bytes = _receber_exactamente(sock, 4)
    if not tamanho_bytes:
        return None

    tamanho = int.from_bytes(tamanho_bytes, byteorder='big')
    if tamanho > MAX_TAMANHO_MENSAGEM:
        raise ValueError(
            f"Mensagem recebida demasiado grande: {tamanho} bytes "
            f"(máximo {MAX_TAMANHO_MENSAGEM} bytes)"
        )

    return _receber_exactamente(sock, tamanho)
