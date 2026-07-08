def construir_payload_controle_servidor(tipo, payload):
    if isinstance(tipo, str):
        tipo = tipo.encode("utf-8")
    return b"SSI-CHAT-v1|SERVER_CTRL|" + tipo + b"|" + payload

def construir_payload_group_msg(grupo, remetente, contador, mensagem):
    return f"GROUP:{grupo}:{remetente}:{contador}:{mensagem}".encode("utf-8")

def construir_payload_session_init(remetente, destinatario, pub_efemera):
    return (
        b"SSI-CHAT-v1|SESSION_INIT|"
        + remetente.encode("utf-8") + b"|"
        + destinatario.encode("utf-8") + b"|"
        + pub_efemera
    )

def construir_payload_session_ack(remetente, destinatario, pub_iniciador, pub_resposta):
    return (
        b"SSI-CHAT-v1|SESSION_ACK|"
        + remetente.encode("utf-8") + b"|"
        + destinatario.encode("utf-8") + b"|"
        + pub_iniciador + b"|" + pub_resposta
    )

def construir_contexto_hkdf(iniciador, respondedor, pub_iniciador, pub_respondedor):
    return (
        b"SSI-CHAT-v1|HKDF|"
        + iniciador.encode("utf-8") + b"|"
        + respondedor.encode("utf-8") + b"|"
        + pub_iniciador + b"|" + pub_respondedor
    )
