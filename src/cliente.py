import socket
import threading
import os
import hmac
import json
import base64
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from rede import enviar_mensagem, receber_mensagem
from validacao import username_valido, nome_grupo_valido
from pki import fingerprint_ca, fingerprint_ca_hex, validar_certificado_ca
from cripto import (
    carregar_ou_gerar_identidade_rsa,
    embrulhar_chave_aes, desembrulhar_chave_aes,
    assinar_mensagem, verificar_assinatura,
    cifrar_mensagem, decifrar_mensagem,
    derivar_chave_aes, gerar_par_efemero,
    verificar_certificado_utilizador,
    construir_payload_session_init, construir_payload_session_ack,
    construir_contexto_hkdf, construir_payload_controle_servidor,
    construir_payload_group_msg,
)

host = '127.0.0.1'
porta = 65432

ARQUIVO_CA_CONFIAVEL = "ca_cert.pem"
MAX_TEXTO_CHAT = 4000

meu_nome_global = ""
chave_sessao_aes = {}
chaves_publicas = {}

contadores_envio = {}
contadores_rececao = {}

ultima_msg_enviada = {}

certificado_ca = None

chaves_efemeras_pendentes = {}

mensagens_pendentes = {}

grupos = {}
contadores_grupo_envio = {}
contadores_grupo_rececao = {}
grupo_msg_sem_chave = {}

def carregar_ca_confiavel():
    if not os.path.exists(ARQUIVO_CA_CONFIAVEL):
        print(f"[!] Não encontrei '{ARQUIVO_CA_CONFIAVEL}'.")
        print("[!] Para evitar MITM, copia previamente o certificado da CA confiável para esta pasta.")
        return None

    try:
        with open(ARQUIVO_CA_CONFIAVEL, "rb") as f:
            cert_pem = f.read()
        certificado = x509.load_pem_x509_certificate(cert_pem)
        validar_certificado_ca(certificado)
        print(f"[CA] CA confiável carregada de '{ARQUIVO_CA_CONFIAVEL}'.")
        print(f"[CA] Fingerprint SHA-256: {fingerprint_ca_hex(certificado)}")
        return certificado
    except Exception as e:
        print(f"[!] Erro ao carregar/validar a CA confiável: {e}")
        return None


def _verificar_e_extrair_controle_servidor(dados):
    if not dados.startswith(b"CTRL:"):
        raise ValueError("mensagem de controlo sem prefixo CTRL")

    sep = dados.find(b":", len(b"CTRL:"))
    if sep == -1:
        raise ValueError("mensagem CTRL malformada")

    tipo = dados[len(b"CTRL:"):sep]
    resto = dados[sep + 1:]

    if len(resto) < 4 + 256:
        raise ValueError("mensagem CTRL demasiado curta")

    tamanho_payload = int.from_bytes(resto[:4], byteorder="big")
    inicio_payload = 4
    fim_payload = inicio_payload + tamanho_payload

    if len(resto) != fim_payload + 256:
        raise ValueError("tamanho da mensagem CTRL inválido")

    payload = resto[inicio_payload:fim_payload]
    assinatura = resto[fim_payload:]

    if certificado_ca is None:
        raise ValueError("CA local não carregada")

    certificado_ca.public_key().verify(
        assinatura,
        construir_payload_controle_servidor(tipo, payload),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return tipo + b":" + payload


sessoes_offline_enviadas = set()

msg_sem_chave = {}

def _processar_msg_recebida(remetente, conteudo):
    global contadores_rececao, meu_nome_global

    nonce      = conteudo[:12]
    ciphertext = conteudo[12:]

    if remetente not in chaves_publicas:
        print(f"\n[!] ALERTA: Chave pública de {remetente} desconhecida. Mensagem rejeitada.")
        return

    try:
        payload_com_assinatura = decifrar_mensagem(nonce, ciphertext, chave_sessao_aes[remetente])
    except Exception as e:
        print(f"\n[!] ERRO ao decifrar a mensagem de {remetente} (Chave AES errada ou dados corrompidos): {e}")
        return

    assinatura = payload_com_assinatura[-256:]
    payload = payload_com_assinatura[:-256]

    try:
        verificar_assinatura(payload, assinatura, chaves_publicas[remetente])
    except Exception:
        print(f"\n[!] ALERTA DE SEGURANÇA: Assinatura inválida de {remetente}. Mensagem rejeitada!")
        return

    try:
        texto = payload.decode('utf-8')
        partes_texto = texto.split(":", 2) # Esperado: ["Destinatario", "Contador", "Mensagem"]

        if len(partes_texto) == 3 and partes_texto[1].isdigit():
            alvo = partes_texto[0]
            contador_recebido = int(partes_texto[1])
            mensagem_real = partes_texto[2]

            if alvo != meu_nome_global:
                print(f"\n[!] ALERTA DE SEGURANÇA: Recebida mensagem de {remetente} que era destinada a '{alvo}'. Tentativa de Ataque de Encaminhamento (Forwarding Attack) bloqueada!")
                return

            if contador_recebido > contadores_rececao.get(remetente, 0):
                contadores_rececao[remetente] = contador_recebido
                print(f"\n[{remetente}]: {mensagem_real}")
            else:
                print(f"\n[!] ALERTA DE SEGURANÇA: Mensagem bloqueada! Possível Replay Attack de {remetente}.")
        else:
            print(f"\n[{remetente} (formato desconhecido)]: {texto}")

    except Exception as e:
         print(f"\n[!] ERRO a ler o conteúdo de {remetente}: {e}")


def _normalizar_membros_grupo(membros):
    vistos = set()
    resultado = []
    for membro in membros:
        membro = membro.strip()
        if membro and membro not in vistos:
            vistos.add(membro)
            resultado.append(membro)
    return resultado


def _processar_group_key(payload, minha_chave_privada):
    partes = payload.split(b":", 3)
    if len(partes) != 4:
        print("\n[!] GROUP_KEY malformado. Rejeitado.")
        return

    grupo = partes[1].decode("utf-8")
    admin = partes[2].decode("utf-8")

    if not nome_grupo_valido(grupo) or not username_valido(admin):
        print("\n[!] GROUP_KEY com identificadores inválidos. Rejeitado.")
        return

    try:
        info = json.loads(partes[3].decode("utf-8"))
        membros = _normalizar_membros_grupo(info["members"])
        chave_cifrada = base64.b64decode(info["key"])
    except Exception as e:
        print(f"\n[!] GROUP_KEY inválido para grupo {grupo}: {e}")
        return

    if meu_nome_global not in membros:
        print(f"\n[!] GROUP_KEY para grupo {grupo} rejeitado: não sou membro.")
        return

    try:
        chave_grupo = desembrulhar_chave_aes(chave_cifrada, minha_chave_privada)
    except Exception as e:
        print(f"\n[!] Não consegui desembrulhar a chave do grupo {grupo}: {e}")
        return

    grupos[grupo] = {
        "key": chave_grupo,
        "members": set(membros),
        "admin": admin,
    }
    contadores_grupo_envio.setdefault(grupo, 1)

    print(f"\n[Grupo {grupo}] Chave de grupo instalada. Membros: {', '.join(membros)}")

    if grupo in grupo_msg_sem_chave:
        pendentes = grupo_msg_sem_chave.pop(grupo)
        print(f"\n[Grupo {grupo}] A processar {len(pendentes)} mensagem(ns) pendente(s) que aguardavam a chave.")
        for remetente_pendente, conteudo_pendente in pendentes:
            _processar_msg_grupo(grupo, remetente_pendente, conteudo_pendente)


def _processar_msg_grupo(grupo, remetente, conteudo):
    if not nome_grupo_valido(grupo) or not username_valido(remetente):
        print("\n[!] Mensagem de grupo com identificadores inválidos. Rejeitada.")
        return

    if grupo not in grupos:
        print(f"\n[!] Recebida mensagem para grupo desconhecido '{grupo}'. Rejeitada.")
        return

    if remetente not in grupos[grupo]["members"]:
        print(f"\n[!] {remetente} não é membro do grupo {grupo}. Mensagem rejeitada.")
        return

    if remetente not in chaves_publicas:
        print(f"\n[!] Chave pública de {remetente} desconhecida. Mensagem de grupo rejeitada.")
        return

    nonce = conteudo[:12]
    ciphertext = conteudo[12:]

    try:
        payload_com_assinatura = decifrar_mensagem(nonce, ciphertext, grupos[grupo]["key"])
    except Exception as e:
        print(f"\n[!] Erro ao decifrar mensagem do grupo {grupo}: {e}")
        return

    if len(payload_com_assinatura) <= 256:
        print(f"\n[!] Mensagem do grupo {grupo} demasiado curta. Rejeitada.")
        return

    assinatura = payload_com_assinatura[-256:]
    payload = payload_com_assinatura[:-256]

    try:
        verificar_assinatura(payload, assinatura, chaves_publicas[remetente])
    except Exception:
        print(f"\n[!] Assinatura inválida em mensagem de grupo de {remetente}. Rejeitada.")
        return

    try:
        texto = payload.decode("utf-8")
        partes = texto.split(":", 4)  # GROUP:<grupo>:<remetente>:<contador>:<mensagem>
        if len(partes) != 5 or partes[0] != "GROUP" or not partes[3].isdigit():
            print(f"\n[!] Payload de grupo com formato inválido. Rejeitado.")
            return

        grupo_payload = partes[1]
        remetente_payload = partes[2]
        contador = int(partes[3])
        mensagem = partes[4]

        if grupo_payload != grupo or remetente_payload != remetente:
            print("\n[!] Contexto da mensagem de grupo não coincide. Possível forwarding attack.")
            return

        chave_contador = (grupo, remetente)
        if contador <= contadores_grupo_rececao.get(chave_contador, 0):
            print(f"\n[!] Replay bloqueado no grupo {grupo} vindo de {remetente}.")
            return

        contadores_grupo_rececao[chave_contador] = contador
        print(f"\n[Grupo {grupo} | {remetente}]: {mensagem}")

    except Exception as e:
        print(f"\n[!] Erro a processar mensagem de grupo: {e}")


def _enviar_msg_grupo(sock, grupo, mensagem, chave_privada):
    if grupo not in grupos:
        print(f"[!] Não tens chave para o grupo '{grupo}'.")
        return

    if meu_nome_global not in grupos[grupo]["members"]:
        print(f"[!] Não és membro do grupo '{grupo}'.")
        return

    contador = contadores_grupo_envio.get(grupo, 1)
    contadores_grupo_envio[grupo] = contador + 1

    payload = construir_payload_group_msg(grupo, meu_nome_global, contador, mensagem)
    assinatura = assinar_mensagem(payload, chave_privada)
    nonce, ciphertext = cifrar_mensagem(payload + assinatura, grupos[grupo]["key"])

    enviar_mensagem(sock, b"GROUP_MSG:" + grupo.encode("utf-8") + b":" + nonce + ciphertext)


def _criar_grupo(sock, grupo, membros, chave_privada):
    if not nome_grupo_valido(grupo):
        print("[!] Nome de grupo inválido. Usa letras, números, '_' ou '-', com 3 a 32 caracteres.")
        return

    membros = _normalizar_membros_grupo(membros + [meu_nome_global])

    if len(membros) < 2:
        print("[!] Um grupo precisa de pelo menos dois membros, incluindo o criador.")
        return

    for membro in membros:
        if not username_valido(membro):
            print(f"[!] Membro inválido: {membro}")
            return
        if membro not in chaves_publicas:
            print(f"[!] Não conheço a chave pública de '{membro}'. Usa /listar ou espera pelo certificado.")
            return

    chave_grupo = os.urandom(32)
    envelopes = {}
    for membro in membros:
        envelopes[membro] = base64.b64encode(
            embrulhar_chave_aes(chave_grupo, chaves_publicas[membro])
        ).decode("ascii")

    grupos[grupo] = {
        "key": chave_grupo,
        "members": set(membros),
        "admin": meu_nome_global,
    }
    contadores_grupo_envio[grupo] = 1

    pacote = json.dumps({
        "members": membros,
        "keys": envelopes,
    }).encode("utf-8")

    enviar_mensagem(sock, b"GROUP_CREATE:" + grupo.encode("utf-8") + b":" + pacote)
    print(f"[Grupo {grupo}] Criado localmente. A distribuir chave aos membros: {', '.join(membros)}")

def receber_mensagens(sock, minha_chave_privada):
    global chave_sessao_aes, chaves_publicas, certificado_ca, ultima_msg_enviada, msg_sem_chave, sessoes_offline_enviadas
    while True:
        try:
            dados = receber_mensagem(sock)
            if not dados:
                break

            if dados.startswith(b"CTRL:"):
                try:
                    dados = _verificar_e_extrair_controle_servidor(dados)
                except Exception as e:
                    print(f"\n[!] ALERTA: mensagem de controlo do servidor inválida/não autenticada: {e}")
                    sock.close()
                    break
            elif dados.startswith((b"CA_CERT:", b"MEU_CERT:", b"CHALLENGE:", b"CERT:", b"INFO:", b"GROUP_KEY:")):
                print("\n[!] ALERTA: mensagem de controlo do servidor chegou sem assinatura. Ligação terminada.")
                sock.close()
                break

            if dados.startswith(b"CA_CERT:"):
                cert_pem = dados[8:]
                try:
                    ca_recebida = x509.load_pem_x509_certificate(cert_pem)
                    validar_certificado_ca(ca_recebida)

                    if certificado_ca is None:
                        print("\n[!] CA local não carregada. Ligação terminada por segurança.")
                        sock.close()
                        break

                    if not hmac.compare_digest(fingerprint_ca(ca_recebida), fingerprint_ca(certificado_ca)):
                        print("\n[!] ALERTA CRÍTICO: A CA recebida do servidor não corresponde à CA confiável local!")
                        print("[!] Possível ataque MITM. Ligação terminada.")
                        print(f"[!] CA local:    {fingerprint_ca_hex(certificado_ca)}")
                        print(f"[!] CA recebida: {fingerprint_ca_hex(ca_recebida)}")
                        sock.close()
                        break

                    print("\n[CA] CA do servidor validada por pinning/fingerprint.")
                except Exception as e:
                    print(f"\n[!] ALERTA: Certificado da CA inválido: {e}. Ligação terminada.")
                    sock.close()
                    break
                print("\nTu: ", end="", flush=True)

            elif dados.startswith(b"MEU_CERT:"):
                cert_pem = dados[9:]
                with open(f"{meu_nome_global}_cert.pem", "wb") as f:
                    f.write(cert_pem)
                print("\n[CA] O servidor emitiu o teu certificado de identidade.")
                print("\nTu: ", end="", flush=True)

            elif dados.startswith(b"CHALLENGE:"):
                desafio = dados[10:]

                assinatura = assinar_mensagem(desafio, minha_chave_privada)

                enviar_mensagem(sock, b"RESPONSE:" + assinatura)

            elif dados.startswith(b"CERT:"):
                partes = dados.split(b":", 2)
                nome_outro = partes[1].decode('utf-8')
                cert_pem = partes[2]

                if certificado_ca is None:
                    continue

                try:
                    nome_cert, chave_publica_pem = verificar_certificado_utilizador(cert_pem, certificado_ca)

                    if nome_cert != nome_outro:
                        continue

                    chaves_publicas[nome_outro] = chave_publica_pem

                    sessoes_offline_enviadas.discard(nome_outro)

                    if nome_outro in chave_sessao_aes:
                        chave_sessao_aes.pop(nome_outro, None)
                        chaves_efemeras_pendentes.pop(nome_outro, None)
                        contadores_envio.pop(nome_outro, None)
                        contadores_rececao.pop(nome_outro, None)
                        mensagens_pendentes.pop(nome_outro, None)
                        msg_sem_chave.pop(nome_outro, None)

                        print(f"\n[*] {nome_outro} reconectou. Sessão anterior encerrada.")

                    print(f"\n[*] {nome_outro} entrou no chat. Certificado verificado pela CA.")

                except Exception as e:
                    print(f"\n[!] ALERTA: Certificado de {nome_outro} inválido: {e}. Rejeitado!")

            elif dados.startswith(b"INFO:"):
                mensagem_servidor = dados[5:].decode('utf-8')
                if mensagem_servidor.startswith("TENS_OFFLINE"):
                    enviar_mensagem(sock, b"CMD:PRONTO")
                elif mensagem_servidor.startswith("OFFLINE:"):
                    destinatario_offline = mensagem_servidor[8:]
                    if destinatario_offline in chave_sessao_aes and destinatario_offline not in chaves_efemeras_pendentes:
                        print(f"\n[*] {destinatario_offline} está offline. Mensagem guardada no servidor.")
                        if destinatario_offline not in sessoes_offline_enviadas and destinatario_offline in chaves_publicas:
                            sessoes_offline_enviadas.add(destinatario_offline)
                            embrulho = embrulhar_chave_aes(chave_sessao_aes[destinatario_offline], chaves_publicas[destinatario_offline])
                            enviar_mensagem(sock, b"SESSION:" + destinatario_offline.encode('utf-8') + b":" + embrulho)
                    else:
                        chaves_efemeras_pendentes.pop(destinatario_offline, None)
                        chave_sessao_aes.pop(destinatario_offline, None)
                        if destinatario_offline in ultima_msg_enviada:
                            mensagens_pendentes.setdefault(destinatario_offline, []).insert(
                                0, ultima_msg_enviada.pop(destinatario_offline)
                            )
                        if destinatario_offline in chaves_publicas:
                            nova_chave = os.urandom(32)
                            chave_sessao_aes[destinatario_offline] = nova_chave
                            contadores_envio[destinatario_offline] = 1
                            embrulho = embrulhar_chave_aes(nova_chave, chaves_publicas[destinatario_offline])
                            enviar_mensagem(sock, b"SESSION:" + destinatario_offline.encode('utf-8') + b":" + embrulho)
                            if destinatario_offline in mensagens_pendentes:
                                for msg_pendente in mensagens_pendentes.pop(destinatario_offline):
                                    _enviar_msg_cifrada(sock, destinatario_offline, msg_pendente, minha_chave_privada)
                            ultima_msg_enviada.pop(destinatario_offline, None)
                            print(f"\n[*] {destinatario_offline} está offline. Mensagem enviada via RSA e guardada no servidor.")
                else:
                    print(f"\n[Servidor]: {mensagem_servidor}")
                print("\nTu: ", end="", flush=True)

            elif dados.startswith(b"GROUP_KEY:"):
                _processar_group_key(dados, minha_chave_privada)
                print("\nTu: ", end="", flush=True)

            elif dados.startswith(b"GROUP_MSG:"):
                partes = dados.split(b":", 3)
                if len(partes) != 4:
                    print("\n[!] GROUP_MSG malformado. Rejeitado.")
                    continue
                grupo = partes[1].decode("utf-8")
                remetente = partes[2].decode("utf-8")
                conteudo = partes[3]
                if grupo not in grupos:
                    grupo_msg_sem_chave.setdefault(grupo, []).append((remetente, conteudo))
                    print(f"\n[Grupo {grupo}] Mensagem recebida antes da chave. Guardada temporariamente.")
                else:
                    _processar_msg_grupo(grupo, remetente, conteudo)
                print("\nTu: ", end="", flush=True)

            elif dados.startswith(b"SESSION:"):
                partes = dados.split(b":", 2)
                remetente = partes[1].decode('utf-8')
                embrulho = partes[2]
                try:
                    chave_sessao_aes[remetente] = desembrulhar_chave_aes(embrulho, minha_chave_privada)
                    contadores_rececao[remetente] = 0

                    if remetente in msg_sem_chave:
                        for cont_pendente in msg_sem_chave.pop(remetente):
                            _processar_msg_recebida(remetente, cont_pendente)

                except Exception as e:
                    print(f"\n[!] ERRO CRÍTICO: Falha ao desembrulhar chave de sessão de {remetente}: {e}")
                print("\nTu: ", end="", flush=True)

            elif dados.startswith(b"SESSION_INIT:"):
                partes = dados.split(b":", 2)
                remetente = partes[1].decode('utf-8')
                conteudo = partes[2]

                if len(conteudo) <= 32:
                    print(f"\n[!] SESSION_INIT malformado de {remetente}. Rejeitado.")
                    continue

                pub_efemera_dele = conteudo[:32]
                assinatura = conteudo[32:]
                if remetente not in chaves_publicas:
                    continue
                try:
                    payload_assinado = construir_payload_session_init(
                        remetente, meu_nome_global, pub_efemera_dele
                    )
                    verificar_assinatura(payload_assinado, assinatura, chaves_publicas[remetente])
                except Exception:
                    print(f"\n[!] ALERTA: SESSION_INIT inválido de {remetente}. Handshake rejeitado.")
                    continue

                minha_priv_efemera, minha_pub_efemera = gerar_par_efemero()
                contexto_hkdf = construir_contexto_hkdf(
                    remetente, meu_nome_global, pub_efemera_dele, minha_pub_efemera
                )
                chave_sessao_aes[remetente] = derivar_chave_aes(
                    minha_priv_efemera, pub_efemera_dele, contexto_hkdf
                )
                contadores_rececao[remetente] = 0
                payload_ack = construir_payload_session_ack(
                    meu_nome_global, remetente, pub_efemera_dele, minha_pub_efemera
                )
                assinatura_ack = assinar_mensagem(payload_ack, minha_chave_privada)
                enviar_mensagem(sock, b"SESSION_ACK:" + remetente.encode('utf-8') + b":" + minha_pub_efemera + assinatura_ack)
                print(f"\n[*] Chat seguro (forward secrecy) ativado com {remetente}!")
                print("\nTu: ", end="", flush=True)

            elif dados.startswith(b"SESSION_ACK:"):
                partes = dados.split(b":", 2)
                remetente = partes[1].decode('utf-8')
                conteudo = partes[2]

                if len(conteudo) <= 32:
                    print(f"\n[!] SESSION_ACK malformado de {remetente}. Rejeitado.")
                    continue

                pub_efemera_dele = conteudo[:32]
                assinatura = conteudo[32:]
                if remetente not in chaves_publicas:
                    continue
                if remetente not in chaves_efemeras_pendentes:
                    print(f"\n[!] SESSION_ACK inesperado de {remetente}. Rejeitado.")
                    continue

                minha_priv_efemera, minha_pub_efemera = chaves_efemeras_pendentes[remetente]
                try:
                    payload_assinado = construir_payload_session_ack(
                        remetente, meu_nome_global, minha_pub_efemera, pub_efemera_dele
                    )
                    verificar_assinatura(payload_assinado, assinatura, chaves_publicas[remetente])
                except Exception:
                    print(f"\n[!] ALERTA: SESSION_ACK inválido de {remetente}. Handshake rejeitado.")
                    continue

                chaves_efemeras_pendentes.pop(remetente, None)
                contexto_hkdf = construir_contexto_hkdf(
                    meu_nome_global, remetente, minha_pub_efemera, pub_efemera_dele
                )
                chave_sessao_aes[remetente] = derivar_chave_aes(
                    minha_priv_efemera, pub_efemera_dele, contexto_hkdf
                )
                contadores_rececao[remetente] = 0
                print(f"\n[*] Chat seguro (forward secrecy) ativado com {remetente}!")
                if remetente in mensagens_pendentes:
                    for msg_pendente in mensagens_pendentes.pop(remetente):
                        _enviar_msg_cifrada(sock, remetente, msg_pendente, minha_chave_privada)
                print("\nTu: ", end="", flush=True)

            elif dados.startswith(b"MSG:"):
                partes = dados.split(b":", 2)
                remetente = partes[1].decode('utf-8')
                conteudo = partes[2]

                if remetente in chave_sessao_aes:
                    _processar_msg_recebida(remetente, conteudo)
                else:
                    msg_sem_chave.setdefault(remetente, []).append(conteudo)

                print("\nTu: ", end="", flush=True)

        except Exception as e:
            print(f"\nErro crítico na receção: {e}.")
            sock.close()
            break

def _enviar_msg_cifrada(sock, destinatario, mensagem, chave_privada):
    ultima_msg_enviada[destinatario] = mensagem
    contador = contadores_envio.get(destinatario, 1)
    contadores_envio[destinatario] = contador + 1
    payload = f"{destinatario}:{contador}:{mensagem}".encode('utf-8')

    assinatura = assinar_mensagem(payload, chave_privada)

    payload_com_assinatura = payload + assinatura

    nonce, ciphertext = cifrar_mensagem(payload_com_assinatura, chave_sessao_aes[destinatario])

    enviar_mensagem(sock, b"MSG:" + destinatario.encode('utf-8') + b":" + nonce + ciphertext)

def iniciar_cliente():
    global meu_nome_global, certificado_ca
    certificado_ca = carregar_ca_confiavel()
    if certificado_ca is None:
        return

    meu_nome_global = input("Bem-vindo! Qual é o teu username? ").strip()
    if not username_valido(meu_nome_global):
        print("[!] Username inválido. Usa apenas letras, números, '_' ou '-', com 3 a 32 caracteres.")
        return

    chave_privada, chave_publica_pem = carregar_ou_gerar_identidade_rsa(meu_nome_global)
    chaves_publicas[meu_nome_global] = chave_publica_pem
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((host, porta))
        enviar_mensagem(sock, b"KEY:" + meu_nome_global.encode('utf-8') + b":" + chave_publica_pem)
        print("Ligado ao servidor.")
    except Exception:
        print("Não foi possível ligar ao servidor.")
        return

    thread = threading.Thread(target=receber_mensagens, args=(sock, chave_privada), daemon=True)
    thread.start()

    print("\n------  Chat iniciado ------")
    print("Comandos: /listar | /msg <utilizador> <texto> | /grupo criar <grupo> <membros...> | /grupo msg <grupo> <texto> | /grupo membros <grupo> | sair")
    print("----------------------------\n")

    while True:
        try:
            texto = input("\nTu: ")
            if texto.lower() == 'sair':
                break
            elif texto.lower() == '/listar':
                enviar_mensagem(sock, b"CMD:LISTAR")
            elif texto.lower().startswith('/grupo criar '):
                partes = texto.split()
                if len(partes) < 5:
                    print("Uso correto: /grupo criar <nome_grupo> <membro1> <membro2> ...")
                    continue
                grupo = partes[2].strip()
                membros = partes[3:]
                _criar_grupo(sock, grupo, membros, chave_privada)

            elif texto.lower().startswith('/grupo msg '):
                partes = texto.split(" ", 3)
                if len(partes) < 4:
                    print("Uso correto: /grupo msg <nome_grupo> <mensagem>")
                    continue
                grupo = partes[2].strip()
                mensagem = partes[3]

                if not nome_grupo_valido(grupo):
                    print("[!] Nome de grupo inválido.")
                    continue
                if len(mensagem.encode('utf-8')) > MAX_TEXTO_CHAT:
                    print(f"[!] Mensagem demasiado grande. Máximo: {MAX_TEXTO_CHAT} bytes de texto.")
                    continue
                _enviar_msg_grupo(sock, grupo, mensagem, chave_privada)

            elif texto.lower().startswith('/grupo membros '):
                partes = texto.split(" ", 2)
                if len(partes) != 3:
                    print("Uso correto: /grupo membros <nome_grupo>")
                    continue
                grupo = partes[2].strip()
                if grupo not in grupos:
                    print(f"[!] Grupo '{grupo}' desconhecido ou sem chave local.")
                    continue
                membros = ", ".join(sorted(grupos[grupo]["members"]))
                print(f"[Grupo {grupo}] Admin: {grupos[grupo]['admin']} | Membros: {membros}")

            elif texto.lower().startswith('/msg '):
                partes = texto.split(" ", 2)
                if len(partes) < 3:
                    print("Uso correto: /msg <nome> <mensagem>")
                    continue
                destinatario = partes[1].strip()
                mensagem     = partes[2]

                if not username_valido(destinatario):
                    print("[!] Destinatário inválido. Usa apenas letras, números, '_' ou '-', com 3 a 32 caracteres.")
                    continue

                if len(mensagem.encode('utf-8')) > MAX_TEXTO_CHAT:
                    print(f"[!] Mensagem demasiado grande. Máximo: {MAX_TEXTO_CHAT} bytes de texto.")
                    continue

                if destinatario == meu_nome_global:
                    print("[!] Não podes enviar mensagens para ti próprio.")
                    continue

                if destinatario in chave_sessao_aes:
                    _enviar_msg_cifrada(sock, destinatario, mensagem, chave_privada)
                elif destinatario in chaves_efemeras_pendentes:
                    mensagens_pendentes.setdefault(destinatario, []).append(mensagem)
                    print(f"[*] Handshake em curso com {destinatario}. Mensagem em fila.")
                elif destinatario in chaves_publicas:
                    priv_efemera, pub_efemera = gerar_par_efemero()
                    chaves_efemeras_pendentes[destinatario] = (priv_efemera, pub_efemera)
                    contadores_envio[destinatario] = 1
                    mensagens_pendentes.setdefault(destinatario, []).append(mensagem)
                    payload_init = construir_payload_session_init(
                        meu_nome_global, destinatario, pub_efemera
                    )
                    assinatura = assinar_mensagem(payload_init, chave_privada)
                    enviar_mensagem(sock, b"SESSION_INIT:" + destinatario.encode('utf-8') + b":" + pub_efemera + assinatura)
                    print(f"[*] Handshake iniciado com {destinatario}. A aguardar resposta...")
                else:
                    print(f"[!] Utilizador '{destinatario}' desconhecido. Usa /listar.")
            else:
                print("Comando inválido. Usa /msg <nome> <mensagem> para falar com alguém.")
        except KeyboardInterrupt:
            break

    sock.close()
    os._exit(0)

if __name__ == "__main__":
    iniciar_cliente()
