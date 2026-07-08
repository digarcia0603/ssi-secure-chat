import socket
import threading
import json
import os
import getpass

from cryptography.hazmat.primitives import serialization
from cryptography import x509
from rede import enviar_mensagem, receber_mensagem
from validacao import username_valido, nome_grupo_valido
from persistencia import carregar_json, guardar_json
from cripto import (
    gerar_certificado_ca, emitir_certificado_utilizador, verificar_assinatura,
    assinar_mensagem, construir_payload_controle_servidor,
)


host = '127.0.0.1'
porta = 65432

clientes = {}


clientes_lock = threading.Lock()
bd_lock = threading.Lock()
offline_lock = threading.Lock()
grupos_lock = threading.Lock()


ARQUIVO_CA_CERT = "ca_cert.pem"
ARQUIVO_CA_KEY  = "ca_key.pem"

chave_privada_ca  = None
certificado_ca    = None
certificado_ca_pem = None

def _pedir_password_ca(confirmar=False):
    while True:
        password = getpass.getpass("[CA] Password da chave privada da CA: ").encode("utf-8")
        if len(password) < 8:
            print("[CA] A password da CA deve ter pelo menos 8 caracteres.")
            continue

        if not confirmar:
            return password

        password2 = getpass.getpass("[CA] Confirma a password da CA: ").encode("utf-8")
        if password != password2:
            print("[CA] As passwords não coincidem. Tenta novamente.")
            continue

        return password


def _guardar_chave_ca_encriptada(chave_privada, password):
    with open(ARQUIVO_CA_KEY, "wb") as f:
        f.write(chave_privada.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password)
        ))
    os.chmod(ARQUIVO_CA_KEY, 0o600)


def inicializar_ca():
    global chave_privada_ca, certificado_ca, certificado_ca_pem

    existe_cert = os.path.exists(ARQUIVO_CA_CERT)
    existe_key = os.path.exists(ARQUIVO_CA_KEY)

    if existe_cert != existe_key:
        raise RuntimeError(
            "Estado inconsistente da CA: devem existir ambos os ficheiros "
            "ca_cert.pem e ca_key.pem, ou nenhum deles. "
            "Remove ambos para gerar uma CA nova, ou restaura o par correto."
        )

    if existe_cert and existe_key:
        print("[CA] A carregar certificado existente da CA...")
        password = _pedir_password_ca(confirmar=False)

        with open(ARQUIVO_CA_KEY, "rb") as f:
            chave_privada_pem = f.read()

        try:
            chave_privada_ca = serialization.load_pem_private_key(
                chave_privada_pem,
                password=password
            )
        except TypeError:
            print("[CA] Aviso: a chave privada da CA estava sem cifragem. A migrar para formato protegido...")
            chave_privada_ca = serialization.load_pem_private_key(
                chave_privada_pem,
                password=None
            )
            _guardar_chave_ca_encriptada(chave_privada_ca, password)
            print("[CA] Chave privada da CA regravada com cifragem.")

        with open(ARQUIVO_CA_CERT, "rb") as f:
            certificado_ca_pem = f.read()
        certificado_ca = x509.load_pem_x509_certificate(certificado_ca_pem)
        print("[CA] Certificado da CA carregado com sucesso.")
    else:
        print("[CA] A gerar novo par de chaves e certificado self-signed da CA...")
        password = _pedir_password_ca(confirmar=True)
        chave_privada_ca, certificado_ca = gerar_certificado_ca()
        certificado_ca_pem = certificado_ca.public_bytes(serialization.Encoding.PEM)

        _guardar_chave_ca_encriptada(chave_privada_ca, password)
        with open(ARQUIVO_CA_CERT, "wb") as f:
            f.write(certificado_ca_pem)

        os.chmod(ARQUIVO_CA_CERT, 0o644)
        print("[CA] Certificado self-signed gerado e guardado com sucesso.")
        print("[CA] A chave privada da CA foi guardada cifrada com password.")


def construir_mensagem_controle(tipo, payload):
    if isinstance(tipo, str):
        tipo_bytes = tipo.encode("utf-8")
    else:
        tipo_bytes = tipo
    payload_assinado = construir_payload_controle_servidor(tipo_bytes, payload)
    assinatura = assinar_mensagem(payload_assinado, chave_privada_ca)
    return b"CTRL:" + tipo_bytes + b":" + len(payload).to_bytes(4, "big") + payload + assinatura


def enviar_controle(conn, tipo, payload=b""):
    enviar_mensagem(conn, construir_mensagem_controle(tipo, payload))


Arquivo_BD = "bd_utilizadores.json"
bases_dados_utilizadores = {}

def carregar_base_dados():
    global bases_dados_utilizadores
    bases_dados_utilizadores = carregar_json(Arquivo_BD, {}, "BD de utilizadores")
    if bases_dados_utilizadores:
        print(f"Base de dados carregada com {len(bases_dados_utilizadores)} utilizadores registados.")
    else:
        print("Nenhuma base de dados encontrada. A iniciar nova...")

def guardar_base_dados():
    guardar_json(Arquivo_BD, bases_dados_utilizadores, "BD de utilizadores")


Arquivo_offline = "mensagens_offline.json"
bd_offline = {}

def carregar_offline():
    global bd_offline
    bd_offline = carregar_json(Arquivo_offline, {}, "mensagens offline")
    if bd_offline:
        print(f"Caixa de correio offline carregada com mensagens pendentes para {len(bd_offline)} utilizadores.")

def guardar_offline():
    guardar_json(Arquivo_offline, bd_offline, "mensagens offline")


Arquivo_grupos = "grupos_chat.json"
grupos_chat = {}


def carregar_grupos():
    global grupos_chat
    grupos_chat = carregar_json(Arquivo_grupos, {}, "grupos")
    if grupos_chat:
        print(f"Grupos carregados: {len(grupos_chat)}")
    else:
        print("Nenhuma base de dados de grupos encontrada. A iniciar nova...")


def guardar_grupos():
    guardar_json(Arquivo_grupos, grupos_chat, "grupos")


def _payload_group_key(grupo, admin, membro):
    info = grupos_chat[grupo]
    payload_json = json.dumps({
        "members": info["members"],
        "key": info["keys"][membro],
    }).encode("utf-8")
    return grupo.encode("utf-8") + b":" + admin.encode("utf-8") + b":" + payload_json


def enviar_group_key_para_conn(conn, grupo, membro):
    info = grupos_chat[grupo]
    payload = _payload_group_key(grupo, info["admin"], membro)
    enviar_controle(conn, "GROUP_KEY", payload)


def enviar_chaves_grupo_para_utilizador(conn, nome):
    with grupos_lock:
        grupos_do_utilizador = [
            grupo for grupo, info in grupos_chat.items()
            if nome in info.get("members", []) and nome in info.get("keys", {})
        ]

    for grupo in grupos_do_utilizador:
        enviar_group_key_para_conn(conn, grupo, nome)


def lidar_com_clientes(conn, addr):
    print(f"Nova ligação: {addr}")
    clientes[conn] = {'addr': addr, 'nome': None, 'pub_key': None}

    while True:
        try:
            dados = receber_mensagem(conn)
            if not dados:
                break

            if dados.startswith(b"KEY:"):
                partes = dados.split(b":", 2)
                if len(partes) != 3:
                    enviar_mensagem(conn, construir_mensagem_controle("INFO", b"ERRO - Pedido KEY malformado."))
                    break

                nome = partes[1].decode('utf-8', errors='strict')
                chave_pem = partes[2]

                if not username_valido(nome):
                    print(f"[!] Username inválido rejeitado de {addr}: {nome!r}")
                    enviar_mensagem(conn, construir_mensagem_controle("INFO", b"ERRO - Username invalido. Usa 3-32 caracteres: letras, numeros, '_' ou '-'."))
                    break

                clientes[conn]['nome'] = nome
                clientes[conn]['pub_key'] = chave_pem
                clientes[conn]['autenticado'] = False # NOVA FLAG DE SEGURANÇA

                chave_pem_str = chave_pem.decode('utf-8')
                with bd_lock:
                    if nome in bases_dados_utilizadores:
                        if bases_dados_utilizadores[nome] != chave_pem_str:
                            print(f"[!] ALERTA DE SEGURANÇA: Tentativa de usurpação de identidade para '{nome}'.")
                            enviar_mensagem(conn, construir_mensagem_controle("INFO", b"ERRO - Nome de utilizador ja registado com outra chave."))
                            continue
                    else:
                        bases_dados_utilizadores[nome] = chave_pem_str
                        guardar_base_dados()
                        print(f"[*] Nova chave pública de {nome} fixada na BD com segurança.")

                desafio = os.urandom(32)
                clientes[conn]['desafio'] = desafio
                enviar_mensagem(conn, construir_mensagem_controle("CHALLENGE", desafio))
                print(f"[*] Desafio de autenticação enviado a {nome} ({addr})")

            elif dados.startswith(b"RESPONSE:"):
                assinatura = dados[9:]
                nome = clientes[conn].get('nome')
                desafio = clientes[conn].get('desafio')
                chave_pem = clientes[conn].get('pub_key')

                if not nome or not desafio or not chave_pem:
                    continue

                try:
                    verificar_assinatura(desafio, assinatura, chave_pem)

                    clientes[conn]['autenticado'] = True
                    print(f"[*] {nome} provou a sua identidade com sucesso!")

                    cert_pem = emitir_certificado_utilizador(nome, chave_pem, chave_privada_ca, certificado_ca)
                    clientes[conn]['cert'] = cert_pem

                    enviar_mensagem(conn, construir_mensagem_controle("CA_CERT", certificado_ca_pem))
                    enviar_mensagem(conn, construir_mensagem_controle("MEU_CERT", cert_pem))

                    with clientes_lock:
                        outros_autenticados = [c for c in clientes if c != conn and clientes[c].get('autenticado')]
                    for c in outros_autenticados:
                        enviar_mensagem(c, construir_mensagem_controle("CERT", nome.encode('utf-8') + b":" + cert_pem))

                    for nome_bd, chave_bd_str in bases_dados_utilizadores.items():
                        if nome_bd != nome:
                            cert_outro = emitir_certificado_utilizador(
                                nome_bd, chave_bd_str.encode('utf-8'), chave_privada_ca, certificado_ca
                            )
                            enviar_mensagem(conn, construir_mensagem_controle("CERT", nome_bd.encode('utf-8') + b":" + cert_outro))

                    enviar_chaves_grupo_para_utilizador(conn, nome)

                    with offline_lock:
                        if nome in bd_offline and len(bd_offline[nome]) > 0:
                            enviar_mensagem(conn, construir_mensagem_controle("INFO", b"TENS_OFFLINE"))

                except Exception:
                    print(f"[!] ALERTA CRÍTICO: {nome} falhou o desafio criptográfico! Conexão terminada.")
                    enviar_mensagem(conn, construir_mensagem_controle("INFO", b"ERRO - Falha na autenticacao criptografica."))
                    break # Expulsa o impostor

            elif dados.startswith(b"CMD:PRONTO"):
                if not clientes[conn].get('autenticado'): continue

                nome = clientes[conn]['nome']
                with offline_lock:
                    if nome in bd_offline and len(bd_offline[nome]) > 0:
                        enviar_mensagem(conn, construir_mensagem_controle("INFO", b"Tens mensagens offline a chegar!"))
                        for pacote_hex in bd_offline[nome]:
                            enviar_mensagem(conn, bytes.fromhex(pacote_hex))
                        del bd_offline[nome]
                        guardar_offline()
                        print(f"[*] Mensagens offline entregues a '{nome}'.")

            elif dados.startswith(b"CMD:LISTAR"):
                if not clientes[conn].get('autenticado'):
                    continue

                with clientes_lock:
                    nomes_online = [
                        info['nome']
                        for c, info in clientes.items()
                        if info['nome'] and info.get('autenticado')
                    ]

                resposta = "Utilizadores online: " + ", ".join(nomes_online)
                enviar_controle(conn, "INFO", resposta.encode('utf-8'))

            elif dados.startswith(b"GROUP_CREATE:"):
                if not clientes[conn].get('autenticado'):
                    continue

                partes = dados.split(b":", 2)
                if len(partes) != 3:
                    enviar_controle(conn, "INFO", b"ERRO - GROUP_CREATE malformado.")
                    continue

                criador = clientes[conn]['nome']
                grupo = partes[1].decode('utf-8', errors='strict')

                if not nome_grupo_valido(grupo):
                    enviar_controle(conn, "INFO", b"ERRO - Nome de grupo invalido.")
                    continue

                try:
                    info = json.loads(partes[2].decode('utf-8'))
                    membros = info["members"]
                    keys = info["keys"]
                except Exception:
                    enviar_controle(conn, "INFO", b"ERRO - Dados de grupo invalidos.")
                    continue

                if not isinstance(membros, list) or not isinstance(keys, dict):
                    enviar_controle(conn, "INFO", b"ERRO - Estrutura de grupo invalida.")
                    continue

                membros_norm = []
                vistos = set()
                valido = True
                for membro in membros:
                    if not isinstance(membro, str) or not username_valido(membro):
                        valido = False
                        break
                    if membro not in vistos:
                        vistos.add(membro)
                        membros_norm.append(membro)

                if not valido or criador not in membros_norm or len(membros_norm) < 2:
                    enviar_controle(conn, "INFO", b"ERRO - Lista de membros invalida.")
                    continue

                for membro in membros_norm:
                    if membro not in keys or not isinstance(keys[membro], str):
                        valido = False
                        break

                if not valido:
                    enviar_controle(conn, "INFO", b"ERRO - Faltam chaves cifradas para membros do grupo.")
                    continue

                with grupos_lock:
                    if grupo in grupos_chat:
                        enviar_controle(conn, "INFO", b"ERRO - Grupo ja existe.")
                        continue

                    grupos_chat[grupo] = {
                        "admin": criador,
                        "members": membros_norm,
                        "keys": {membro: keys[membro] for membro in membros_norm},
                    }
                    guardar_grupos()

                print(f"[*] Grupo '{grupo}' criado por {criador} com membros: {', '.join(membros_norm)}")

                with clientes_lock:
                    destinos_online = [
                        (c, info['nome']) for c, info in clientes.items()
                        if info.get('autenticado') and info.get('nome') in membros_norm
                    ]

                for destino_conn, nome_destino in destinos_online:
                    enviar_group_key_para_conn(destino_conn, grupo, nome_destino)

                enviar_controle(conn, "INFO", f"Grupo {grupo} criado com sucesso.".encode('utf-8'))

            elif dados.startswith(b"GROUP_MSG:"):
                if not clientes[conn].get('autenticado'):
                    continue

                partes = dados.split(b":", 2)
                if len(partes) != 3:
                    enviar_controle(conn, "INFO", b"ERRO - GROUP_MSG malformado.")
                    continue

                remetente = clientes[conn]['nome']
                grupo = partes[1].decode('utf-8', errors='strict')
                conteudo = partes[2]

                if not nome_grupo_valido(grupo):
                    enviar_controle(conn, "INFO", b"ERRO - Nome de grupo invalido.")
                    continue

                with grupos_lock:
                    info_grupo = grupos_chat.get(grupo)
                    if not info_grupo:
                        enviar_controle(conn, "INFO", b"ERRO - Grupo desconhecido.")
                        continue
                    membros = list(info_grupo.get("members", []))

                if remetente not in membros:
                    enviar_controle(conn, "INFO", b"ERRO - Nao es membro desse grupo.")
                    continue

                pacote_final = b"GROUP_MSG:" + grupo.encode('utf-8') + b":" + remetente.encode('utf-8') + b":" + conteudo

                with clientes_lock:
                    destinos_online = {
                        info['nome']: c for c, info in clientes.items()
                        if info.get('autenticado') and info.get('nome') in membros and info.get('nome') != remetente
                    }

                for membro in membros:
                    if membro == remetente:
                        continue
                    destino_conn = destinos_online.get(membro)
                    if destino_conn:
                        enviar_mensagem(destino_conn, pacote_final)
                    else:
                        with offline_lock:
                            if membro not in bd_offline:
                                bd_offline[membro] = []
                            bd_offline[membro].append(pacote_final.hex())
                            guardar_offline()

            elif dados.startswith(b"SESSION:") or dados.startswith(b"MSG:") or dados.startswith(b"SESSION_INIT:") or dados.startswith(b"SESSION_ACK:"):
                if not clientes[conn].get('autenticado'): continue

                partes = dados.split(b":", 2)
                if len(partes) != 3:
                    enviar_mensagem(conn, construir_mensagem_controle("INFO", b"ERRO - Pacote malformado."))
                    continue

                destinatario_nome = partes[1].decode('utf-8', errors='strict')
                if not username_valido(destinatario_nome):
                    enviar_mensagem(conn, construir_mensagem_controle("INFO", b"ERRO - Destinatario invalido."))
                    continue

                if destinatario_nome == clientes[conn]['nome']:
                    enviar_mensagem(conn, construir_mensagem_controle("INFO", b"ERRO - Nao podes enviar mensagens para ti proprio."))
                    continue

                if dados.startswith(b"SESSION_INIT:"):
                    prefixo = b"SESSION_INIT:"
                elif dados.startswith(b"SESSION_ACK:"):
                    prefixo = b"SESSION_ACK:"
                elif dados.startswith(b"SESSION:"):
                    prefixo = b"SESSION:"
                else:
                    prefixo = b"MSG:"

                pacote_final = prefixo + clientes[conn]['nome'].encode('utf-8') + b":" + partes[2]
                enviado = False
                with clientes_lock:
                    destino_conn = next(
                        (c for c, info in clientes.items() if info['nome'] == destinatario_nome and info.get('autenticado')),
                        None
                    )
                if destino_conn:
                    enviar_mensagem(destino_conn, pacote_final)
                    enviado = True

                if not enviado:
                    if dados.startswith(b"SESSION_INIT:") or dados.startswith(b"SESSION_ACK:"):
                        enviar_mensagem(conn, construir_mensagem_controle("INFO", b"OFFLINE:" + destinatario_nome.encode('utf-8')))
                    else:
                        with offline_lock:
                            if destinatario_nome not in bd_offline:
                                bd_offline[destinatario_nome] = []
                            bd_offline[destinatario_nome].append(pacote_final.hex())
                            guardar_offline()
                        if dados.startswith(b"MSG:"):
                            enviar_mensagem(conn, construir_mensagem_controle("INFO", b"OFFLINE:" + destinatario_nome.encode('utf-8')))

        except Exception as e:
            print(f"Erro com {addr}: {e}")
            break

    print(f"Cliente desconectado: {addr}")
    with clientes_lock:
        if conn in clientes:
            del clientes[conn]
    conn.close()


def iniciar_servidor():
    carregar_base_dados()
    carregar_offline()
    carregar_grupos()
    inicializar_ca()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, porta))
    server.listen()
    print(f"Servidor à escuta em {host}:{porta}")

    while True:
        try:
            conn, addr = server.accept()
            thread = threading.Thread(target=lidar_com_clientes, args=(conn, addr))
            thread.start()
        except KeyboardInterrupt:
            print("\n A encerrar o servidor...")
            break

if __name__ == "__main__":
    iniciar_servidor()
