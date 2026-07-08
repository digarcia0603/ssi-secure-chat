import os
import getpass

from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from pki import gerar_certificado_ca, emitir_certificado_utilizador, verificar_certificado_utilizador
from protocolo import (
    construir_payload_controle_servidor,
    construir_payload_group_msg,
    construir_payload_session_init,
    construir_payload_session_ack,
    construir_contexto_hkdf,
)


def carregar_ou_gerar_identidade_rsa(nome):
    ficheiro_priv = f"{nome}_privada.pem"
    ficheiro_pub = f"{nome}_publica.pem"

    if os.path.exists(ficheiro_priv) and os.path.exists(ficheiro_pub):
        print(f"Identidade local encontrada para o utilizador '{nome}'.")
        password = getpass.getpass("Introduz a tua password para destrancar a chave privada: ").encode("utf-8")

        try:
            with open(ficheiro_priv, "rb") as f:
                chave_privada = serialization.load_pem_private_key(f.read(), password=password)
            with open(ficheiro_pub, "rb") as f:
                chave_publica_bytes = f.read()
            print("Identidade carregada e destrancada com sucesso!")
            return chave_privada, chave_publica_bytes
        except ValueError:
            print("ERRO: Password incorreta! Acesso negado à identidade.")
            os._exit(1)
        except Exception as e:
            print(f"Erro a carregar as chaves: {e}")
            os._exit(1)

    print(f"Nenhuma identidade encontrada para '{nome}'. A gerar nova...")
    password = getpass.getpass("Cria uma password para proteger a tua nova chave: ").encode("utf-8")

    chave_privada = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    chave_publica_bytes = chave_privada.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    with open(ficheiro_priv, "wb") as f:
        f.write(chave_privada.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password),
        ))
    with open(ficheiro_pub, "wb") as f:
        f.write(chave_publica_bytes)

    os.chmod(ficheiro_priv, 0o600)
    print(f"Nova identidade gerada e guardada em '{ficheiro_priv}' e '{ficheiro_pub}'!")
    return chave_privada, chave_publica_bytes


def embrulhar_chave_aes(chave_aes, chave_publica_pem_do_outro):
    chave_publica = serialization.load_pem_public_key(chave_publica_pem_do_outro)
    return chave_publica.encrypt(
        chave_aes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

def desembrulhar_chave_aes(chave_cifrada, minha_privada):
    return minha_privada.decrypt(
        chave_cifrada,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def assinar_mensagem(dados, minha_chave_privada):
    return minha_chave_privada.sign(
        dados,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

def verificar_assinatura(dados, assinatura, chave_publica_pem):
    chave_publica = serialization.load_pem_public_key(chave_publica_pem)
    chave_publica.verify(
        assinatura,
        dados,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def cifrar_mensagem(texto_bytes, chave_aes):
    nonce = os.urandom(12)
    ciphertext = AESGCM(chave_aes).encrypt(nonce, texto_bytes, None)
    return nonce, ciphertext

def decifrar_mensagem(nonce, ciphertext, chave_aes):
    return AESGCM(chave_aes).decrypt(nonce, ciphertext, None)


def gerar_par_efemero():
    priv = X25519PrivateKey.generate()
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv, pub_bytes

def derivar_chave_aes(minha_priv_efemera, pub_bytes_outro, contexto=b""):
    pub_outro = X25519PublicKey.from_public_bytes(pub_bytes_outro)
    segredo_partilhado = minha_priv_efemera.exchange(pub_outro)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"chat-e2ee-session|" + contexto,
    ).derive(segredo_partilhado)
