import datetime

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

def _validade_certificado(certificado):
    try:
        return certificado.not_valid_before_utc, certificado.not_valid_after_utc
    except AttributeError:
        return (
            certificado.not_valid_before.replace(tzinfo=datetime.timezone.utc),
            certificado.not_valid_after.replace(tzinfo=datetime.timezone.utc),
        )

def gerar_certificado_ca():
    chave_privada_ca = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    nome_ca = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"Chat CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"SSI Chat Server"),
    ])

    agora = datetime.datetime.now(datetime.timezone.utc)
    certificado_ca = (
        x509.CertificateBuilder()
        .subject_name(nome_ca)
        .issuer_name(nome_ca)
        .public_key(chave_privada_ca.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(agora)
        .not_valid_after(agora + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(chave_privada_ca, hashes.SHA256())
    )
    return chave_privada_ca, certificado_ca

def emitir_certificado_utilizador(nome, chave_publica_pem, chave_privada_ca, certificado_ca):
    chave_publica = serialization.load_pem_public_key(chave_publica_pem)
    agora = datetime.datetime.now(datetime.timezone.utc)

    certificado = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, nome)]))
        .issuer_name(certificado_ca.subject)
        .public_key(chave_publica)
        .serial_number(x509.random_serial_number())
        .not_valid_before(agora)
        .not_valid_after(agora + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(chave_privada_ca, hashes.SHA256())
    )
    return certificado.public_bytes(serialization.Encoding.PEM)

def verificar_certificado_utilizador(certificado_pem, certificado_ca):
    certificado = x509.load_pem_x509_certificate(certificado_pem)

    certificado_ca.public_key().verify(
        certificado.signature,
        certificado.tbs_certificate_bytes,
        padding.PKCS1v15(),
        certificado.signature_hash_algorithm,
    )

    agora = datetime.datetime.now(datetime.timezone.utc)
    not_before, not_after = _validade_certificado(certificado)
    if agora < not_before or agora > not_after:
        raise ValueError("Certificado fora do período de validade.")

    nome = certificado.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    chave_publica_pem = certificado.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return nome, chave_publica_pem

def fingerprint_ca(certificado):
    return certificado.fingerprint(hashes.SHA256())

def fingerprint_ca_hex(certificado):
    return fingerprint_ca(certificado).hex()

def validar_certificado_ca(certificado):
    agora = datetime.datetime.now(datetime.timezone.utc)
    not_before, not_after = _validade_certificado(certificado)
    if agora < not_before or agora > not_after:
        raise ValueError("certificado da CA fora do período de validade")

    basic_constraints = certificado.extensions.get_extension_for_class(x509.BasicConstraints).value
    if not basic_constraints.ca:
        raise ValueError("certificado recebido não está marcado como CA")

    if certificado.subject != certificado.issuer:
        raise ValueError("certificado da CA não é self-signed")

    certificado.public_key().verify(
        certificado.signature,
        certificado.tbs_certificate_bytes,
        padding.PKCS1v15(),
        certificado.signature_hash_algorithm,
    )
