"""Modelo orientado a objetos da cifragem híbrida dos chamados (Entrega 1).

Classes:
    RepositorioChaves  gera, grava e carrega o par de chaves RSA do suporte.
    Envelope           representa o chamado cifrado (e o converte de/para JSON).
    Cliente            cifra um chamado usando a chave pública do suporte.
    Analista           decifra um envelope usando a chave privada do suporte.
    EnvelopeInvalido   erro lançado quando o envelope está malformado ou foi adulterado.

Toda a criptografia vem da biblioteca `cryptography`; nenhum algoritmo é próprio.
"""

import base64
import binascii
import json
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

VERSAO = 1
ALGORITMO = "RSA-OAEP-SHA256+AES-256-GCM"
TAMANHO_NONCE = 12  # 96 bits, o tamanho recomendado para o GCM
TAMANHO_CHAVE_RSA = 3072
EXPOENTE_PUBLICO = 65537
TAMANHO_MINIMO_SENHA = 12
CAMPOS_BINARIOS = ("chave_cifrada", "nonce", "texto_cifrado")


class EnvelopeInvalido(Exception):
    """Envelope malformado ou adulterado."""


def oaep() -> padding.OAEP:
    """Parâmetros do RSA-OAEP usados pelos dois lados (cliente e analista)."""
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


@dataclass
class RepositorioChaves:
    """Guarda e recupera o par de chaves RSA do suporte em uma pasta."""

    pasta: Path

    @property
    def privada(self) -> Path:
        return self.pasta / "suporte_privada.pem"

    @property
    def publica(self) -> Path:
        return self.pasta / "suporte_publica.pem"

    def gerar(self, senha: bytes, forcar: bool = False) -> None:
        """Gera o par RSA-3072. A chave privada é gravada cifrada com a senha."""
        if self.privada.exists() and not forcar:
            raise FileExistsError(f"{self.privada} já existe. Use --forcar.")
        if len(senha.decode("utf-8")) < TAMANHO_MINIMO_SENHA:
            raise ValueError(f"a senha deve ter pelo menos {TAMANHO_MINIMO_SENHA} caracteres")

        chave = rsa.generate_private_key(
            public_exponent=EXPOENTE_PUBLICO, key_size=TAMANHO_CHAVE_RSA
        )
        pem_privada = chave.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(senha),
        )
        pem_publica = chave.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        self.pasta.mkdir(parents=True, exist_ok=True)
        self.privada.write_bytes(pem_privada)
        self.publica.write_bytes(pem_publica)
        try:
            os.chmod(self.privada, 0o600)  # efeito limitado no Windows
        except OSError:
            pass

    def carregar_publica(self) -> rsa.RSAPublicKey:
        chave = serialization.load_pem_public_key(self.publica.read_bytes())
        if not isinstance(chave, rsa.RSAPublicKey) or chave.key_size < TAMANHO_CHAVE_RSA:
            raise ValueError("a chave pública do suporte deve ser RSA de pelo menos 3072 bits")
        return chave

    def carregar_privada(self, senha: bytes) -> rsa.RSAPrivateKey:
        try:
            chave = serialization.load_pem_private_key(self.privada.read_bytes(), password=senha)
        except ValueError as erro:
            raise ValueError("senha incorreta ou chave privada corrompida.") from erro
        if not isinstance(chave, rsa.RSAPrivateKey):
            raise ValueError("a chave privada não é RSA")
        return chave


@dataclass
class Envelope:
    """Chamado cifrado: cabeçalho legível + campos binários protegidos."""

    cabecalho: dict
    chave_cifrada: bytes
    nonce: bytes
    texto_cifrado: bytes  # texto cifrado || tag de autenticação (16 bytes)

    def aad(self) -> bytes:
        """Forma canônica do cabeçalho, usada como dados associados (AAD) do GCM."""
        return json.dumps(self.cabecalho, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def para_dict(self) -> dict:
        dados = {"cabecalho": self.cabecalho}
        for campo in CAMPOS_BINARIOS:
            dados[campo] = base64.b64encode(getattr(self, campo)).decode("ascii")
        return dados

    @classmethod
    def de_dict(cls, dados: dict) -> "Envelope":
        """Valida a estrutura do envelope; lança EnvelopeInvalido se algo estiver errado."""
        try:
            cabecalho = dados["cabecalho"]
            if not isinstance(cabecalho, dict):
                raise TypeError("cabeçalho inválido")
            if cabecalho.get("versao") != VERSAO or cabecalho.get("alg") != ALGORITMO:
                raise EnvelopeInvalido("versão ou algoritmo não suportado")
            chave_cifrada, nonce, texto_cifrado = (
                base64.b64decode(dados[campo], validate=True) for campo in CAMPOS_BINARIOS
            )
            if len(nonce) != TAMANHO_NONCE:
                raise EnvelopeInvalido("nonce com tamanho inválido")
            return cls(cabecalho, chave_cifrada, nonce, texto_cifrado)
        except (KeyError, TypeError, AttributeError, ValueError, binascii.Error) as erro:
            raise EnvelopeInvalido(f"envelope malformado ({erro!r})") from None


class Cliente:
    """Quem abre o chamado: só precisa da chave pública do suporte."""

    def __init__(self, chave_publica: rsa.RSAPublicKey):
        self.chave_publica = chave_publica

    def cifrar(self, texto: str) -> Envelope:
        if not texto.strip():
            raise ValueError("chamado vazio")
        cabecalho = {
            "versao": VERSAO,
            "alg": ALGORITMO,
            "id": str(uuid.uuid4()),
            "criado_em": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        chave_aes = AESGCM.generate_key(bit_length=256)  # nova a cada chamado
        envelope = Envelope(cabecalho, b"", os.urandom(TAMANHO_NONCE), b"")
        envelope.texto_cifrado = AESGCM(chave_aes).encrypt(
            envelope.nonce, texto.encode("utf-8"), envelope.aad()
        )
        envelope.chave_cifrada = self.chave_publica.encrypt(chave_aes, oaep())
        return envelope


class Analista:
    """Quem atende o chamado: possui a chave privada do suporte."""

    def __init__(self, chave_privada: rsa.RSAPrivateKey):
        self.chave_privada = chave_privada

    def decifrar(self, envelope: Envelope) -> str:
        try:
            chave_aes = self.chave_privada.decrypt(envelope.chave_cifrada, oaep())
        except ValueError:
            raise EnvelopeInvalido("falha ao decifrar a chave AES (RSA-OAEP)") from None
        try:
            texto = AESGCM(chave_aes).decrypt(envelope.nonce, envelope.texto_cifrado, envelope.aad())
            return texto.decode("utf-8")
        except (InvalidTag, ValueError, UnicodeDecodeError, TypeError):
            raise EnvelopeInvalido("falha na autenticação AES-GCM (tag inválida)") from None
