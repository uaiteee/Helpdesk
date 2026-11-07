"""Analista do suporte: decifra um envelope de chamado com a chave privada.

1. Abre a chave privada (PEM cifrado) com a senha.
2. Recupera a chave AES com RSA-OAEP/SHA-256.
3. Decifra com AES-256-GCM, usando o cabeçalho como AAD. Se qualquer parte
   do envelope tiver sido alterada, a verificação da tag falha e nada é exibido.

Uso:
    python analista.py chamados/chamado_<id>.json
"""

import argparse
import base64
import binascii
import json
import sys
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cliente import ALGORITMO, TAMANHO_NONCE, VERSAO, oaep, serializar_aad
from gerar_chaves import ARQ_PRIVADA, obter_senha


class EnvelopeInvalido(Exception):
    """O envelope está malformado, foi adulterado ou não é para esta chave."""


def b64d(texto: str) -> bytes:
    return base64.b64decode(texto, validate=True)


def carregar_chave_privada(senha: bytes, caminho: Path = ARQ_PRIVADA) -> rsa.RSAPrivateKey:
    try:
        chave = serialization.load_pem_private_key(caminho.read_bytes(), password=senha)
    except ValueError:
        raise SystemExit("Erro: senha incorreta ou chave privada corrompida.")
    if not isinstance(chave, rsa.RSAPrivateKey):
        raise SystemExit("Erro: a chave privada não é RSA.")
    return chave


def decifrar_chamado(envelope: dict, chave_privada: rsa.RSAPrivateKey) -> str:
    """Valida e decifra o envelope. Lança EnvelopeInvalido em qualquer falha."""
    try:
        cabecalho = envelope["cabecalho"]
        if cabecalho.get("versao") != VERSAO or cabecalho.get("alg") != ALGORITMO:
            raise EnvelopeInvalido("versão ou algoritmo não suportado")
        chave_cifrada = b64d(envelope["chave_cifrada"])
        nonce = b64d(envelope["nonce"])
        cifrado = b64d(envelope["texto_cifrado"])
    except (KeyError, TypeError, AttributeError, ValueError, binascii.Error) as erro:
        raise EnvelopeInvalido(f"envelope malformado ({erro!r})") from None

    if len(nonce) != TAMANHO_NONCE:
        raise EnvelopeInvalido("nonce com tamanho inválido")

    try:
        chave_aes = chave_privada.decrypt(chave_cifrada, oaep())
    except ValueError:
        raise EnvelopeInvalido("falha ao decifrar a chave AES (RSA-OAEP)") from None

    try:
        texto = AESGCM(chave_aes).decrypt(nonce, cifrado, serializar_aad(cabecalho))
    except (InvalidTag, ValueError):
        raise EnvelopeInvalido("falha na autenticação AES-GCM (tag inválida)") from None

    return texto.decode("utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Decifra um chamado do helpdesk.")
    parser.add_argument("envelope", type=Path, help="arquivo JSON do chamado")
    args = parser.parse_args()

    try:
        envelope = json.loads(args.envelope.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as erro:
        sys.exit(f"Erro ao ler o envelope: {erro}")

    chave_privada = carregar_chave_privada(obter_senha())
    try:
        texto = decifrar_chamado(envelope, chave_privada)
    except EnvelopeInvalido as erro:
        sys.exit(f"Chamado REJEITADO: {erro}")

    cab = envelope["cabecalho"]
    print(f"Chamado {cab['id']} (criado em {cab['criado_em']})")
    print("-" * 60)
    print(texto)


if __name__ == "__main__":
    main()
