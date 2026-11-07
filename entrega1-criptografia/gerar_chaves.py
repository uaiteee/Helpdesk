"""Gera o par de chaves RSA-3072 do suporte.

- chaves/suporte_privada.pem : chave privada PKCS#8, cifrada com senha
- chaves/suporte_publica.pem : chave pública (SubjectPublicKeyInfo), distribuída aos clientes

A senha é lida da variável de ambiente HELPDESK_SENHA (útil para testes
automatizados) ou, se ela não existir, pedida no terminal sem eco.
"""

import argparse
import getpass
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

PASTA_CHAVES = Path(__file__).resolve().parent / "chaves"
ARQ_PRIVADA = PASTA_CHAVES / "suporte_privada.pem"
ARQ_PUBLICA = PASTA_CHAVES / "suporte_publica.pem"

TAMANHO_CHAVE = 3072
EXPOENTE_PUBLICO = 65537
TAMANHO_MINIMO_SENHA = 12


def obter_senha(confirmar: bool = False) -> bytes:
    """Lê a senha da variável HELPDESK_SENHA ou do terminal."""
    senha = os.environ.get("HELPDESK_SENHA")
    if senha is None:
        senha = getpass.getpass("Senha da chave privada: ")
        if confirmar and senha != getpass.getpass("Confirme a senha: "):
            sys.exit("Erro: as senhas não conferem.")
    return senha.encode("utf-8")


def gerar_par_de_chaves(senha: bytes) -> tuple[bytes, bytes]:
    """Retorna (pem_privada_cifrada, pem_publica)."""
    chave_privada = rsa.generate_private_key(
        public_exponent=EXPOENTE_PUBLICO, key_size=TAMANHO_CHAVE
    )
    pem_privada = chave_privada.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(senha),
    )
    pem_publica = chave_privada.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem_privada, pem_publica


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--forcar", action="store_true", help="sobrescreve chaves já existentes"
    )
    args = parser.parse_args()

    if ARQ_PRIVADA.exists() and not args.forcar:
        sys.exit(f"Erro: {ARQ_PRIVADA} já existe. Use --forcar para sobrescrever.")

    senha = obter_senha(confirmar=True)
    if len(senha) < TAMANHO_MINIMO_SENHA:
        sys.exit(f"Erro: a senha deve ter pelo menos {TAMANHO_MINIMO_SENHA} caracteres.")

    print(f"Gerando chave RSA de {TAMANHO_CHAVE} bits...")
    pem_privada, pem_publica = gerar_par_de_chaves(senha)

    PASTA_CHAVES.mkdir(exist_ok=True)
    ARQ_PRIVADA.write_bytes(pem_privada)
    ARQ_PUBLICA.write_bytes(pem_publica)
    try:
        os.chmod(ARQ_PRIVADA, 0o600)  # efeito limitado no Windows
    except OSError:
        pass

    print(f"Chave privada (cifrada): {ARQ_PRIVADA}")
    print(f"Chave pública:           {ARQ_PUBLICA}")


if __name__ == "__main__":
    main()
