"""Cliente do helpdesk: cifra um chamado para o suporte (envelope híbrido).

1. Gera uma chave AES-256 aleatória e um nonce de 96 bits (únicos por chamado).
2. Cifra o texto com AES-256-GCM; o cabeçalho do envelope entra como AAD,
   então qualquer alteração nele também é detectada.
3. Cifra a chave AES com a chave pública RSA-3072 do suporte (RSA-OAEP/SHA-256).
4. Grava o envelope em JSON (campos binários em Base64).

Uso:
    python cliente.py "texto do chamado"
    python cliente.py                  (lê o texto do terminal)
    python cliente.py -s saida.json "texto"
"""

import argparse
import base64
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PASTA_BASE = Path(__file__).resolve().parent
ARQ_PUBLICA = PASTA_BASE / "chaves" / "suporte_publica.pem"
PASTA_CHAMADOS = PASTA_BASE / "chamados"

VERSAO = 1
ALGORITMO = "RSA-OAEP-SHA256+AES-256-GCM"
TAMANHO_NONCE = 12  # 96 bits, o recomendado para GCM


def oaep() -> padding.OAEP:
    """Parâmetros OAEP usados nos dois lados (cliente e analista)."""
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


def b64e(dados: bytes) -> str:
    return base64.b64encode(dados).decode("ascii")


def serializar_aad(cabecalho: dict) -> bytes:
    """Forma canônica do cabeçalho, usada como dados associados (AAD) do GCM."""
    return json.dumps(cabecalho, sort_keys=True, separators=(",", ":")).encode("utf-8")


def carregar_chave_publica(caminho: Path = ARQ_PUBLICA) -> rsa.RSAPublicKey:
    chave = serialization.load_pem_public_key(caminho.read_bytes())
    if not isinstance(chave, rsa.RSAPublicKey) or chave.key_size < 3072:
        raise ValueError("A chave pública do suporte deve ser RSA de pelo menos 3072 bits.")
    return chave


def cifrar_chamado(texto: str, chave_publica: rsa.RSAPublicKey) -> dict:
    """Cifra o texto e devolve o envelope (dicionário pronto para JSON)."""
    cabecalho = {
        "versao": VERSAO,
        "alg": ALGORITMO,
        "id": str(uuid.uuid4()),
        "criado_em": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }

    chave_aes = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(TAMANHO_NONCE)
    # O resultado é texto cifrado || tag de 16 bytes.
    cifrado = AESGCM(chave_aes).encrypt(nonce, texto.encode("utf-8"), serializar_aad(cabecalho))
    chave_cifrada = chave_publica.encrypt(chave_aes, oaep())

    return {
        "cabecalho": cabecalho,
        "chave_cifrada": b64e(chave_cifrada),
        "nonce": b64e(nonce),
        "texto_cifrado": b64e(cifrado),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Cifra um chamado para o suporte.")
    parser.add_argument("texto", nargs="?", help="texto do chamado")
    parser.add_argument("-s", "--saida", type=Path, help="arquivo de saída do envelope")
    args = parser.parse_args()

    texto = args.texto if args.texto is not None else input("Descreva o chamado: ")
    if not texto.strip():
        raise SystemExit("Erro: o chamado está vazio.")

    envelope = cifrar_chamado(texto, carregar_chave_publica())

    saida = args.saida or PASTA_CHAMADOS / f"chamado_{envelope['cabecalho']['id']}.json"
    saida.parent.mkdir(parents=True, exist_ok=True)
    saida.write_text(json.dumps(envelope, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Chamado cifrado salvo em: {saida}")


if __name__ == "__main__":
    main()
