"""Gera o par de chaves RSA do suporte."""
import argparse
import getpass
import os
from pathlib import Path
from helpdesk import RepositorioChaves

CHAVES = RepositorioChaves(Path(__file__).resolve().parent / "chaves")


def obter_senha(confirmar=False):
    senha = os.environ.get("HELPDESK_SENHA")
    if senha is None:
        senha = getpass.getpass("Senha da chave privada: ")
        if confirmar and senha != getpass.getpass("Confirme a senha: "):
            raise SystemExit("Erro: as senhas não conferem.")
    return senha.encode("utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--forcar", action="store_true")
    args = parser.parse_args()
    try:
        CHAVES.gerar(obter_senha(confirmar=True), args.forcar)
    except (FileExistsError, ValueError) as erro:
        raise SystemExit(f"Erro: {erro}") from None
    print(f"Chave privada (cifrada): {CHAVES.privada}")
    print(f"Chave pública:           {CHAVES.publica}")


if __name__ == "__main__":
    main()
