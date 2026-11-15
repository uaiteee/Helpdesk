"""Portal de linha de comando do Helpdesk (Entrega 2).

Uso:
    python portal.py cadastrar <usuario> [--offline]
    python portal.py entrar <usuario>
    python portal.py banco

A senha é sempre pedida sem aparecer na tela (getpass). Para automatizar,
defina a variável de ambiente HELPDESK_SENHA_PORTAL.
"""

import argparse
import getpass
import os
import sys
from pathlib import Path

from autenticacao import (ErroAutenticacao, PwnedPasswords, RepositorioUsuarios,
                          SemVerificacao, ServicoAutenticacao)

BANCO_PADRAO = Path(__file__).parent / "dados" / "usuarios.db"


def ler_senha(confirmar: bool = False) -> str:
    senha = os.environ.get("HELPDESK_SENHA_PORTAL")
    if senha is not None:
        return senha
    senha = getpass.getpass("Senha: ")
    if confirmar and getpass.getpass("Repita a senha: ") != senha:
        raise SystemExit("As senhas não conferem.")
    return senha


def mostrar_banco(repositorio: RepositorioUsuarios) -> None:
    """Mostra o que realmente fica gravado: nenhum campo contém a senha."""
    usuarios = repositorio.listar()
    if not usuarios:
        print("Banco vazio.")
        return
    for u in usuarios:
        print(f"usuario : {u.nome}")
        print(f"salt    : {u.salt.hex()}")
        print(f"hash    : {u.hash_senha.hex()}")
        print(f"scrypt  : N={u.n} r={u.r} p={u.p}")
        print(f"falhas  : {u.falhas}")
        print()


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description="Portal do Helpdesk (cadastro e login)")
    parser.add_argument("--banco", type=Path,
                        default=Path(os.environ.get("HELPDESK_BANCO", BANCO_PADRAO)))
    sub = parser.add_subparsers(dest="comando", required=True)
    cad = sub.add_parser("cadastrar", help="cria um usuário")
    cad.add_argument("usuario")
    cad.add_argument("--offline", action="store_true",
                     help="não consulta a API de senhas vazadas")
    ent = sub.add_parser("entrar", help="faz login")
    ent.add_argument("usuario")
    sub.add_parser("banco", help="mostra os registros gravados")
    args = parser.parse_args(argv)

    repositorio = RepositorioUsuarios(args.banco)
    if args.comando == "banco":
        mostrar_banco(repositorio)
        return

    verificador = SemVerificacao() if getattr(args, "offline", False) else PwnedPasswords()
    servico = ServicoAutenticacao(repositorio, verificador=verificador)
    try:
        if args.comando == "cadastrar":
            servico.cadastrar(args.usuario, ler_senha(confirmar="HELPDESK_SENHA_PORTAL" not in os.environ))
            print(f"Usuário '{args.usuario.lower()}' cadastrado.")
        else:
            servico.autenticar(args.usuario, ler_senha())
            print(f"Login realizado: {args.usuario.lower()}")
    except ErroAutenticacao as erro:
        sys.exit(f"Erro: {erro}")


if __name__ == "__main__":
    main()
