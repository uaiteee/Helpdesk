"""Linha de comando do Helpdesk.

    python -m helpdesk gerar-chaves [--forcar]
    python -m helpdesk cadastrar <usuario> [--analista] [--offline]
    python -m helpdesk abrir-chamado <usuario> ["texto"] [-s arquivo]
    python -m helpdesk ler-chamado <usuario> <arquivo.json>
    python -m helpdesk banco
"""

import argparse
import json
from pathlib import Path

from helpdesk.autenticacao import (ErroAutenticacao, PwnedPasswords, RepositorioUsuarios,
                                   SemVerificacao, ServicoAutenticacao)
from helpdesk.chamados import ServicoChamados
from helpdesk.config import (BANCO, CHAVES, PASTA_CHAMADOS, obter_senha_chave,
                             obter_senha_usuario)
from helpdesk.criptografia import EnvelopeInvalido


def criar_servicos(offline: bool = False):
    verificador = SemVerificacao() if offline else PwnedPasswords()
    autenticacao = ServicoAutenticacao(RepositorioUsuarios(BANCO), verificador=verificador)
    return autenticacao, ServicoChamados(autenticacao, CHAVES, PASTA_CHAMADOS)


def cmd_gerar_chaves(args):
    try:
        CHAVES.gerar(obter_senha_chave(confirmar=True), args.forcar)
    except (FileExistsError, ValueError) as erro:
        raise SystemExit(f"Erro: {erro}") from None
    print(f"Chave privada (cifrada): {CHAVES.privada}")
    print(f"Chave pública:           {CHAVES.publica}")


def cmd_cadastrar(args):
    autenticacao, chamados = criar_servicos(args.offline)
    senha = obter_senha_usuario(confirmar=True)
    if args.analista:
        chamados.cadastrar_analista(args.usuario, senha, obter_senha_chave())
    else:
        autenticacao.cadastrar(args.usuario, senha)
    print(f"Usuário '{args.usuario.lower()}' cadastrado ({'analista' if args.analista else 'cliente'}).")


def cmd_abrir_chamado(args):
    _, chamados = criar_servicos(offline=True)
    senha = obter_senha_usuario()
    texto = args.texto if args.texto is not None else input("Descreva o chamado: ")
    try:
        saida = chamados.abrir(args.usuario, senha, texto, args.saida)
    except ValueError as erro:
        raise SystemExit(f"Erro: {erro}") from None
    print(f"Chamado cifrado salvo em: {saida}")


def cmd_ler_chamado(args):
    _, chamados = criar_servicos(offline=True)
    senha = obter_senha_usuario()
    try:
        envelope, texto = chamados.ler(args.usuario, senha, args.arquivo, obter_senha_chave)
    except (OSError, json.JSONDecodeError, EnvelopeInvalido) as erro:
        raise SystemExit(f"Chamado REJEITADO: {erro}") from None
    except ValueError as erro:
        raise SystemExit(f"Erro: {erro}") from None
    print(f"Chamado {envelope.cabecalho['id']} (criado em {envelope.cabecalho['criado_em']})")
    print("-" * 60)
    print(texto)


def cmd_banco(_args):
    """Mostra o que fica gravado: nenhum campo contém a senha."""
    usuarios = RepositorioUsuarios(BANCO).listar()
    if not usuarios:
        print("Banco vazio.")
    for u in usuarios:
        print(f"usuario : {u.nome} ({u.perfil})")
        print(f"salt    : {u.salt.hex()}")
        print(f"hash    : {u.hash_senha.hex()}")
        print(f"scrypt  : N={u.n} r={u.r} p={u.p}")
        print(f"falhas  : {u.falhas}\n")


def montar_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m helpdesk", description="Helpdesk Corporativo")
    sub = parser.add_subparsers(dest="comando", required=True)

    p = sub.add_parser("gerar-chaves", help="gera o par de chaves RSA do suporte")
    p.add_argument("--forcar", action="store_true", help="sobrescreve chaves existentes")
    p.set_defaults(funcao=cmd_gerar_chaves)

    p = sub.add_parser("cadastrar", help="cria um usuário")
    p.add_argument("usuario")
    p.add_argument("--analista", action="store_true", help="cria um analista (pede a senha da chave privada)")
    p.add_argument("--offline", action="store_true", help="não consulta a API de senhas vazadas")
    p.set_defaults(funcao=cmd_cadastrar)

    p = sub.add_parser("abrir-chamado", help="cifra um chamado (exige login)")
    p.add_argument("usuario")
    p.add_argument("texto", nargs="?")
    p.add_argument("-s", "--saida", type=Path)
    p.set_defaults(funcao=cmd_abrir_chamado)

    p = sub.add_parser("ler-chamado", help="decifra um chamado (exige login de analista)")
    p.add_argument("usuario")
    p.add_argument("arquivo", type=Path)
    p.set_defaults(funcao=cmd_ler_chamado)

    p = sub.add_parser("banco", help="mostra os registros gravados")
    p.set_defaults(funcao=cmd_banco)
    return parser


def main(argv=None):
    args = montar_parser().parse_args(argv)
    try:
        args.funcao(args)
    except ErroAutenticacao as erro:
        raise SystemExit(f"Erro: {erro}") from None
