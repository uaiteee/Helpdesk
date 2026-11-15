"""Locais dos arquivos e leitura de senhas (compartilhados pela linha de comando e pelos scripts)."""

import getpass
import os
from pathlib import Path

from helpdesk.criptografia import RepositorioChaves

RAIZ = Path(__file__).resolve().parent.parent
CHAVES = RepositorioChaves(RAIZ / "chaves")
PASTA_CHAMADOS = RAIZ / "chamados"
BANCO = Path(os.environ.get("HELPDESK_BANCO", RAIZ / "dados" / "usuarios.db"))


def obter_senha_chave(confirmar: bool = False) -> bytes:
    """Senha da chave privada do suporte (variável HELPDESK_SENHA ou digitada sem eco)."""
    senha = os.environ.get("HELPDESK_SENHA")
    if senha is None:
        senha = getpass.getpass("Senha da chave privada: ")
        if confirmar and senha != getpass.getpass("Confirme a senha: "):
            raise SystemExit("Erro: as senhas não conferem.")
    return senha.encode("utf-8")


def obter_senha_usuario(confirmar: bool = False) -> str:
    """Senha de login do usuário (variável HELPDESK_SENHA_PORTAL ou digitada sem eco)."""
    senha = os.environ.get("HELPDESK_SENHA_PORTAL")
    if senha is not None:
        return senha
    senha = getpass.getpass("Senha do usuário: ")
    if confirmar and getpass.getpass("Repita a senha: ") != senha:
        raise SystemExit("Erro: as senhas não conferem.")
    return senha
