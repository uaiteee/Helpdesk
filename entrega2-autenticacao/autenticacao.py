"""Cadastro e autenticação de usuários com scrypt (Entrega 2).

A senha nunca é gravada: o banco guarda apenas o salt aleatório e o hash
derivado pelo scrypt, junto com os parâmetros usados.

Classes (cada uma com uma responsabilidade):
    Usuario                 registro de um usuário (sem a senha).
    PoliticaSenha           regras de tamanho da senha.
    HasherScrypt            deriva e verifica hashes com scrypt (hashlib).
    VerificadorVazamentos   interface para checar senhas vazadas.
      PwnedPasswords        implementação via API Pwned Passwords (k-anonymity).
      SemVerificacao        não verifica (uso offline ou em testes).
    RepositorioUsuarios     persistência em SQLite.
    PoliticaBloqueio        bloqueio temporário após falhas consecutivas.
    ServicoAutenticacao     junta tudo: cadastrar() e autenticar().
"""

import hashlib
import hmac
import os
import re
import sqlite3
import time
import unicodedata
import urllib.request
from abc import ABC, abstractmethod
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path


class ErroAutenticacao(Exception):
    """Cadastro ou autenticação recusados."""


class UsuarioDuplicado(Exception):
    """Já existe um usuário com esse nome (lançado pelo repositório)."""


@dataclass(frozen=True)
class Usuario:
    """Registro guardado no banco. Não existe campo para a senha."""

    nome: str
    salt: bytes
    hash_senha: bytes
    n: int
    r: int
    p: int
    falhas: int = 0
    bloqueado_ate: float = 0.0


class PoliticaSenha:
    """Regras de tamanho da senha, sem exigência de composição (ASVS 6.2)."""

    TAMANHO_MINIMO = 12
    TAMANHO_MAXIMO = 1024  # evita que senhas enormes sejam usadas para sobrecarregar o servidor

    def validar(self, senha: str) -> None:
        if len(senha) < self.TAMANHO_MINIMO:
            raise ErroAutenticacao(f"a senha deve ter pelo menos {self.TAMANHO_MINIMO} caracteres")
        if len(senha) > self.TAMANHO_MAXIMO:
            raise ErroAutenticacao("senha muito longa")


class HasherScrypt:
    """Deriva e verifica hashes de senha com scrypt (hashlib.scrypt, da biblioteca padrão).

    Parâmetros padrão: N=2**17, r=8, p=1, o mínimo recomendado pela OWASP para
    scrypt (usa cerca de 128 MiB de memória por verificação). Salt de 16 bytes
    aleatórios por usuário e hash de 32 bytes.
    """

    def __init__(self, n: int = 2**17, r: int = 8, p: int = 1,
                 tamanho_salt: int = 16, tamanho_hash: int = 32):
        self.n, self.r, self.p = n, r, p
        self.tamanho_salt = tamanho_salt
        self.tamanho_hash = tamanho_hash

    @staticmethod
    def _preparar(senha: str) -> bytes:
        # NFKC: a mesma senha digitada com formas Unicode diferentes gera o mesmo hash.
        return unicodedata.normalize("NFKC", senha).encode("utf-8")

    def derivar(self, senha: str, salt: bytes, n: int = None, r: int = None, p: int = None) -> bytes:
        n, r, p = n or self.n, r or self.r, p or self.p
        return hashlib.scrypt(
            self._preparar(senha), salt=salt, n=n, r=r, p=p,
            dklen=self.tamanho_hash, maxmem=2 * 128 * n * r + 2**20,
        )

    def novo_hash(self, senha: str) -> tuple[bytes, bytes]:
        """Gera um salt aleatório e devolve (salt, hash)."""
        salt = os.urandom(self.tamanho_salt)
        return salt, self.derivar(senha, salt)

    def verificar(self, senha: str, usuario: Usuario) -> bool:
        """Recalcula o hash com os parâmetros guardados e compara em tempo constante."""
        calculado = self.derivar(senha, usuario.salt, usuario.n, usuario.r, usuario.p)
        return hmac.compare_digest(calculado, usuario.hash_senha)

    def gastar_tempo(self, senha: str) -> None:
        """Faz o mesmo trabalho de uma verificação, para usuários que não existem."""
        self.derivar(senha, b"\0" * self.tamanho_salt)


class VerificadorVazamentos(ABC):
    """Decide se uma senha já apareceu em vazamentos conhecidos."""

    @abstractmethod
    def foi_vazada(self, senha: str) -> bool:
        ...


class SemVerificacao(VerificadorVazamentos):
    """Não consulta nada (modo offline e testes)."""

    def foi_vazada(self, senha: str) -> bool:
        return False


class PwnedPasswords(VerificadorVazamentos):
    """Consulta a API Pwned Passwords por k-anonymity.

    Apenas os 5 primeiros caracteres do SHA-1 da senha saem do computador. O
    SHA-1 é usado só porque a API o exige; não protege nenhuma senha.
    """

    URL = "https://api.pwnedpasswords.com/range/"

    def __init__(self, timeout: float = 8.0):
        self.timeout = timeout

    def foi_vazada(self, senha: str) -> bool:
        digest = hashlib.sha1(senha.encode("utf-8"), usedforsecurity=False).hexdigest().upper()
        prefixo, sufixo = digest[:5], digest[5:]
        pedido = urllib.request.Request(
            self.URL + prefixo,
            headers={"User-Agent": "Helpdesk-Entrega2", "Add-Padding": "true"},
        )
        try:
            with urllib.request.urlopen(pedido, timeout=self.timeout) as resposta:
                linhas = resposta.read().decode("ascii").splitlines()
        except (OSError, UnicodeError):
            raise ErroAutenticacao(
                "não foi possível verificar senhas vazadas; tente novamente ou use --offline"
            ) from None
        for linha in linhas:
            hash_sufixo, _, contagem = linha.partition(":")
            # Com "Add-Padding" a API inclui linhas falsas com contagem 0: ignorá-las.
            if hash_sufixo.strip() == sufixo and contagem.strip() not in ("", "0"):
                return True
        return False


class RepositorioUsuarios:
    """Guarda os usuários em um banco SQLite."""

    def __init__(self, caminho: Path):
        self.caminho = Path(caminho)
        self.caminho.parent.mkdir(parents=True, exist_ok=True)
        with self._conectar() as conexao:
            conexao.execute(
                """CREATE TABLE IF NOT EXISTS usuarios (
                       usuario TEXT PRIMARY KEY,
                       salt BLOB NOT NULL,
                       hash BLOB NOT NULL,
                       n INTEGER NOT NULL, r INTEGER NOT NULL, p INTEGER NOT NULL,
                       falhas INTEGER NOT NULL DEFAULT 0,
                       bloqueado_ate REAL NOT NULL DEFAULT 0
                   )"""
            )

    def _conectar(self):
        """Conexão que confirma (commit) ao sair do bloco `with` e sempre fecha."""
        conexao = sqlite3.connect(self.caminho, timeout=10)
        return _Transacao(conexao)

    @staticmethod
    def _para_usuario(linha) -> Usuario:
        return Usuario(*linha)

    def inserir(self, usuario: Usuario) -> None:
        try:
            with self._conectar() as conexao:
                conexao.execute(
                    "INSERT INTO usuarios (usuario, salt, hash, n, r, p) VALUES (?, ?, ?, ?, ?, ?)",
                    (usuario.nome, usuario.salt, usuario.hash_senha, usuario.n, usuario.r, usuario.p),
                )
        except sqlite3.IntegrityError:
            raise UsuarioDuplicado(usuario.nome) from None

    def buscar(self, nome: str):
        with self._conectar() as conexao:
            linha = conexao.execute(
                "SELECT usuario, salt, hash, n, r, p, falhas, bloqueado_ate FROM usuarios WHERE usuario=?",
                (nome,),
            ).fetchone()
        return self._para_usuario(linha) if linha else None

    def atualizar_falhas(self, nome: str, falhas: int, bloqueado_ate: float) -> None:
        with self._conectar() as conexao:
            conexao.execute(
                "UPDATE usuarios SET falhas=?, bloqueado_ate=? WHERE usuario=?",
                (falhas, bloqueado_ate, nome),
            )

    def listar(self) -> list:
        with self._conectar() as conexao:
            linhas = conexao.execute(
                "SELECT usuario, salt, hash, n, r, p, falhas, bloqueado_ate FROM usuarios ORDER BY usuario"
            ).fetchall()
        return [self._para_usuario(linha) for linha in linhas]


class _Transacao:
    """Envolve a conexão SQLite: commit se tudo der certo, rollback se houver erro, e fecha."""

    def __init__(self, conexao: sqlite3.Connection):
        self.conexao = conexao

    def __enter__(self) -> sqlite3.Connection:
        return self.conexao

    def __exit__(self, tipo, valor, traceback) -> bool:
        with closing(self.conexao):
            if tipo is None:
                self.conexao.commit()
            else:
                self.conexao.rollback()
        return False


class PoliticaBloqueio:
    """Bloqueia a conta por um tempo após falhas consecutivas."""

    MAX_TENTATIVAS = 5
    BLOQUEIO_SEGUNDOS = 300

    def esta_bloqueado(self, usuario: Usuario, agora: float) -> bool:
        return usuario.bloqueado_ate > agora

    def registrar_falha(self, usuario: Usuario, agora: float) -> tuple[int, float]:
        """Devolve (falhas, bloqueado_ate) depois de mais uma falha."""
        falhas = usuario.falhas + 1
        if falhas >= self.MAX_TENTATIVAS:
            return 0, agora + self.BLOQUEIO_SEGUNDOS
        return falhas, 0.0


class ServicoAutenticacao:
    """Cadastro e login. Recebe suas dependências, o que facilita os testes."""

    PADRAO_USUARIO = re.compile(r"[A-Za-z0-9._-]{3,64}")

    def __init__(self, repositorio: RepositorioUsuarios, hasher: HasherScrypt = None,
                 verificador: VerificadorVazamentos = None, politica_senha: PoliticaSenha = None,
                 politica_bloqueio: PoliticaBloqueio = None, relogio=time.time):
        self.repositorio = repositorio
        self.hasher = hasher or HasherScrypt()
        self.verificador = verificador or PwnedPasswords()
        self.politica_senha = politica_senha or PoliticaSenha()
        self.politica_bloqueio = politica_bloqueio or PoliticaBloqueio()
        self.relogio = relogio

    def _normalizar_usuario(self, nome: str) -> str:
        if not self.PADRAO_USUARIO.fullmatch(nome):
            raise ErroAutenticacao(
                "usuário deve ter 3 a 64 caracteres: letras, números, ponto, _ ou -"
            )
        return nome.lower()  # "Alice" e "alice" são o mesmo usuário

    def cadastrar(self, nome: str, senha: str) -> None:
        nome = self._normalizar_usuario(nome)
        self.politica_senha.validar(senha)
        if self.verificador.foi_vazada(senha):
            raise ErroAutenticacao("esta senha aparece em vazamentos; escolha outra")
        salt, derivado = self.hasher.novo_hash(senha)
        try:
            self.repositorio.inserir(
                Usuario(nome, salt, derivado, self.hasher.n, self.hasher.r, self.hasher.p)
            )
        except UsuarioDuplicado:
            raise ErroAutenticacao("usuário já cadastrado") from None

    def autenticar(self, nome: str, senha: str) -> bool:
        """Devolve True se o login estiver correto; caso contrário lança ErroAutenticacao.

        A mensagem de erro é a mesma para usuário inexistente e senha errada,
        para não revelar quais usuários existem.
        """
        agora = self.relogio()
        usuario = self.repositorio.buscar(nome.lower())
        if usuario is None:
            self.hasher.gastar_tempo(senha[: self.politica_senha.TAMANHO_MAXIMO])
            raise ErroAutenticacao("credenciais inválidas")
        if self.politica_bloqueio.esta_bloqueado(usuario, agora):
            raise ErroAutenticacao("acesso temporariamente bloqueado")

        correta = (
            len(senha) <= self.politica_senha.TAMANHO_MAXIMO
            and self.hasher.verificar(senha, usuario)
        )
        if not correta:
            falhas, bloqueado_ate = self.politica_bloqueio.registrar_falha(usuario, agora)
            self.repositorio.atualizar_falhas(usuario.nome, falhas, bloqueado_ate)
            raise ErroAutenticacao("credenciais inválidas")

        if usuario.falhas or usuario.bloqueado_ate:
            self.repositorio.atualizar_falhas(usuario.nome, 0, 0.0)
        return True
