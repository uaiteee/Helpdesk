"""Une as Entregas 1 e 2: só usuários autenticados abrem chamados, e só analistas os leem."""

import json
from pathlib import Path

from helpdesk.autenticacao import ErroAutenticacao, ServicoAutenticacao
from helpdesk.criptografia import Analista, Cliente, Envelope, RepositorioChaves


class AcessoNegado(ErroAutenticacao):
    """O usuário autenticado não tem permissão para a operação."""


class ServicoChamados:
    def __init__(self, autenticacao: ServicoAutenticacao, chaves: RepositorioChaves, pasta: Path):
        self.autenticacao = autenticacao
        self.chaves = chaves
        self.pasta = Path(pasta)

    def abrir(self, nome: str, senha: str, texto: str, saida: Path = None) -> Path:
        """Qualquer usuário autenticado cifra um chamado com a chave pública do suporte."""
        self.autenticacao.autenticar(nome, senha)
        envelope = Cliente(self.chaves.carregar_publica()).cifrar(texto)
        saida = Path(saida) if saida else self.pasta / f"chamado_{envelope.cabecalho['id']}.json"
        saida.parent.mkdir(parents=True, exist_ok=True)
        saida.write_text(json.dumps(envelope.para_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
        return saida

    def ler(self, nome: str, senha: str, arquivo: Path, pedir_senha_chave) -> tuple[Envelope, str]:
        """Só analistas leem. `pedir_senha_chave` é chamada somente depois da autorização.

        Lança EnvelopeInvalido se o chamado foi adulterado ou está malformado.
        """
        usuario = self.autenticacao.autenticar(nome, senha)
        if usuario.perfil != "analista":
            raise AcessoNegado("apenas analistas podem ler chamados")
        envelope = Envelope.de_dict(json.loads(Path(arquivo).read_text(encoding="utf-8")))
        analista = Analista(self.chaves.carregar_privada(pedir_senha_chave()))
        return envelope, analista.decifrar(envelope)

    def cadastrar_analista(self, nome: str, senha: str, senha_chave: bytes) -> None:
        """Criar um analista exige a senha da chave privada do suporte (quem a possui administra)."""
        try:
            self.chaves.carregar_privada(senha_chave)
        except ValueError:
            raise AcessoNegado("senha da chave privada incorreta") from None
        self.autenticacao.cadastrar(nome, senha, perfil="analista")
