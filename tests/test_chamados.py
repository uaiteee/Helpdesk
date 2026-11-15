"""Testes da integração: login obrigatório para abrir chamados e perfil de analista para lê-los."""

import json
import tempfile
import unittest
from pathlib import Path

from helpdesk.autenticacao import (ErroAutenticacao, HasherScrypt, RepositorioUsuarios,
                                   SemVerificacao, ServicoAutenticacao)
from helpdesk.chamados import AcessoNegado, ServicoChamados
from helpdesk.criptografia import EnvelopeInvalido, RepositorioChaves

SENHA = "uma senha bem longa 2026"
SENHA_CHAVE = b"senha-da-chave-12345"
TEXTO = "Meu computador não liga. Patrimônio 4521, sala 302."


class TestChamados(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._pasta = tempfile.TemporaryDirectory()
        cls.raiz = Path(cls._pasta.name)
        cls.chaves = RepositorioChaves(cls.raiz / "chaves")
        cls.chaves.gerar(SENHA_CHAVE)  # RSA-3072: gerado uma vez só

    @classmethod
    def tearDownClass(cls):
        cls._pasta.cleanup()

    def setUp(self):
        self.pasta = Path(tempfile.mkdtemp(dir=self.raiz))
        autenticacao = ServicoAutenticacao(
            RepositorioUsuarios(self.pasta / "u.db"), hasher=HasherScrypt(n=2**10),
            verificador=SemVerificacao())
        self.servico = ServicoChamados(autenticacao, self.chaves, self.pasta / "chamados")
        autenticacao.cadastrar("cliente1", SENHA)
        self.servico.cadastrar_analista("analista1", SENHA, SENHA_CHAVE)

    def _abrir(self):
        return self.servico.abrir("cliente1", SENHA, TEXTO)

    def test_abrir_exige_login(self):
        with self.assertRaises(ErroAutenticacao):
            self.servico.abrir("cliente1", "senha errada qualquer", TEXTO)
        self.assertFalse((self.pasta / "chamados").exists())

    def test_chamado_gravado_e_cifrado(self):
        arquivo = self._abrir()
        self.assertNotIn("computador", arquivo.read_text(encoding="utf-8"))

    def test_analista_le_o_chamado(self):
        arquivo = self._abrir()
        _, texto = self.servico.ler("analista1", SENHA, arquivo, lambda: SENHA_CHAVE)
        self.assertEqual(texto, TEXTO)

    def test_cliente_nao_le_e_a_senha_da_chave_nem_e_pedida(self):
        arquivo = self._abrir()
        pedida = []
        with self.assertRaises(AcessoNegado):
            self.servico.ler("cliente1", SENHA, arquivo, lambda: pedida.append(1) or SENHA_CHAVE)
        self.assertEqual(pedida, [])

    def test_senha_da_chave_errada(self):
        arquivo = self._abrir()
        with self.assertRaises(ValueError):
            self.servico.ler("analista1", SENHA, arquivo, lambda: b"outra-senha-errada")

    def test_chamado_adulterado_e_rejeitado(self):
        arquivo = self._abrir()
        dados = json.loads(arquivo.read_text(encoding="utf-8"))
        dados["cabecalho"]["id"] = "00000000-0000-0000-0000-000000000000"
        arquivo.write_text(json.dumps(dados), encoding="utf-8")
        with self.assertRaises(EnvelopeInvalido):
            self.servico.ler("analista1", SENHA, arquivo, lambda: SENHA_CHAVE)

    def test_criar_analista_exige_a_senha_da_chave(self):
        with self.assertRaises(AcessoNegado):
            self.servico.cadastrar_analista("analista2", SENHA, b"senha-errada-qualquer")
        self.assertIsNone(self.servico.autenticacao.repositorio.buscar("analista2"))


if __name__ == "__main__":
    unittest.main()
