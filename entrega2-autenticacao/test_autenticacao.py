"""Testes da Entrega 2. Executar: python -m unittest -v

Os testes usam scrypt com N pequeno (rápido) e relógio falso; um teste
confere que o padrão de produção segue o mínimo da OWASP.
"""

import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from autenticacao import (ErroAutenticacao, HasherScrypt, PoliticaBloqueio, PwnedPasswords,
                          RepositorioUsuarios, SemVerificacao, ServicoAutenticacao,
                          VerificadorVazamentos)

SENHA = "uma senha bem longa 2026"


class Vazadas(VerificadorVazamentos):
    def foi_vazada(self, senha):
        return True


class Relogio:
    def __init__(self):
        self.agora = 1000.0

    def __call__(self):
        return self.agora


class BaseTeste(unittest.TestCase):
    def setUp(self):
        self._pasta = tempfile.TemporaryDirectory()
        self.addCleanup(self._pasta.cleanup)
        self.caminho = Path(self._pasta.name) / "teste.db"
        self.relogio = Relogio()
        self.repositorio = RepositorioUsuarios(self.caminho)
        self.servico = ServicoAutenticacao(
            self.repositorio, hasher=HasherScrypt(n=2**10), verificador=SemVerificacao(),
            relogio=self.relogio,
        )


class TestCadastro(BaseTeste):
    def test_senha_nao_e_gravada_em_claro(self):
        self.servico.cadastrar("alice", SENHA)
        bruto = self.caminho.read_bytes()
        self.assertNotIn(SENHA.encode(), bruto)
        u = self.repositorio.buscar("alice")
        self.assertEqual(len(u.salt), 16)
        self.assertEqual(len(u.hash_senha), 32)
        self.assertEqual((u.n, u.r, u.p), (2**10, 8, 1))

    def test_mesma_senha_gera_salt_e_hash_diferentes(self):
        self.servico.cadastrar("alice", SENHA)
        self.servico.cadastrar("bruno", SENHA)
        a, b = self.repositorio.buscar("alice"), self.repositorio.buscar("bruno")
        self.assertNotEqual(a.salt, b.salt)
        self.assertNotEqual(a.hash_senha, b.hash_senha)

    def test_senha_curta_recusada(self):
        with self.assertRaises(ErroAutenticacao):
            self.servico.cadastrar("alice", "curta")
        self.assertIsNone(self.repositorio.buscar("alice"))

    def test_senha_enorme_recusada(self):
        with self.assertRaises(ErroAutenticacao):
            self.servico.cadastrar("alice", "a" * 5000)

    def test_usuario_duplicado_ignora_maiusculas(self):
        self.servico.cadastrar("alice", SENHA)
        with self.assertRaises(ErroAutenticacao):
            self.servico.cadastrar("ALICE", SENHA)

    def test_nome_de_usuario_invalido(self):
        for nome in ("", "ab", "a b c", "x'; DROP TABLE usuarios;--"):
            with self.assertRaises(ErroAutenticacao, msg=nome):
                self.servico.cadastrar(nome, SENHA)

    def test_senha_vazada_recusada(self):
        servico = ServicoAutenticacao(self.repositorio, hasher=HasherScrypt(n=2**10),
                                      verificador=Vazadas())
        with self.assertRaises(ErroAutenticacao):
            servico.cadastrar("alice", SENHA)


class TestLogin(BaseTeste):
    def setUp(self):
        super().setUp()
        self.servico.cadastrar("alice", SENHA)

    def test_login_correto(self):
        self.assertTrue(self.servico.autenticar("alice", SENHA))
        self.assertTrue(self.servico.autenticar("ALICE", SENHA))

    def test_login_com_senha_errada(self):
        with self.assertRaises(ErroAutenticacao):
            self.servico.autenticar("alice", "senha errada qualquer")

    def test_mensagem_igual_para_usuario_inexistente(self):
        with self.assertRaises(ErroAutenticacao) as errada:
            self.servico.autenticar("alice", "senha errada qualquer")
        with self.assertRaises(ErroAutenticacao) as inexistente:
            self.servico.autenticar("ninguem", "senha errada qualquer")
        self.assertEqual(str(errada.exception), str(inexistente.exception))

    def test_normalizacao_unicode(self):
        self.servico.cadastrar("carla", "café com leite 2026")        # é composto
        self.assertTrue(self.servico.autenticar("carla", "café com leite 2026"))  # e + acento

    def test_comparacao_usa_compare_digest(self):
        with patch("autenticacao.hmac.compare_digest", return_value=True) as comparar:
            self.assertTrue(self.servico.autenticar("alice", "qualquer coisa aqui"))
        comparar.assert_called_once()

    def test_parametros_guardados_valem_apos_mudar_o_padrao(self):
        servico_novo = ServicoAutenticacao(
            self.repositorio, hasher=HasherScrypt(n=2**11), verificador=SemVerificacao(),
            relogio=self.relogio,
        )
        self.assertTrue(servico_novo.autenticar("alice", SENHA))


class TestBloqueio(BaseTeste):
    def setUp(self):
        super().setUp()
        self.servico.cadastrar("alice", SENHA)

    def _errar(self, vezes):
        for _ in range(vezes):
            with self.assertRaises(ErroAutenticacao):
                self.servico.autenticar("alice", "senha errada qualquer")

    def test_bloqueia_apos_cinco_falhas(self):
        self._errar(PoliticaBloqueio.MAX_TENTATIVAS)
        with self.assertRaises(ErroAutenticacao) as erro:
            self.servico.autenticar("alice", SENHA)  # mesmo a senha certa é recusada
        self.assertIn("bloqueado", str(erro.exception))

    def test_desbloqueia_apos_o_prazo(self):
        self._errar(PoliticaBloqueio.MAX_TENTATIVAS)
        self.relogio.agora += PoliticaBloqueio.BLOQUEIO_SEGUNDOS + 1
        self.assertTrue(self.servico.autenticar("alice", SENHA))

    def test_sucesso_zera_contador(self):
        self._errar(PoliticaBloqueio.MAX_TENTATIVAS - 1)
        self.assertTrue(self.servico.autenticar("alice", SENHA))
        self.assertEqual(self.repositorio.buscar("alice").falhas, 0)
        self._errar(PoliticaBloqueio.MAX_TENTATIVAS - 1)  # ainda não bloqueia
        self.assertTrue(self.servico.autenticar("alice", SENHA))

    def test_falhas_persistem_no_banco(self):
        self._errar(2)
        outro = RepositorioUsuarios(self.caminho)
        self.assertEqual(outro.buscar("alice").falhas, 2)


class TestPadroes(unittest.TestCase):
    def test_padrao_segue_minimo_owasp(self):
        h = HasherScrypt()
        self.assertGreaterEqual(h.n, 2**17)
        self.assertGreaterEqual(h.r, 8)
        self.assertGreaterEqual(h.p, 1)
        self.assertGreaterEqual(h.tamanho_salt, 16)

    def test_hash_de_referencia_rfc7914(self):
        # Vetor de teste do RFC 7914: scrypt("", "", N=16, r=1, p=1, dkLen=64).
        import hashlib
        esperado = bytes.fromhex(
            "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442"
            "fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906"
        )
        self.assertEqual(hashlib.scrypt(b"", salt=b"", n=16, r=1, p=1, dklen=64), esperado)


class RespostaFalsa:
    def __init__(self, texto):
        self.texto = texto

    def read(self):
        return self.texto.encode("ascii")

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class TestPwnedPasswords(unittest.TestCase):
    SENHA = "password"  # SHA-1 = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8

    def test_encontrada(self):
        resposta = RespostaFalsa("1E4C9B93F3F0682250B6CF8331B7EE68FD8:9545824\r\nABCDEF:2")
        with patch("autenticacao.urllib.request.urlopen", return_value=resposta) as abrir:
            self.assertTrue(PwnedPasswords().foi_vazada(self.SENHA))
        # Só o prefixo de 5 caracteres vai para a rede.
        self.assertTrue(abrir.call_args[0][0].full_url.endswith("/5BAA6"))

    def test_nao_encontrada(self):
        with patch("autenticacao.urllib.request.urlopen", return_value=RespostaFalsa("ABCDEF:2")):
            self.assertFalse(PwnedPasswords().foi_vazada(self.SENHA))

    def test_linha_de_preenchimento_com_contagem_zero_e_ignorada(self):
        resposta = RespostaFalsa("1E4C9B93F3F0682250B6CF8331B7EE68FD8:0")
        with patch("autenticacao.urllib.request.urlopen", return_value=resposta):
            self.assertFalse(PwnedPasswords().foi_vazada(self.SENHA))

    def test_sem_rede_recusa_o_cadastro(self):
        with patch("autenticacao.urllib.request.urlopen", side_effect=OSError("sem rede")):
            with self.assertRaises(ErroAutenticacao):
                PwnedPasswords().foi_vazada(self.SENHA)


if __name__ == "__main__":
    unittest.main()
