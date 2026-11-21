"""Testes da análise de superfície (Entrega 3). Executar: python -m unittest -v"""

import tempfile
import unittest
from pathlib import Path

from helpdesk.superficie import Avaliador, LeitorNmapXml, Porta, Relatorio, principal

XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap"><host><ports>
<port protocol="tcp" portid="22"><state state="open"/>
  <service name="ssh" product="OpenSSH" version="10.2p1" extrainfo="Ubuntu"/></port>
<port protocol="tcp" portid="23"><state state="open"/><service name="telnet"/></port>
<port protocol="tcp" portid="80"><state state="closed"/><service name="http"/></port>
<port protocol="tcp" portid="9999"><state state="open"/><service name="abc"/></port>
</ports></host></nmaprun>"""

XML_DEPOIS = """<?xml version="1.0"?>
<nmaprun scanner="nmap"><host><ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH"/></port>
</ports></host></nmaprun>"""


class Base(unittest.TestCase):
    def setUp(self):
        self._pasta = tempfile.TemporaryDirectory()
        self.addCleanup(self._pasta.cleanup)
        self.pasta = Path(self._pasta.name)

    def arquivo(self, nome, conteudo):
        caminho = self.pasta / nome
        caminho.write_text(conteudo, encoding="utf-8")
        return caminho


class TestLeitor(Base):
    def test_le_so_portas_abertas(self):
        portas = LeitorNmapXml().ler(self.arquivo("a.xml", XML))
        self.assertEqual([p.numero for p in portas], [22, 23, 9999])

    def test_extrai_produto_e_versao(self):
        ssh = LeitorNmapXml().ler(self.arquivo("a.xml", XML))[0]
        self.assertEqual(ssh.identificacao, "OpenSSH 10.2p1 Ubuntu")

    def test_arquivo_invalido(self):
        with self.assertRaises(ValueError):
            LeitorNmapXml().ler(self.arquivo("ruim.xml", "isso nao e xml"))
        with self.assertRaises(ValueError):
            LeitorNmapXml().ler(self.arquivo("outro.xml", "<html></html>"))

    def test_arquivo_inexistente(self):
        with self.assertRaises(ValueError):
            LeitorNmapXml().ler(self.pasta / "nao-existe.xml")


class TestAvaliador(unittest.TestCase):
    def avaliar(self, servico, versao=""):
        return Avaliador().avaliar([Porta(1, "tcp", servico, "Prod" if versao else "", versao)])[0]

    def test_telnet_e_risco_alto(self):
        self.assertEqual(self.avaliar("telnet").risco, "Alto")

    def test_servico_desconhecido_recebe_risco_medio_e_pede_justificativa(self):
        a = self.avaliar("abc")
        self.assertEqual(a.risco, "Médio")
        self.assertIn("necessário", a.recomendacao)

    def test_versao_exposta_gera_observacao(self):
        com = self.avaliar("http", "2.4.66")
        sem = self.avaliar("http")
        self.assertIn("banner", com.recomendacao)
        self.assertNotIn("banner", sem.recomendacao)


class TestRelatorio(Base):
    def test_tabela_tem_cabecalho_e_linhas(self):
        portas = LeitorNmapXml().ler(self.arquivo("a.xml", XML))
        tabela = Relatorio.tabela(Avaliador().avaliar(portas))
        linhas = tabela.splitlines()
        self.assertEqual(len(linhas), 2 + 3)
        self.assertIn("| 23 | TCP | telnet |", tabela)

    def test_comparacao_mostra_porta_fechada_e_versao_oculta(self):
        leitor = LeitorNmapXml()
        antes = leitor.ler(self.arquivo("a.xml", XML))
        depois = leitor.ler(self.arquivo("d.xml", XML_DEPOIS))
        texto = Relatorio.comparar(antes, depois)
        self.assertIn("| 23/tcp | aberta, versão não revelada | fechada |", texto)
        self.assertIn("| 22/tcp | OpenSSH 10.2p1 Ubuntu | OpenSSH |", texto)


class TestLinhaDeComando(Base):
    def test_gera_arquivo(self):
        entrada = self.arquivo("a.xml", XML)
        saida = self.pasta / "saida.md"
        self.assertEqual(principal([str(entrada), "-o", str(saida)]), 0)
        self.assertIn("telnet", saida.read_text(encoding="utf-8"))

    def test_erro_retorna_codigo_1(self):
        self.assertEqual(principal([str(self.pasta / "x.xml")]), 1)


if __name__ == "__main__":
    unittest.main()
