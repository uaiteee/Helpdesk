"""Análise da superfície de ataque a partir de um XML do Nmap (Entrega 3).

Lê o resultado de ``nmap -sV -oX`` e produz a tabela
porta / protocolo / serviço / risco / recomendação. Com dois arquivos
(antes e depois do endurecimento) também mostra o que mudou.

Uso:
    python -m helpdesk.superficie antes.xml
    python -m helpdesk.superficie antes.xml depois.xml -o tabela.md

O módulo só lê arquivos: não faz varredura de rede nem se conecta a nada.
"""

from __future__ import annotations

import argparse
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

NIVEIS = {"Baixo": 1, "Médio": 2, "Alto": 3}


@dataclass(frozen=True)
class Porta:
    """Uma porta aberta encontrada pelo Nmap."""

    numero: int
    protocolo: str
    servico: str
    produto: str = ""
    versao: str = ""

    @property
    def chave(self) -> tuple[int, str]:
        return (self.numero, self.protocolo)

    @property
    def identificacao(self) -> str:
        """Produto e versão como o Nmap reportou (vazio se não revelou nada)."""
        return " ".join(parte for parte in (self.produto, self.versao) if parte)


@dataclass(frozen=True)
class Regra:
    """Conhecimento sobre um tipo de serviço: risco, motivo e recomendação."""

    risco: str
    motivo: str
    recomendacao: str


@dataclass(frozen=True)
class Avaliacao:
    porta: Porta
    risco: str
    motivo: str
    recomendacao: str


class LeitorNmapXml:
    """Extrai as portas abertas de um arquivo XML gerado pelo Nmap (-oX)."""

    def ler(self, caminho: Path | str) -> list[Porta]:
        try:
            raiz = ET.parse(caminho).getroot()
        except (ET.ParseError, OSError) as erro:
            raise ValueError(f"não foi possível ler '{caminho}': {erro}") from erro
        if raiz.tag != "nmaprun":
            raise ValueError(f"'{caminho}' não parece um XML do Nmap")
        portas = []
        for elemento in raiz.iter("port"):
            estado = elemento.find("state")
            if estado is None or estado.get("state") != "open":
                continue
            servico = elemento.find("service")
            dados = servico.attrib if servico is not None else {}
            portas.append(Porta(
                numero=int(elemento.get("portid")),
                protocolo=elemento.get("protocol", "tcp"),
                servico=dados.get("name", "desconhecido"),
                produto=dados.get("product", ""),
                versao=" ".join(
                    parte for parte in (dados.get("version", ""), dados.get("extrainfo", "")) if parte
                ),
            ))
        return sorted(portas, key=lambda p: (p.protocolo, p.numero))


class BaseConhecimento:
    """Regras por serviço. Serviços não catalogados recebem risco Médio."""

    REGRAS = {
        "ssh": Regra(
            "Médio",
            "Administração remota: alvo frequente de força bruta e de roubo de credenciais.",
            "Só autenticação por chave, sem login de root, poucas tentativas, algoritmos "
            "modernos e acesso limitado por firewall.",
        ),
        "http": Regra(
            "Médio",
            "Tráfego em texto claro e página exposta a qualquer cliente da rede.",
            "Publicar apenas se for necessário; preferir HTTPS (TLS), remover páginas padrão "
            "e aplicar atualizações.",
        ),
        "https": Regra(
            "Baixo",
            "Tráfego criptografado, mas ainda é superfície exposta.",
            "Manter TLS atualizado, desativar protocolos antigos e aplicar atualizações.",
        ),
        "telnet": Regra(
            "Alto",
            "Senhas e comandos trafegam sem criptografia.",
            "Desativar e substituir por SSH.",
        ),
        "ftp": Regra(
            "Alto",
            "Credenciais e dados trafegam sem criptografia.",
            "Desativar ou trocar por SFTP.",
        ),
        "microsoft-ds": Regra(
            "Alto",
            "Compartilhamento SMB: histórico de vulnerabilidades críticas e movimentação lateral.",
            "Não expor; bloquear no firewall e aplicar atualizações.",
        ),
        "ms-wbt-server": Regra(
            "Alto",
            "Área de trabalho remota exposta é vetor comum de ataque.",
            "Não expor; usar VPN e autenticação multifator.",
        ),
        "mysql": Regra(
            "Médio",
            "Banco de dados acessível pela rede.",
            "Escutar apenas em localhost ou em rede interna e exigir contas com privilégio mínimo.",
        ),
        "domain": Regra(
            "Médio",
            "Servidor DNS pode ser usado em ataques de amplificação.",
            "Desativar se não for necessário e restringir consultas recursivas.",
        ),
        "snmp": Regra(
            "Alto",
            "Comunidades padrão revelam toda a configuração do equipamento.",
            "Desativar ou usar SNMPv3 com autenticação e restringir por origem.",
        ),
    }
    PADRAO = Regra(
        "Médio",
        "Serviço não catalogado: sem justificativa de necessidade.",
        "Confirmar se o serviço é necessário; se não for, desativar e fechar a porta.",
    )

    def buscar(self, servico: str) -> Regra:
        return self.REGRAS.get(servico.lower(), self.PADRAO)


class Avaliador:
    """Aplica a base de conhecimento e acrescenta observações sobre a versão exposta."""

    def __init__(self, base: BaseConhecimento | None = None):
        self.base = base or BaseConhecimento()

    def avaliar(self, portas: list[Porta]) -> list[Avaliacao]:
        resultado = []
        for porta in portas:
            regra = self.base.buscar(porta.servico)
            motivo, recomendacao = regra.motivo, regra.recomendacao
            if porta.versao:
                motivo += f" Versão exposta ({porta.identificacao})."
                recomendacao += " Ocultar o banner de versão quando o serviço permitir."
            resultado.append(Avaliacao(porta, regra.risco, motivo, recomendacao))
        return resultado


class Relatorio:
    """Gera as tabelas em Markdown."""

    @staticmethod
    def tabela(avaliacoes: list[Avaliacao]) -> str:
        linhas = [
            "| Porta | Protocolo | Serviço | Versão exposta | Risco | Recomendação |",
            "|---|---|---|---|---|---|",
        ]
        for a in avaliacoes:
            p = a.porta
            linhas.append(
                f"| {p.numero} | {p.protocolo.upper()} | {p.servico} | "
                f"{p.identificacao or 'não revelada'} | {a.risco} | {a.recomendacao} |"
            )
        return "\n".join(linhas)

    @staticmethod
    def _situacao(porta: Porta | None) -> str:
        if porta is None:
            return "fechada"
        return porta.identificacao or "aberta, versão não revelada"

    @staticmethod
    def comparar(antes: list[Porta], depois: list[Porta]) -> str:
        a = {p.chave: p for p in antes}
        d = {p.chave: p for p in depois}
        linhas = ["| Porta | Antes | Depois |", "|---|---|---|"]
        for chave in sorted(set(a) | set(d)):
            rotulo = f"{chave[0]}/{chave[1]}"
            ant = Relatorio._situacao(a.get(chave))
            dep = Relatorio._situacao(d.get(chave))
            linhas.append(f"| {rotulo} | {ant} | {dep} |")
        return "\n".join(linhas)


def principal(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Tabela de risco a partir de XML do Nmap")
    parser.add_argument("antes", type=Path, help="XML do scan (ou do scan 'antes')")
    parser.add_argument("depois", type=Path, nargs="?", help="XML do scan 'depois' (opcional)")
    parser.add_argument("-o", "--saida", type=Path, help="grava o resultado em um arquivo")
    args = parser.parse_args(argv)

    leitor, avaliador = LeitorNmapXml(), Avaliador()
    try:
        antes = leitor.ler(args.antes)
        depois = leitor.ler(args.depois) if args.depois else None
    except ValueError as erro:
        print(f"Erro: {erro}", file=sys.stderr)
        return 1

    partes = ["## Superfície de ataque" + (" (antes)" if depois is not None else ""),
              Relatorio.tabela(avaliador.avaliar(antes))]
    if depois is not None:
        partes += ["\n## Superfície de ataque (depois)",
                   Relatorio.tabela(avaliador.avaliar(depois)),
                   "\n## O que mudou", Relatorio.comparar(antes, depois)]
    texto = "\n".join(partes) + "\n"
    if args.saida:
        args.saida.write_text(texto, encoding="utf-8")
        print(f"Resultado gravado em {args.saida}")
    else:
        print(texto)
    return 0


if __name__ == "__main__":
    raise SystemExit(principal())
