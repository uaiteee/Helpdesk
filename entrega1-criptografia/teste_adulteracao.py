"""Demonstra que qualquer alteração no envelope é detectada.

Cria um chamado legítimo com a chave pública do suporte, confirma que ele
decifra corretamente e então aplica uma série de adulterações, uma de cada
vez, sobre cópias do envelope. Todas devem ser rejeitadas pelo analista.

Uso:
    python teste_adulteracao.py
Retorna código 0 se todas as adulterações forem detectadas, 1 caso contrário.
"""

import base64
import copy
import sys

from gerar_chaves import CHAVES, obter_senha
from helpdesk import Analista, Cliente, Envelope, EnvelopeInvalido

TEXTO_ORIGINAL = "Meu computador não liga. Patrimônio 4521, sala 302."


def inverter_bit(campo_b64: str, posicao: int = 0) -> str:
    """Inverte o bit menos significativo de um byte do campo Base64."""
    dados = bytearray(base64.b64decode(campo_b64))
    dados[posicao] ^= 0x01
    return base64.b64encode(bytes(dados)).decode("ascii")


def adulterar_ultimo_byte(campo_b64: str) -> str:
    return inverter_bit(campo_b64, -1)


def trocar_texto_por_outro(envelope: dict, chave_publica) -> None:
    """Substitui o texto cifrado pelo de outro chamado (mesmo tamanho não importa)."""
    outro = Cliente(chave_publica).cifrar("Por favor, resetem a senha do diretor.").para_dict()
    envelope["texto_cifrado"] = outro["texto_cifrado"]


def main() -> int:
    chave_publica = CHAVES.carregar_publica()
    analista = Analista(CHAVES.carregar_privada(obter_senha()))

    original = Cliente(chave_publica).cifrar(TEXTO_ORIGINAL).para_dict()

    print("== Controle: envelope íntegro ==")
    texto = analista.decifrar(Envelope.de_dict(original))
    assert texto == TEXTO_ORIGINAL, "o envelope íntegro não decifrou corretamente"
    print(f"  OK, decifrado: {texto!r}\n")

    outro_envelope = Cliente(chave_publica).cifrar("Outro chamado qualquer.").para_dict()

    adulteracoes = {
        "1 bit invertido no texto cifrado":
            lambda e: e.update(texto_cifrado=inverter_bit(e["texto_cifrado"])),
        "1 bit invertido na tag GCM (últimos 16 bytes)":
            lambda e: e.update(texto_cifrado=adulterar_ultimo_byte(e["texto_cifrado"])),
        "tag GCM removida (texto truncado)":
            lambda e: e.update(texto_cifrado=base64.b64encode(
                base64.b64decode(e["texto_cifrado"])[:-16]).decode()),
        "1 bit invertido no nonce":
            lambda e: e.update(nonce=inverter_bit(e["nonce"])),
        "1 bit invertido na chave AES cifrada (RSA)":
            lambda e: e.update(chave_cifrada=inverter_bit(e["chave_cifrada"], 100)),
        "chave AES cifrada trocada pela de outro chamado":
            lambda e: e.update(chave_cifrada=outro_envelope["chave_cifrada"]),
        "texto cifrado trocado pelo de outro chamado":
            lambda e: trocar_texto_por_outro(e, chave_publica),
        "cabeçalho (AAD): id do chamado alterado":
            lambda e: e["cabecalho"].update(id="00000000-0000-0000-0000-000000000000"),
        "cabeçalho (AAD): data de criação alterada":
            lambda e: e["cabecalho"].update(criado_em="2020-01-01T00:00:00+00:00"),
        "campo obrigatório removido (nonce)":
            lambda e: e.pop("nonce"),
        "Base64 inválido no texto cifrado":
            lambda e: e.update(texto_cifrado="@@não-é-base64@@"),
    }

    print("== Adulterações ==")
    falhas_nao_detectadas = 0
    for descricao, adulterar in adulteracoes.items():
        envelope = copy.deepcopy(original)
        adulterar(envelope)
        try:
            resultado = analista.decifrar(Envelope.de_dict(envelope))
        except EnvelopeInvalido as erro:
            print(f"  [DETECTADA]     {descricao}\n                  -> {erro}")
        else:
            falhas_nao_detectadas += 1
            print(f"  [NÃO DETECTADA] {descricao} -> {resultado!r}")

    total = len(adulteracoes)
    print(f"\nResultado: {total - falhas_nao_detectadas}/{total} adulterações detectadas.")
    return 0 if falhas_nao_detectadas == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
