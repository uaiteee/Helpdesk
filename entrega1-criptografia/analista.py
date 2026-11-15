"""Decifra um chamado com a chave privada do suporte."""
import argparse
import json
from pathlib import Path

from gerar_chaves import CHAVES, obter_senha
from helpdesk import Analista, Envelope, EnvelopeInvalido


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("envelope", type=Path, help="arquivo JSON do chamado")
    args = parser.parse_args()

    try:
        envelope = Envelope.de_dict(json.loads(args.envelope.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError, EnvelopeInvalido) as erro:
        raise SystemExit(f"Chamado REJEITADO: {erro}") from None

    try:
        analista = Analista(CHAVES.carregar_privada(obter_senha()))
    except (OSError, ValueError) as erro:
        raise SystemExit(f"Erro: {erro}") from None

    try:
        texto = analista.decifrar(envelope)
    except EnvelopeInvalido as erro:
        raise SystemExit(f"Chamado REJEITADO: {erro}") from None

    print(f"Chamado {envelope.cabecalho['id']} (criado em {envelope.cabecalho['criado_em']})")
    print("-" * 60)
    print(texto)


if __name__ == "__main__":
    main()
