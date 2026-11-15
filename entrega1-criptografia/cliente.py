"""Cifra um chamado para o suporte."""
import argparse
import json
from pathlib import Path
from gerar_chaves import CHAVES
from helpdesk import Cliente


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("texto", nargs="?")
    parser.add_argument("-s", "--saida", type=Path)
    args = parser.parse_args()
    texto = args.texto if args.texto is not None else input("Descreva o chamado: ")
    try:
        envelope = Cliente(CHAVES.carregar_publica()).cifrar(texto)
    except ValueError as erro:
        raise SystemExit(f"Erro: {erro}") from None
    saida = args.saida or Path(__file__).resolve().parent / "chamados" / f"chamado_{envelope.cabecalho['id']}.json"
    saida.parent.mkdir(parents=True, exist_ok=True)
    saida.write_text(json.dumps(envelope.para_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Chamado cifrado salvo em: {saida}")


if __name__ == "__main__":
    main()
