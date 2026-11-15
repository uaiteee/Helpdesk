"""Demonstração para a documentação: por que SHA-256 puro não serve para senhas.

Executa: python demonstracao.py
Mostra (1) SHA-256 sem salt gera sempre o mesmo hash, (2) a velocidade do
SHA-256 contra a do scrypt e (3) que o scrypt com salt diferente gera hashes
diferentes para a mesma senha.
"""

import hashlib
import time

from autenticacao import HasherScrypt

SENHA = "senha-de-exemplo-123"


def main() -> None:
    print("1) SHA-256 sem salt: a mesma senha sempre dá o mesmo hash")
    print("   usuário A:", hashlib.sha256(SENHA.encode()).hexdigest())
    print("   usuário B:", hashlib.sha256(SENHA.encode()).hexdigest())
    print("   -> quem vê hashes iguais sabe que as senhas são iguais, e tabelas")
    print("      prontas (rainbow tables) quebram o hash na hora.\n")

    tentativas = 200_000
    inicio = time.perf_counter()
    for i in range(tentativas):
        hashlib.sha256(f"{SENHA}{i}".encode()).digest()
    sha = time.perf_counter() - inicio
    print(f"2) Velocidade: {tentativas:,} hashes SHA-256 em {sha:.3f} s "
          f"(~{tentativas / sha:,.0f} por segundo, em uma CPU comum)")
    hasher = HasherScrypt()
    amostras = 3
    inicio = time.perf_counter()
    for _ in range(amostras):
        hasher.novo_hash(SENHA)
    scrypt = (time.perf_counter() - inicio) / amostras
    print(f"   scrypt (N={hasher.n}, r={hasher.r}, p={hasher.p}): {scrypt:.3f} s por hash "
          f"(~{1 / scrypt:.1f} por segundo)")
    print(f"   -> o scrypt é cerca de {scrypt / (sha / tentativas):,.0f}x mais lento "
          "para o atacante testar cada palpite, e exige muita memória (difícil de paralelizar em GPU).\n")

    print("3) scrypt com salt aleatório: a mesma senha gera hashes diferentes")
    salt_a, hash_a = hasher.novo_hash(SENHA)
    salt_b, hash_b = hasher.novo_hash(SENHA)
    print("   usuário A:", hash_a.hex())
    print("   usuário B:", hash_b.hex())
    print("   hashes iguais?", hash_a == hash_b)


if __name__ == "__main__":
    main()
