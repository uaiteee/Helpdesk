# Entrega 2 — Hash e autenticação segura (Helpdesk Corporativo)

Projeto Integrador: Segurança Aplicada ao Desenvolvimento
Equipe: João Pedro Andrade Oliveira, Erick Silva Vieira, Ivys Gabriel Alves Santos Almeida

## 1. Problema e objetivo

Os analistas e clientes do Helpdesk precisam entrar no sistema. Se as senhas fossem
guardadas em texto puro ou com um hash rápido, o vazamento do banco expõe todas as contas.
**Objetivo:** cadastro e login em que a senha nunca é gravada, só um hash lento com salt,
e a conferência é feita de forma segura.

## 2. Ambiente e tecnologias

- Python 3.13 ou superior; apenas biblioteca padrão (`hashlib`, `hmac`, `sqlite3`, `unittest`).
- Nada de criptografia própria: o scrypt é o `hashlib.scrypt` (OpenSSL).

## 3. Algoritmo e justificativa

| Decisão | Escolha | Motivo |
|---|---|---|
| Algoritmo | scrypt | Lento e consome memória, o que encarece ataques com GPU/ASIC (RFC 7914) |
| Parâmetros | N=2^17, r=8, p=1 | Mínimo recomendado pela OWASP para scrypt (~128 MiB por verificação) |
| Salt | 16 bytes de `os.urandom`, um por usuário | Mesma senha gera hashes diferentes; inutiliza tabelas prontas |
| Hash | 32 bytes | Tamanho de saída padrão para 256 bits |
| Armazenamento | salt, hash, N, r, p | Guardar os parâmetros permite aumentá-los no futuro sem quebrar contas antigas |
| Comparação | `hmac.compare_digest` | Tempo constante, evita ataque por medição de tempo |
| Senha | mínimo 12 e máximo 1024 caracteres, normalização NFKC | Tamanho importa mais que regras de composição; o máximo evita abuso de CPU/memória |
| Senhas vazadas | API Pwned Passwords (k-anonymity) | Só 5 caracteres do SHA-1 saem da máquina; se a API falhar, o cadastro é recusado (`--offline` desliga) |
| Login | mesma mensagem para usuário inexistente e senha errada; derivação "falsa" para usuário inexistente | Não revela quais usuários existem |
| Bloqueio | 5 falhas seguidas = 5 min bloqueado | Limita adivinhação online |

### Por que SHA-256 sozinho não serve para senhas

1. É **rápido por projeto**: uma CPU comum calcula milhões por segundo e uma GPU, bilhões,
   então o atacante testa listas enormes de senhas em pouco tempo.
2. Sem **salt**, a mesma senha gera sempre o mesmo hash: quem vê dois hashes iguais sabe que
   as senhas são iguais, e tabelas pré-calculadas (rainbow tables) quebram o hash na hora.
3. Não tem **fator de custo** ajustável. Funções como scrypt, Argon2id, bcrypt e PBKDF2 foram
   feitas para ser lentas e configuráveis. O comando `python demonstracao.py` mostra isso na prática.

## 4. Implementação e execução

Classes em `autenticacao.py` (uma responsabilidade cada): `Usuario`, `PoliticaSenha`,
`HasherScrypt`, `VerificadorVazamentos` (`PwnedPasswords`, `SemVerificacao`),
`RepositorioUsuarios` (SQLite), `PoliticaBloqueio`, `ServicoAutenticacao`.
As dependências são injetadas no serviço, o que permite testar sem rede e sem esperar.

```
cd entrega2-autenticacao
python portal.py cadastrar alice            # pede a senha sem mostrar na tela
python portal.py entrar alice
python portal.py banco                      # mostra o que ficou gravado
python demonstracao.py                      # SHA-256 x scrypt
python -m unittest -v                       # 23 testes
```

Use `--offline` no `cadastrar` se não houver internet. O banco fica em `dados/usuarios.db`
(fora do Git).

## 5. Testes e evidências

`test_autenticacao.py` cobre: senha não aparece no banco, salt e hash diferentes para a mesma
senha, senha curta/longa/vazada recusada, usuário duplicado, login correto e incorreto, mesma
mensagem para usuário inexistente, uso de `hmac.compare_digest`, bloqueio e desbloqueio,
normalização Unicode, vetor de teste do RFC 7914 e a API Pwned Passwords (com resposta simulada).

Prints sugeridos em `evidencias/`: cadastro, `portal.py banco`, login correto, login incorreto,
`demonstracao.py` e `python -m unittest -v`.

## 6. Riscos, limitações e melhorias

- O bloqueio por conta pode ser usado para travar o acesso de outra pessoa (negação de serviço); melhoria: limitar também por origem.
- Sem autenticação multifator nem recuperação de senha.
- SQLite local sem criptografia do arquivo; em produção, banco com controle de acesso.
- scrypt com 128 MiB por login exige dimensionar o servidor; Argon2id seria alternativa moderna.
- A verificação de vazamentos depende de serviço externo.
- Melhoria: reprocessar o hash com parâmetros maiores quando o usuário logar.

## 7. Referências

- OWASP. Password Storage Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- PERCIVAL, C.; JOSEFSSON, S. RFC 7914: The scrypt Password-Based Key Derivation Function. 2016.
- PYTHON SOFTWARE FOUNDATION. hashlib e hmac.compare_digest. https://docs.python.org/3/library/hashlib.html
- HAVE I BEEN PWNED. Pwned Passwords API. https://haveibeenpwned.com/API/v3#PwnedPasswords
