# Helpdesk Corporativo

Projeto Integrador: Segurança Aplicada ao Desenvolvimento (Segurança da Informação, ADS).
Equipe: João Pedro Andrade Oliveira, Erick Silva Vieira, Ivys Gabriel Alves Santos Almeida

Um único sistema que evolui a cada entrega. Chamados de suporte são cifrados com a chave pública do
suporte (Entrega 1), e o acesso exige login com senha protegida por scrypt (Entrega 2). Cada entrega é
marcada por uma **tag** do Git (`entrega-1`, `entrega-2`, ...), e a documentação fica em `docs/`.

| Entrega | Tema | Código | Documentação |
|---|---|---|---|
| 1 | Criptografia híbrida (RSA-OAEP + AES-256-GCM) | `helpdesk/criptografia.py`, `teste_adulteracao.py` | [docs/entrega1](docs/entrega1/README.md) |
| 2 | Cadastro e login com scrypt, salt e comparação segura | `helpdesk/autenticacao.py`, `helpdesk/chamados.py` | [docs/entrega2](docs/entrega2/README.md) |
| 3 | Varredura com Nmap | a fazer | |
| 4 | Auditoria e correções | a fazer | |

## Estrutura

```
Helpdesk/
├── helpdesk/                 # o sistema (pacote Python, orientado a objetos)
│   ├── criptografia.py       # RepositorioChaves, Envelope, Cliente, Analista
│   ├── autenticacao.py       # HasherScrypt, RepositorioUsuarios, ServicoAutenticacao, ...
│   ├── chamados.py           # ServicoChamados: login para abrir, analista para ler
│   ├── config.py, cli.py     # caminhos, senhas e linha de comando
├── tests/                    # testes automatizados (unittest)
├── teste_adulteracao.py      # demonstração: 11 adulterações detectadas
├── demonstracao_hash.py      # demonstração: SHA-256 x scrypt
├── docs/                     # documentação e evidências de cada entrega
├── chaves/  chamados/  dados/   # criados localmente; NÃO vão para o Git
└── requirements.txt
```

## Requisitos

- Windows, com [Python 3](https://www.python.org/downloads/) (marque "Add Python to PATH" na instalação; testado com 3.13 e 3.14) e [Git](https://git-scm.com/downloads)
- Internet para instalar as dependências e, opcionalmente, para a verificação de senhas vazadas

## Instalação (máquina nova)

```
git clone https://github.com/uaiteee/Helpdesk.git
cd Helpdesk
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

Os comandos abaixo são executados na raiz do projeto, com o ambiente virtual ativo (aparece `(venv)` no início da linha).
Se `python` não for reconhecido, use `py`.

## Primeira execução

As chaves, os chamados e o banco de usuários não vão para o Git, então são criados localmente:

```
python -m helpdesk gerar-chaves
python -m helpdesk cadastrar alice
python -m helpdesk cadastrar ana --analista
```

O `cadastrar` consulta a API Pwned Passwords para recusar senhas vazadas; sem internet, acrescente `--offline`.
As senhas têm no mínimo 12 caracteres e não aparecem na tela. Criar um analista pede também a senha da chave
privada definida em `gerar-chaves`.

## Uso

```
python -m helpdesk abrir-chamado alice "Meu computador não liga"
python -m helpdesk ler-chamado ana chamados\chamado_<id>.json
python -m helpdesk banco
```

- `abrir-chamado`: qualquer usuário autenticado cifra um chamado.
- `ler-chamado`: só analistas decifram (pede a senha de login e a da chave privada).
- `banco`: mostra o que fica gravado (salt, hash e parâmetros do scrypt, nunca a senha).
- Troque `<id>` pelo nome do arquivo mostrado pelo `abrir-chamado`.

## Testes e demonstrações

```
python -m unittest -v          # 32 testes automatizados
python teste_adulteracao.py    # Entrega 1: 11 adulterações detectadas
python demonstracao_hash.py    # Entrega 2: SHA-256 x scrypt
```

## Segurança

Nenhum algoritmo criptográfico é próprio: usamos `cryptography` (Entrega 1) e `hashlib.scrypt` (Entrega 2).
Chaves (`*.pem`), chamados cifrados e bancos de dados não vão para o Git.
