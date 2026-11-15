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

## Como usar

Na raiz do projeto, com o ambiente virtual ativo:

```
pip install -r requirements.txt
python -m helpdesk gerar-chaves
python -m helpdesk cadastrar alice
python -m helpdesk cadastrar ana --analista
python -m helpdesk abrir-chamado alice "Meu computador não liga"
python -m helpdesk ler-chamado ana chamados\chamado_<id>.json
python -m unittest -v
```

Nenhum algoritmo criptográfico é próprio: usamos `cryptography` (Entrega 1) e `hashlib.scrypt` (Entrega 2).
Chaves (`*.pem`), chamados cifrados e bancos de dados não vão para o Git.
