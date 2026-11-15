# Helpdesk Corporativo

Projeto Integrador: Segurança Aplicada ao Desenvolvimento (Segurança da Informação, ADS).
Equipe: João Pedro Andrade Oliveira, Erick Silva Vieira, Ivys Gabriel Alves Santos Almeida

Chamados de suporte protegidos com criptografia e autenticação. Cada entrega fica em sua própria pasta:

| Pasta | Entrega | Conteúdo |
|---|---|---|
| [`entrega1-criptografia/`](entrega1-criptografia/README.md) | 1 | Criptografia híbrida (RSA-OAEP + AES-256-GCM) dos chamados |
| [`entrega2-autenticacao/`](entrega2-autenticacao/README.md) | 2 | Cadastro e login com scrypt, salt e comparação segura |

Entregas 3 (varredura com Nmap) e 4 (auditoria e correções) virão em novas pastas.

## Preparação

```
python -m venv C:\venvs\helpdesk
C:\venvs\helpdesk\Scripts\activate
pip install -r requirements.txt
```

Todo o código usa programação orientada a objetos. Nenhum algoritmo criptográfico foi
implementado por conta própria: usamos `cryptography` (Entrega 1) e `hashlib.scrypt` (Entrega 2).
Chaves (`*.pem`), envelopes e bancos de dados não vão para o Git.
