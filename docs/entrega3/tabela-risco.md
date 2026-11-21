## Superfície de ataque (antes)
| Porta | Protocolo | Serviço | Versão exposta | Risco | Recomendação |
|---|---|---|---|---|---|
| 22 | TCP | ssh | OpenSSH 10.2p1 Ubuntu 2ubuntu3.8 Ubuntu Linux; protocol 2.0 | Médio | Só autenticação por chave, sem login de root, poucas tentativas, algoritmos modernos e acesso limitado por firewall. Ocultar o banner de versão quando o serviço permitir. |
| 80 | TCP | http | Apache httpd 2.4.66 (Ubuntu) | Médio | Publicar apenas se for necessário; preferir HTTPS (TLS), remover páginas padrão e aplicar atualizações. Ocultar o banner de versão quando o serviço permitir. |

## Superfície de ataque (depois)
| Porta | Protocolo | Serviço | Versão exposta | Risco | Recomendação |
|---|---|---|---|---|---|
| 22 | TCP | ssh | OpenSSH 10.2p1 Ubuntu 2ubuntu3.8 Ubuntu Linux; protocol 2.0 | Médio | Só autenticação por chave, sem login de root, poucas tentativas, algoritmos modernos e acesso limitado por firewall. Ocultar o banner de versão quando o serviço permitir. |
| 80 | TCP | http | Apache httpd | Médio | Publicar apenas se for necessário; preferir HTTPS (TLS), remover páginas padrão e aplicar atualizações. |

## O que mudou
| Porta | Antes | Depois |
|---|---|---|
| 22/tcp | OpenSSH 10.2p1 Ubuntu 2ubuntu3.8 Ubuntu Linux; protocol 2.0 | OpenSSH 10.2p1 Ubuntu 2ubuntu3.8 Ubuntu Linux; protocol 2.0 |
| 80/tcp | Apache httpd 2.4.66 (Ubuntu) | Apache httpd |
