# Entrega 3 – Reconhecimento de rede e redução da superfície de ataque

Laboratório: VM Ubuntu Server (`helpdesk-lab`, 192.168.56.102) no VirtualBox, rede host-only.
Escopo autorizado: **apenas** 192.168.56.102 (ver Quadro 2 da documentação técnica).

## Conteúdo
- `scans/01..04` – situação inicial (portas TCP, serviços, SSH, UDP)
- `scans/05..07` – situação final, depois do endurecimento
- `tabela-risco.md` – tabela porta/protocolo/serviço/risco/recomendação (antes e depois)
- `../../helpdesk/superficie.py` – script que gera a tabela a partir do XML do Nmap

## Reproduzir a análise
```
python -m helpdesk.superficie docs\entrega3\scans\02-servicos.xml docs\entrega3\scans\06-servicos-depois.xml
python -m unittest -v
```

## Atenção
Não versionar chaves SSH (`helpdesk_lab`) nem senhas. A chave privada fica em `%USERPROFILE%\.ssh`.
