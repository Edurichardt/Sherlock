# Sherlock
An recon all in one tool for pentest exercises and CTFs, based on a room by TryHackMe

# Skyfall

Ferramenta de reconhecimento e enumeração com interface gráfica, desenvolvida em Python.

## Funcionalidades

- **Extração de Links** — extrai links e actions de formulários de um HTML
- **Enumeração de Subdomínios** — testa subdomínios via resolução DNS
- **Enumeração de Diretórios** — bruteforce de diretórios web com detecção por fingerprint
- **ARP Scan** — descoberta de hosts na rede local via pacotes ARP
- **Port Scan** — varredura de portas com 50 threads simultâneas
- **SSH Bruteforce** — tentativa de autenticação SSH via wordlist
- **Hash Cracker** — quebra de hashes por dicionário (MD5, SHA1, SHA256, SHA512 e outros)

## Requisitos

```
pip install beautifulsoup4 requests scapy paramiko
```

## Estrutura

```
sherlock.py   — funções de reconhecimento e enumeração
ssh.py        — funções de bruteforce SSH
cracker.py    — funções de quebra de hash
main.py       — interface gráfica (tkinter)
```

## Uso

```
python main.py
```

## Aviso

Use apenas em ambientes autorizados. O uso desta ferramenta em sistemas sem permissão é ilegal.
