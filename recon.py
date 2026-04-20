from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
import socket
import requests
import scapy.all as scapy


HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; recon-tool/1.0)"}


def links(html):
    soup = BeautifulSoup(html, "html.parser")

    links = []

    # pegar <a href="">
    for tag in soup.find_all("a"):
        href = tag.get("href")
        if href and not href.startswith(("#", "mailto:", "javascript:")):
            links.append(href)

    # pegar <form action="">
    for tag in soup.find_all("form"):
        action = tag.get("action")
        if action and not action.startswith(("#", "mailto:", "javascript:")):
            links.append(action)

    return list(set(links))


def lista(domain, wordlist):
    encontrados = []

    for sub in wordlist:
        subdominio = f"{sub}.{domain}"

        try:
            ip = socket.gethostbyname(subdominio)
            print(f"Encontrado: {subdominio} - {ip}")
            encontrados.append((subdominio, ip))
        except socket.gaierror:
            pass  # subdomínio não resolvido — esperado

    return encontrados


def diretorios(base_url, wordlist):
    encontrados = []

    for word in wordlist:
        url = f"{base_url.rstrip('/')}/{word}"

        try:
            resposta = requests.get(url, timeout=3, headers=HEADERS, allow_redirects=False)

            if resposta.status_code in (200, 301, 302, 403):
                print(f"[{resposta.status_code}] {url}")
                encontrados.append(url)
        except requests.RequestException:
            pass

    return encontrados


def arp_scan(ip_range, interface=None):
    print(f"Escaneando: {ip_range}")

    # broadcast
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    # ARP request
    arp_request = scapy.ARP(pdst=ip_range)

    # pacote completo
    packet = broadcast / arp_request

    # envio
    ans, _ = scapy.srp(packet, timeout=2, iface=interface, inter=0.1, verbose=0)

    devices = []

    for sent, received in ans:
        devices.append({
            "ip": received.psrc,
            "mac": received.hwsrc
        })

    return devices


def scan_port(ip, porta, stop_flag=None):
    if stop_flag and stop_flag():
        return None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, porta))
        sock.close()

        if result == 0:
            print(f"[+] Porta aberta: {porta}")
            return porta
    except socket.error:
        pass
    return None


def port_scan(ip, portas, stop_flag=None):
    from concurrent.futures import as_completed
    abertas = []

    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(scan_port, ip, p, stop_flag): p for p in portas}
        for future in as_completed(futures):
            if stop_flag and stop_flag():
                executor.shutdown(wait=False, cancel_futures=True)
                break
            result = future.result()
            if result:
                abertas.append(result)

    return abertas