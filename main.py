import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import sys
import io
from recon import links, lista, diretorios, arp_scan, port_scan
from ssh import ssh_bruteforce
from cracker import wordlist_hash_cracker, ALGORITMOS_SUPORTADOS
import requests
import socket

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; recon-tool/1.0)"}

BG        = "#0d0f14"
BG2       = "#13161e"
BG3       = "#1a1f2e"
BORDER    = "#2a3050"
GREEN     = "#00ff9d"
GREEN_DIM = "#00c87a"
CYAN      = "#00cfff"
RED       = "#ff4f6a"
MUTED     = "#4a5270"
TEXT      = "#cdd6f4"
FONT_MONO = ("Courier New", 10)
FONT_UI   = ("Courier New", 9)
FONT_HEAD = ("Courier New", 12, "bold")
FONT_TINY = ("Courier New", 8)

def parse_wordlist(raw: str) -> list[str]:
    """Aceita vírgulas ou quebras de linha como separador."""
    import re
    items = re.split(r"[,\n]+", raw)
    return [i.strip() for i in items if i.strip()]

def parse_ports(raw: str):
    """
    Aceita:
      80,443,8080
      80-1024
      80,443,8000-8100
    """
    ports = []
    for part in raw.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            ports.extend(range(int(a.strip()), int(b.strip()) + 1))
        elif part.isdigit():
            ports.append(int(part))
    return ports

class Redirect(io.StringIO):
    """Redireciona stdout para o widget de output."""
    def __init__(self, widget):
        super().__init__()
        self.widget = widget

    def write(self, s):
        if s.strip():
            self.widget.insert_line(s)

    def flush(self):
        pass

class OutputBox(tk.Frame):
    def __init__(self, master, **kw):
        super().__init__(master, bg=BG2, bd=0, **kw)
        self._build()

    def _build(self):
        header = tk.Frame(self, bg=BG3)
        header.pack(fill="x")
        tk.Label(header, text="▸ OUTPUT", font=FONT_TINY, fg=MUTED,
                 bg=BG3, padx=8, pady=4).pack(side="left")
        tk.Button(header, text="limpar", font=FONT_TINY, fg=MUTED,
                  bg=BG3, activebackground=BG3, activeforeground=GREEN,
                  bd=0, cursor="hand2", command=self.clear).pack(side="right", padx=8)

        self.text = scrolledtext.ScrolledText(
            self, font=FONT_MONO, bg=BG, fg=GREEN,
            insertbackground=GREEN, bd=0, padx=12, pady=10,
            wrap="word", state="disabled", relief="flat",
            selectbackground=BG3, selectforeground=GREEN
        )
        self.text.pack(fill="both", expand=True)
        self.text.tag_config("err", foreground=RED)
        self.text.tag_config("ok",  foreground=CYAN)
        self.text.tag_config("sep", foreground=MUTED)

    def insert_line(self, msg: str, tag: str = ""):
        self.text.configure(state="normal")
        self.text.insert("end", msg.rstrip("\n") + "\n", tag)
        self.text.see("end")
        self.text.configure(state="disabled")

    def clear(self):
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        self.text.configure(state="disabled")

    def separator(self, label=""):
        line = f"{'─'*20} {label} {'─'*20}" if label else "─"*44
        self.insert_line(line, "sep")

class Card(tk.Frame):
    def __init__(self, master, title: str, output: OutputBox, **kw):
        super().__init__(master, bg=BG2, bd=0, highlightthickness=1,
                         highlightbackground=BORDER, **kw)
        self.output = output
        self._fields: dict[str, tk.StringVar] = {}
        self._build_header(title)
        self.body = tk.Frame(self, bg=BG2)
        self.body.pack(fill="x", padx=14, pady=(0, 14))

    def _build_header(self, title):
        h = tk.Frame(self, bg=BG3)
        h.pack(fill="x")
        tk.Label(h, text=f" {title}", font=FONT_HEAD,
                 fg=GREEN, bg=BG3, padx=10, pady=8).pack(side="left")

    def field(self, label: str, key: str, placeholder: str = "", wide: bool = False):
        """Adiciona um campo de entrada ao card."""
        row = tk.Frame(self.body, bg=BG2)
        row.pack(fill="x", pady=3)
        tk.Label(row, text=label, font=FONT_UI, fg=MUTED,
                 bg=BG2, width=16, anchor="w").pack(side="left")
        var = tk.StringVar()
        width = 52 if wide else 32
        e = tk.Entry(row, textvariable=var, font=FONT_MONO,
                     bg=BG3, fg=TEXT, insertbackground=GREEN,
                     bd=0, highlightthickness=1,
                     highlightbackground=BORDER,
                     highlightcolor=GREEN,
                     width=width, relief="flat")
        e.pack(side="left", padx=(4, 0), ipady=4)
        if placeholder:
            e.insert(0, placeholder)
            e.config(fg=MUTED)
            def on_focus_in(ev, en=e, v=var, p=placeholder):
                if v.get() == p:
                    en.delete(0, "end")
                    en.config(fg=TEXT)
            def on_focus_out(ev, en=e, v=var, p=placeholder):
                if not v.get():
                    en.insert(0, p)
                    en.config(fg=MUTED)
            e.bind("<FocusIn>",  on_focus_in)
            e.bind("<FocusOut>", on_focus_out)
        self._fields[key] = var
        return var

    def text_field(self, label: str, key: str, placeholder: str = ""):
        """Campo de texto multi-linha."""
        row = tk.Frame(self.body, bg=BG2)
        row.pack(fill="x", pady=3)
        tk.Label(row, text=label, font=FONT_UI, fg=MUTED,
                 bg=BG2, width=16, anchor="nw").pack(side="left", anchor="n")
        frame = tk.Frame(row, bg=BG3, highlightthickness=1,
                         highlightbackground=BORDER)
        frame.pack(side="left", padx=(4, 0))
        t = tk.Text(frame, font=FONT_MONO, bg=BG3, fg=MUTED,
                    insertbackground=GREEN, bd=0, width=52, height=3,
                    relief="flat", padx=6, pady=4)
        t.pack()
        t.insert("1.0", placeholder)

        def on_focus_in(ev):
            if t.get("1.0", "end-1c") == placeholder:
                t.delete("1.0", "end")
                t.config(fg=TEXT)
        def on_focus_out(ev):
            if not t.get("1.0", "end-1c").strip():
                t.insert("1.0", placeholder)
                t.config(fg=MUTED)

        t.bind("<FocusIn>",  on_focus_in)
        t.bind("<FocusOut>", on_focus_out)

        self._fields[key] = t
        return t

    def get(self, key: str) -> str:
        v = self._fields[key]
        if isinstance(v, tk.StringVar):
            return v.get()
        else:
            return v.get("1.0", "end-1c")

    def button(self, label: str, command):
        btn = tk.Button(
            self.body, text=label, font=("Courier New", 10, "bold"),
            fg=BG, bg=GREEN, activebackground=GREEN_DIM, activeforeground=BG,
            bd=0, cursor="hand2", relief="flat", padx=16, pady=6,
            command=command
        )
        btn.pack(anchor="w", pady=(8, 0))
        return btn

    def run_threaded(self, fn):
        """Executa fn numa thread e redireciona prints para o output."""
        def task():
            redir = Redirect(self.output)
            old = sys.stdout
            sys.stdout = redir
            try:
                result = fn()
                if result is not None:
                    self.output.insert_line(str(result), "ok")
            except Exception as ex:
                self.output.insert_line(f"ERRO: {ex}", "err")
            finally:
                sys.stdout = old
        threading.Thread(target=task, daemon=True).start()

class LinksCard(Card):
    def __init__(self, master, output):
        super().__init__(master, "Extração de Links", output)
        self.text_field("HTML", "html", "Cole o HTML aqui...")
        self.button("▶  Extrair Links", self._run)

    def _run(self):
        html = self.get("html")
        self.output.separator("links")
        def fn():
            result = links(html)
            if result:
                for l in result:
                    self.output.insert_line(f"  {l}", "ok")
                self.output.insert_line(f"\nTotal: {len(result)} links", "sep")
            else:
                self.output.insert_line("Nenhum link encontrado.", "err")
        self.run_threaded(fn)

class SubdomainCard(Card):
    def __init__(self, master, output):
        super().__init__(master, "Enumeração de Subdomínios", output)
        self.field("Domínio", "domain", "exemplo.com")
        self.field("Wordlist (caminho)", "wordlist", "/path/to/wordlist.txt", wide=True)
        tk.Label(self.body, text="Informe o caminho absoluto para o arquivo (.txt, um subdomínio por linha)",
                 font=FONT_TINY, fg=MUTED, bg=BG2).pack(anchor="w", pady=(0, 2))

        btn_row = tk.Frame(self.body, bg=BG2)
        btn_row.pack(anchor="w", pady=(8, 0))
        self._btn = tk.Button(btn_row, text="▶  Enumerar",
                              font=("Courier New", 10, "bold"),
                              fg=BG, bg=GREEN, activebackground=GREEN_DIM,
                              activeforeground=BG, bd=0, cursor="hand2",
                              relief="flat", padx=16, pady=6, command=self._run)
        self._btn.pack(side="left")
        self._stop_btn = tk.Button(btn_row, text="■  Parar",
                                   font=("Courier New", 10, "bold"),
                                   fg=BG, bg=RED, activebackground="#cc3050",
                                   activeforeground=BG, bd=0, cursor="hand2",
                                   relief="flat", padx=12, pady=6,
                                   command=self._stop, state="disabled")
        self._stop_btn.pack(side="left", padx=(8, 0))
        self._running = False
        self._stopped = False

    def _stop(self):
        self._stopped = True

    def _run(self):
        if self._running:
            return
        domain = self.get("domain")
        pwfile = self.get("wordlist")
        self.output.separator("subdomínios")

        def fn():
            self._running = True
            self._stopped = False
            self._btn.config(text="⏳  Executando...", state="disabled")
            self._stop_btn.config(state="normal")
            try:
                with open(pwfile, "r", errors="ignore") as f:
                    wordlist = [l.strip() for l in f if l.strip()]
            except FileNotFoundError:
                self.output.insert_line(f"Arquivo não encontrado: {pwfile}", "err")
                self._running = False
                self._btn.config(text="▶  Enumerar", state="normal")
                self._stop_btn.config(state="disabled")
                return

            self.output.insert_line(f"[*] {len(wordlist)} entradas carregadas", "sep")
            encontrados = []
            for sub in wordlist:
                if self._stopped:
                    self.output.insert_line("\n[!] Interrompido pelo usuário.", "sep")
                    break
                subdominio = f"{sub}.{domain}"
                try:
                    ip = socket.gethostbyname(subdominio)
                    self.output.insert_line(f"  {subdominio} — {ip}", "ok")
                    encontrados.append((subdominio, ip))
                except socket.gaierror:
                    pass

            if not self._stopped:
                if encontrados:
                    self.output.insert_line(f"\nTotal encontrado: {len(encontrados)}", "sep")
                else:
                    self.output.insert_line("Nenhum subdomínio encontrado.", "err")

            self._running = False
            self._btn.config(text="▶  Enumerar", state="normal")
            self._stop_btn.config(state="disabled")

        threading.Thread(target=fn, daemon=True).start()

class DirsCard(Card):
    def __init__(self, master, output):
        super().__init__(master, "Enumeração de Diretórios", output)
        self.field("URL Base", "url", "https://alvo.com")
        self.field("Wordlist (caminho)", "wordlist", "/path/to/wordlist.txt", wide=True)
        tk.Label(self.body, text="Informe o caminho absoluto para o arquivo de palavras (.txt, uma por linha)",
                 font=FONT_TINY, fg=MUTED, bg=BG2).pack(anchor="w", pady=(0, 2))

        btn_row = tk.Frame(self.body, bg=BG2)
        btn_row.pack(anchor="w", pady=(8, 0))
        self._btn  = tk.Button(btn_row, text="▶  Buscar Diretórios",
                               font=("Courier New", 10, "bold"),
                               fg=BG, bg=GREEN, activebackground=GREEN_DIM,
                               activeforeground=BG, bd=0, cursor="hand2",
                               relief="flat", padx=16, pady=6, command=self._run)
        self._btn.pack(side="left")
        self._stop_btn = tk.Button(btn_row, text="■  Parar",
                                   font=("Courier New", 10, "bold"),
                                   fg=BG, bg=RED, activebackground="#cc3050",
                                   activeforeground=BG, bd=0, cursor="hand2",
                                   relief="flat", padx=12, pady=6,
                                   command=self._stop, state="disabled")
        self._stop_btn.pack(side="left", padx=(8, 0))
        self._running  = False
        self._stopped  = False

    def _stop(self):
        self._stopped = True

    def _run(self):
        if self._running:
            return
        import hashlib
        url    = self.get("url")
        pwfile = self.get("wordlist")
        self.output.separator("diretórios")

        def fn():
            self._running = True
            self._stopped = False
            self._btn.config(text="⏳  Executando...", state="disabled")
            self._stop_btn.config(state="normal")
            try:
                with open(pwfile, "r", errors="ignore") as f:
                    wordlist = [l.strip() for l in f if l.strip()]
            except FileNotFoundError:
                self.output.insert_line(f"Arquivo não encontrado: {pwfile}", "err")
                self._running = False
                self._btn.config(text="▶  Buscar Diretórios", state="normal")
                self._stop_btn.config(state="disabled")
                return

            self.output.insert_line(f"[*] {len(wordlist)} palavras carregadas", "sep")

            try:
                baseline = requests.get(
                    f"{url.rstrip('/')}/__baseline_xyzxyz123__",
                    timeout=3, headers=HEADERS
                )
                baseline_hash = hashlib.md5(baseline.content).hexdigest()
            except Exception as e:
                self.output.insert_line(f"Erro ao conectar: {e}", "err")
                self._running = False
                self._btn.config(text="▶  Buscar Diretórios", state="normal")
                self._stop_btn.config(state="disabled")
                return

            encontrados = []
            for word in wordlist:
                if self._stopped:
                    self.output.insert_line("\n[!] Interrompido pelo usuário.", "sep")
                    break
                target = f"{url.rstrip('/')}/{word}.html"
                try:
                    r = requests.get(target, timeout=3, headers=HEADERS)
                    if hashlib.md5(r.content).hexdigest() != baseline_hash:
                        self.output.insert_line(f"[{r.status_code}] {target}  ({len(r.content)} bytes)", "ok")
                        encontrados.append(target)
                except requests.RequestException:
                    pass

            if not self._stopped:
                if encontrados:
                    self.output.insert_line(f"\nTotal encontrado: {len(encontrados)}", "sep")
                else:
                    self.output.insert_line("Nenhum diretório encontrado.", "err")

            self._running = False
            self._btn.config(text="▶  Buscar Diretórios", state="normal")
            self._stop_btn.config(state="disabled")

        threading.Thread(target=fn, daemon=True).start()

class ArpCard(Card):
    def __init__(self, master, output):
        super().__init__(master, "ARP Scan", output)
        self.field("Faixa IP (CIDR)", "range", "192.168.1.0/24")
        self.field("Interface", "iface", "eth0 (opcional)")
        self.button("▶  Iniciar ARP Scan", self._run)

    def _run(self):
        ip_range  = self.get("range")
        raw_iface = self.get("iface")
        iface = None if "opcional" in raw_iface or not raw_iface.strip() else raw_iface.strip()
        self.output.separator("arp scan")
        def fn():
            devices = arp_scan(ip_range, iface)
            if not devices:
                self.output.insert_line("Nenhum dispositivo encontrado.", "err")
            else:
                for d in devices:
                    self.output.insert_line(f"  IP: {d['ip']}  MAC: {d['mac']}", "ok")
                self.output.insert_line(f"\nTotal: {len(devices)} dispositivos", "sep")
        self.run_threaded(fn)

class PortCard(Card):
    def __init__(self, master, output):
        super().__init__(master, "Port Scan", output)
        self.field("Alvo (IP)", "ip", "192.168.1.1")
        self.field("Portas", "ports", "80,443,22,21,8080-8090")
        tk.Label(self.body, text="Aceita: 80,443  ou  80-1024  ou combinação",
                 font=FONT_TINY, fg=MUTED, bg=BG2).pack(anchor="w", pady=(0, 2))

        btn_row = tk.Frame(self.body, bg=BG2)
        btn_row.pack(anchor="w", pady=(8, 0))
        self._btn = tk.Button(btn_row, text="▶  Iniciar Port Scan",
                              font=("Courier New", 10, "bold"),
                              fg=BG, bg=GREEN, activebackground=GREEN_DIM,
                              activeforeground=BG, bd=0, cursor="hand2",
                              relief="flat", padx=16, pady=6, command=self._run)
        self._btn.pack(side="left")
        self._stop_btn = tk.Button(btn_row, text="■  Parar",
                                   font=("Courier New", 10, "bold"),
                                   fg=BG, bg=RED, activebackground="#cc3050",
                                   activeforeground=BG, bd=0, cursor="hand2",
                                   relief="flat", padx=12, pady=6,
                                   command=self._stop, state="disabled")
        self._stop_btn.pack(side="left", padx=(8, 0))
        self._running = False
        self._stopped = False

    def _stop(self):
        self._stopped = True

    def _run(self):
        if self._running:
            return
        ip    = self.get("ip")
        ports = parse_ports(self.get("ports"))
        self.output.separator("port scan")

        def fn():
            self._running = True
            self._stopped = False
            self._btn.config(text="⏳  Executando...", state="disabled")
            self._stop_btn.config(state="normal")
            self.output.insert_line(f"[*] Escaneando {len(ports)} porta(s) em {ip} (50 threads)...", "sep")

            abertas = port_scan(ip, ports, stop_flag=lambda: self._stopped)

            for p in sorted(abertas):
                self.output.insert_line(f"  [+] Porta aberta: {p}", "ok")

            if self._stopped:
                self.output.insert_line("\n[!] Interrompido pelo usuário.", "sep")
            elif abertas:
                self.output.insert_line(f"\nTotal: {len(abertas)} porta(s) aberta(s)", "sep")
            else:
                self.output.insert_line("Nenhuma porta aberta encontrada.", "err")

            self._running = False
            self._btn.config(text="▶  Iniciar Port Scan", state="normal")
            self._stop_btn.config(state="disabled")

        threading.Thread(target=fn, daemon=True).start()

class SshCard(Card):
    def __init__(self, master, output):
        super().__init__(master, "SSH Bruteforce", output)
        self.field("Alvo (IP)", "target", "192.168.1.1")
        self.field("Usuário", "usuario", "root")
        self.field("Wordlist (caminho)", "pwfile", "/path/to/passwords.txt", wide=True)
        tk.Label(self.body,
                 text="Informe o caminho absoluto para o arquivo de senhas (.txt, uma por linha)",
                 font=FONT_TINY, fg=MUTED, bg=BG2).pack(anchor="w", pady=(0, 2))

        btn_row = tk.Frame(self.body, bg=BG2)
        btn_row.pack(anchor="w", pady=(8, 0))
        self._btn = tk.Button(btn_row, text="▶  Iniciar Bruteforce",
                              font=("Courier New", 10, "bold"),
                              fg=BG, bg=GREEN, activebackground=GREEN_DIM,
                              activeforeground=BG, bd=0, cursor="hand2",
                              relief="flat", padx=16, pady=6, command=self._run)
        self._btn.pack(side="left")
        self._stop_btn = tk.Button(btn_row, text="■  Parar",
                                   font=("Courier New", 10, "bold"),
                                   fg=BG, bg=RED, activebackground="#cc3050",
                                   activeforeground=BG, bd=0, cursor="hand2",
                                   relief="flat", padx=12, pady=6,
                                   command=self._stop, state="disabled")
        self._stop_btn.pack(side="left", padx=(8, 0))
        self._running = False
        self._stopped = False

    def _stop(self):
        self._stopped = True

    def _run(self):
        if self._running:
            return
        import paramiko
        target  = self.get("target")
        usuario = self.get("usuario")
        pwfile  = self.get("pwfile")

        if not target or not usuario or not pwfile:
            self.output.insert_line("Preencha todos os campos antes de executar.", "err")
            return

        self.output.separator("ssh bruteforce")

        def fn():
            self._running = True
            self._stopped = False
            self._btn.config(text="⏳  Executando...", state="disabled")
            self._stop_btn.config(state="normal")
            try:
                with open(pwfile, "r", errors="ignore") as f:
                    senhas = [l.strip() for l in f if l.strip()]
            except FileNotFoundError:
                self.output.insert_line(f"Arquivo não encontrado: {pwfile}", "err")
                self._running = False
                self._btn.config(text="▶  Iniciar Bruteforce", state="normal")
                self._stop_btn.config(state="disabled")
                return

            self.output.insert_line(f"[*] {len(senhas)} senhas carregadas", "sep")
            encontrado = None
            for senha in senhas:
                if self._stopped:
                    self.output.insert_line("\n[!] Interrompido pelo usuário.", "sep")
                    break
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                try:
                    ssh.connect(target, port=22, username=usuario, password=senha, timeout=5)
                    ssh.close()
                    self.output.insert_line(f"\n✔  SENHA ENCONTRADA: {senha}", "ok")
                    encontrado = senha
                    break
                except paramiko.AuthenticationException:
                    pass
                except Exception as e:
                    print(f"Erro inesperado: {type(e).__name__}: {e}")
                    self.output.insert_line(f"Erro: {e}", "err")
                    break

            if not self._stopped and not encontrado:
                self.output.insert_line("\n✘  Nenhuma senha funcionou.", "err")

            self._running = False
            self._btn.config(text="▶  Iniciar Bruteforce", state="normal")
            self._stop_btn.config(state="disabled")

        threading.Thread(target=fn, daemon=True).start()

class CrackerCard(Card):
    def __init__(self, master, output):
        super().__init__(master, "Hash Cracker", output)
        self.field("Hash alvo", "hash", "5f4dcc3b5aa765d61d8327deb882cf99", wide=True)
        self.field("Wordlist (caminho)", "pwfile", "/path/to/wordlist.txt", wide=True)

        row = tk.Frame(self.body, bg=BG2)
        row.pack(fill="x", pady=3)
        tk.Label(row, text="Algoritmo", font=FONT_UI, fg=MUTED,
                 bg=BG2, width=16, anchor="w").pack(side="left")
        self._algo_var = tk.StringVar(value="md5")
        menu = tk.OptionMenu(row, self._algo_var, *ALGORITMOS_SUPORTADOS)
        menu.config(font=FONT_MONO, bg=BG3, fg=GREEN, activebackground=BG3,
                    activeforeground=GREEN, bd=0, highlightthickness=1,
                    highlightbackground=BORDER, relief="flat", cursor="hand2")
        menu["menu"].config(font=FONT_MONO, bg=BG3, fg=TEXT,
                            activebackground=BG, activeforeground=GREEN, bd=0)
        menu.pack(side="left", padx=(4, 0))

        btn_row = tk.Frame(self.body, bg=BG2)
        btn_row.pack(anchor="w", pady=(8, 0))
        self._btn = tk.Button(btn_row, text="▶  Iniciar Cracker",
                              font=("Courier New", 10, "bold"),
                              fg=BG, bg=GREEN, activebackground=GREEN_DIM,
                              activeforeground=BG, bd=0, cursor="hand2",
                              relief="flat", padx=16, pady=6, command=self._run)
        self._btn.pack(side="left")
        self._stop_btn = tk.Button(btn_row, text="■  Parar",
                                   font=("Courier New", 10, "bold"),
                                   fg=BG, bg=RED, activebackground="#cc3050",
                                   activeforeground=BG, bd=0, cursor="hand2",
                                   relief="flat", padx=12, pady=6,
                                   command=self._stop, state="disabled")
        self._stop_btn.pack(side="left", padx=(8, 0))
        self._running = False
        self._stopped = False

    def _stop(self):
        self._stopped = True

    def _run(self):
        if self._running:
            return
        import hashlib
        hash_input = self.get("hash")
        pwfile     = self.get("pwfile")
        algoritmo  = self._algo_var.get()

        if not hash_input or not pwfile:
            self.output.insert_line("Preencha o hash e o caminho da wordlist.", "err")
            return

        self.output.separator("hash cracker")

        def fn():
            self._running = True
            self._stopped = False
            self._btn.config(text="⏳  Executando...", state="disabled")
            self._stop_btn.config(state="normal")
            try:
                with open(pwfile, "r", errors="ignore") as f:
                    senhas = [l.strip() for l in f if l.strip()]
            except FileNotFoundError:
                self.output.insert_line(f"Arquivo não encontrado: {pwfile}", "err")
                self._running = False
                self._btn.config(text="▶  Iniciar Cracker", state="normal")
                self._stop_btn.config(state="disabled")
                return

            self.output.insert_line(f"[*] {len(senhas)} entradas carregadas ({algoritmo.upper()})", "sep")
            encontrado = None
            for senha in senhas:
                if self._stopped:
                    self.output.insert_line("\n[!] Interrompido pelo usuário.", "sep")
                    break
                h = hashlib.new(algoritmo, senha.encode()).hexdigest()
                if h == hash_input.strip().lower():
                    self.output.insert_line(f"\n✔  SENHA ENCONTRADA: {senha}", "ok")
                    encontrado = senha
                    break

            if not self._stopped and not encontrado:
                self.output.insert_line("\n✘  Hash não encontrado na wordlist.", "err")

            self._running = False
            self._btn.config(text="▶  Iniciar Cracker", state="normal")
            self._stop_btn.config(state="disabled")

        threading.Thread(target=fn, daemon=True).start()

class SherlockApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Sherlock — Recon & Enumeration")
        self.configure(bg=BG)
        self.geometry("960x820")
        self.minsize(800, 600)
        self._build()

    def _build(self):

        header = tk.Frame(self, bg=BG)
        header.pack(fill="x", padx=20, pady=(16, 8))

        tk.Label(header, text="SHERLOCK", font=("Courier New", 22, "bold"),
                 fg=GREEN, bg=BG).pack(side="left")
        tk.Label(header, text=" // recon & enumeration toolkit",
                 font=("Courier New", 11), fg=MUTED, bg=BG).pack(side="left", pady=4)

        sep = tk.Frame(self, bg=BORDER, height=1)
        sep.pack(fill="x", padx=20, pady=(0, 12))

        pane = tk.PanedWindow(self, orient="horizontal", bg=BG,
                              sashwidth=6, sashrelief="flat",
                              bd=0, handlesize=0)
        pane.pack(fill="both", expand=True, padx=16, pady=(0, 16))

        left = tk.Frame(pane, bg=BG)

        canvas = tk.Canvas(left, bg=BG, bd=0, highlightthickness=0)
        scrollbar = ttk.Scrollbar(left, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        inner = tk.Frame(canvas, bg=BG)
        win_id = canvas.create_window((0, 0), window=inner, anchor="nw")

        def on_configure(ev):
            canvas.configure(scrollregion=canvas.bbox("all"))
        def on_canvas_resize(ev):
            canvas.itemconfig(win_id, width=ev.width)

        inner.bind("<Configure>", on_configure)
        canvas.bind("<Configure>", on_canvas_resize)
        canvas.bind_all("<MouseWheel>",
                        lambda e: canvas.yview_scroll(-1*(e.delta//120), "units"))

        pane.add(left, minsize=480)

        right  = tk.Frame(pane, bg=BG2)
        output = OutputBox(right)
        output.pack(fill="both", expand=True)
        output.insert_line("Sistema pronto. Insira os parâmetros e execute uma função.\n", "sep")
        pane.add(right, minsize=280)

        PADDING = {"fill": "x", "padx": 8, "pady": 6}
        LinksCard    (inner, output).pack(**PADDING)
        SubdomainCard(inner, output).pack(**PADDING)
        DirsCard     (inner, output).pack(**PADDING)
        ArpCard      (inner, output).pack(**PADDING)
        PortCard     (inner, output).pack(**PADDING)
        SshCard      (inner, output).pack(**PADDING)
        CrackerCard  (inner, output).pack(**PADDING)

        tk.Label(self, text="use com responsabilidade e apenas em ambientes autorizados",
                 font=FONT_TINY, fg=MUTED, bg=BG).pack(pady=(0, 6))

if __name__ == "__main__":
    app = SherlockApp()
    app.mainloop()