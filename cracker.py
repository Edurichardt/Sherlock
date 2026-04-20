import hashlib

ALGORITMOS_SUPORTADOS = ["md5", "sha1", "sha224", "sha256", "sha384", "sha512"]


def wordlist_hash_cracker(hash_input: str, wordlist_path: str, algoritmo: str = "md5"):
    """
    Tenta quebrar um hash comparando com cada senha de uma wordlist.

    Parâmetros:
        hash_input    — hash alvo (ex: "5f4dcc3b5aa765d61d8327deb882cf99")
        wordlist_path — caminho para o arquivo de senhas (.txt, uma por linha)
        algoritmo     — algoritmo do hash: md5, sha1, sha256, sha512, etc.

    Retorna a senha em texto plano se encontrada, ou None.
    """
    algoritmo = algoritmo.lower().strip()

    if algoritmo not in ALGORITMOS_SUPORTADOS:
        print(f"Algoritmo '{algoritmo}' não suportado. Use: {', '.join(ALGORITMOS_SUPORTADOS)}")
        return None

    try:
        with open(wordlist_path, "r", errors="ignore") as f:
            senhas = [linha.strip() for linha in f if linha.strip()]
    except FileNotFoundError:
        print(f"Arquivo não encontrado: {wordlist_path}")
        return None

    print(f"Iniciando cracker ({algoritmo.upper()}) com {len(senhas)} entradas...\n")

    for i, senha in enumerate(senhas, 1):
        h = hashlib.new(algoritmo, senha.encode()).hexdigest()
        if h == hash_input.strip().lower():
            print(f"[+] Senha encontrada: {senha}")
            return senha

        if i % 5000 == 0:
            print(f"[{i}/{len(senhas)}] testando...")

    print("[-] Hash não encontrado na wordlist.")
    return None