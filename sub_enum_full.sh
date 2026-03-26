#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
shopt -s inherit_errexit   # Bash 4.4+

export PATH="$PATH:$HOME/go/bin"
# Usage: ./sub_enum_full.sh dominio.com

DOM="${1:-}"
WORDLIST="$HOME/tools/enum/Wordlists/wordlist_sdm.txt"
THREADS=100

if [[ ! "$DOM" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$ ]]; then
  echo "Uso correto: $0 erome.com"
  exit 1
fi

echo "==============================="
echo "[+] Coletando passivamente..."
(subfinder -d "$DOM" -silent; assetfinder --subs-only "$DOM"; amass enum -passive -d "$DOM") | sort -u > "${DOM}-subs-passivos.txt"

echo "[+] Resolvendo DNS (Passivos)..."
cat "${DOM}-subs-passivos.txt" | dnsx -silent -resp -o "${DOM}-ativos-passivos.txt"

echo "[+] Realizando Brute-force com $WORDLIST..."
dnsx -d "$DOM" -w "$WORDLIST" -silent -o "${DOM}-ativos-brute.txt"

echo "[+] Consolidando resultados únicos..."
cat "${DOM}-ativos-passivos.txt" "${DOM}-ativos-brute.txt" | sort -u > "${DOM}-ativos-final.txt"

echo "[+] Verificando HTTP/S (${THREADS} threads)..."
cat "${DOM}-ativos-final.txt" | httpx -silent -status-code -title -threads "$THREADS" -o "${DOM}-httpx.txt"

echo "==============================="
echo "[+] Subdomínios encontrados (ativos DNS): $(wc -l < "${DOM}-ativos-final.txt")"
echo "[+] Subdomínios HTTP/S ativos: $(wc -l < "${DOM}-httpx.txt")"
echo "[+] Resultados salvos em:"
echo " - ${DOM}-subs-passivos.txt"
echo " - ${DOM}-ativos-passivos.txt"
echo " - ${DOM}-ativos-brute.txt"
echo " - ${DOM}-ativos-final.txt"
echo " - ${DOM}-httpx.txt"

# Opcional: visualizar resultado HTTP/S com fzf
if command -v fzf >/dev/null 2>&1; then
  echo
  echo "[+] Visualizar resultado com fzf (pressione ESC para sair)"
  cat "${DOM}-httpx.txt" | fzf --preview="echo {}" --height=30% --border
fi
