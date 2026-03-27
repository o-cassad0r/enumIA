set -Eeuo pipefail
IFS=$'\n\t'
shopt -s inherit_errexit

source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../core" && pwd)/utils.sh"

export PATH=$PATH:$HOME/go/bin

DEFAULT_WORDLIST="/usr/share/wordlists/seclists/Discovery/DNS/n0kovo_subdomains.txt"
THREADS=100

show_progress() {
  while read -r line; do
    echo -ne "\r$1 $line    "
    sleep 0.05
  done
  echo
}

run_step_safe() {
  local file=$1
  shift
  local tmpfile="${file}.tmp"

  if [ -f "$file" ] && [ $(stat -c%s "$file") -gt 100 ]; then
    log_info "Arquivo $file válido encontrado. Pulando etapa."
  else
    log_info "Executando etapa e salvando em $file..."
    if "$@" 2>&1 | tee "$tmpfile" | show_progress "$2"; then
      mv "$tmpfile" "$file"
      echo "[+] Etapa concluída, arquivo salvo em $file"
    else
      echo "[!] Erro na etapa. Arquivo temporário removido."
      rm -f "$tmpfile"
      exit 1
    fi
  fi
}

if [ -z "$1" ]; then
  read -p "Informe o domínio a ser enumerado (ex: exemplo.com): " DOM
else
  DOM=$1
fi

if [ -z "$DOM" ]; then
  echo "[ERRO] Domínio não informado. Encerrando."
  exit 1
fi

# Loop para validação da wordlist
while true; do
  read -p "Informe o caminho da wordlist para brute-force [padrão: $DEFAULT_WORDLIST]: " WORDLIST
  WORDLIST=${WORDLIST:-$DEFAULT_WORDLIST}
  if [ -f "$WORDLIST" ]; then
    break
  else
    echo "[ERRO] Wordlist '$WORDLIST' não encontrada. Por favor, informe um caminho válido."
  fi
done

echo "==============================="

run_step_safe "${DOM}-subfinder.txt" subfinder -d "$DOM" -silent "Subfinder:"
run_step_safe "${DOM}-assetfinder.txt" assetfinder --subs-only "$DOM" "Assetfinder:"
run_step_safe "${DOM}-amass.txt" amass enum -passive -d "$DOM" "Amass:"

if [ -f "${DOM}-subs-passivos.txt" ] && [ $(stat -c%s "${DOM}-subs-passivos.txt") -gt 100 ]; then
  echo "[*] Arquivo ${DOM}-subs-passivos.txt válido encontrado. Pulando consolidação."
else
  echo "[+] Consolidando subdomínios passivos..."
  cat "${DOM}-subfinder.txt" "${DOM}-assetfinder.txt" "${DOM}-amass.txt" | sort -u | tee "${DOM}-subs-passivos.txt"
fi
CMD="cat ${DOM}-subs-passivos.txt | dnsx -silent -resp"
run_step_safe "${DOM}-ativos-passivos.txt" "$CMD" "DNSx (passivos):"
run_step_safe "${DOM}-ativos-brute.txt" dnsx -d "$DOM" -w "$WORDLIST" -silent "DNSx (brute-force):"

if [ -f "${DOM}-ativos-final.txt" ] && [ $(stat -c%s "${DOM}-ativos-final.txt") -gt 100 ]; then
  echo "[*] Arquivo ${DOM}-ativos-final.txt válido encontrado. Pulando consolidação."
else
  echo "[+] Consolidando ativos DNS (passivos + brute)..."
  cat "${DOM}-ativos-passivos.txt" "${DOM}-ativos-brute.txt" | sort -u | tee "${DOM}-ativos-final.txt"
fi

run_step_safe "${DOM}-httpx.txt" bash -c "cat ${DOM}-ativos-final.txt | httpx -silent -status-code -title -threads $THREADS" "Httpx:"

echo "==============================="
echo "[+] Resumo:"
echo " - Subdomínios passivos únicos: $(wc -l < ${DOM}-subs-passivos.txt)"
echo " - Subdomínios ativos DNS: $(wc -l < ${DOM}-ativos-final.txt)"
echo " - Subdomínios HTTP/S ativos: $(wc -l < ${DOM}-httpx.txt)"

if command -v fzf >/dev/null 2>&1; then
  echo
  echo "[+] Visualizar HTTP/S ativos com fzf (ESC para sair)"
  cat "${DOM}-httpx.txt" | fzf --preview="echo {}" --height=30% --border
fi
