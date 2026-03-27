#!/usr/bin/env bash
# Module: WAF/403 Bypass (bash-pro)
set -Eeuo pipefail
IFS=$'\n\t'
shopt -s inherit_errexit

source core/utils.sh

# Configurações
WORDLIST="/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-big.txt"

THREADS=100
SUB="${1:-}"

if [[ ! "$SUB" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$ ]]; then
    printf "Erro: Domínio inválido '%s'\n" "$SUB" >&2
    exit 1
fi

OUTDIR="./bypass-$SUB"
mkdir -p "$OUTDIR"

log_info "Testando HEADERS com httpx"
echo "$SUB" | httpx -silent -path /admin -status-code -title \
-H "X-Forwarded-For: 127.0.0.1" \
-H "X-Original-URL: /admin" \
-H "X-Forwarded-Host: internal" \
> "$OUTDIR/httpx-admin-test.txt"

log_info "Rodando FFUF padrão em https://$SUB/"
ffuf -w "$WORDLIST" -u "https://$SUB/FUZZ" -mc all -fs 0 -fc 403,404,410 -t "$THREADS" \
> "$OUTDIR/ffuf-standard.txt"

log_info "Rodando FFUF com Headers de Bypass"
ffuf -w "$WORDLIST" -u "https://$SUB/FUZZ" \
-H "X-Forwarded-For: 127.0.0.1" \
-H "X-Original-URL: /admin" \
-H "X-Forwarded-Host: internal" \
-mc all -fs 0 -fc 403,404,410 -t "$THREADS" \
> "$OUTDIR/ffuf-bypass.txt"

log_info "Coletando URLs do Wayback"
echo "$SUB" | waybackurls | tee "$OUTDIR/waybackurls.txt"

log_info "Finalizado. Resultados em $OUTDIR"
