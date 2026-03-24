#!/bin/bash

set -euo pipefail
IFS=$'\n\t'

# Configurações
WORDLIST="/usr/share/seclists/Discovery/Web-Content/common.txt"
THREADS=100
SUB=$1
OUTDIR="./bypass-$SUB"
mkdir -p "$OUTDIR"

echo "[+] Testando HEADERS com httpx"
echo "$SUB" | httpx -silent -path /admin -status-code -title \
-H "X-Forwarded-For: 127.0.0.1" \
-H "X-Original-URL: /admin" \
-H "X-Forwarded-Host: internal" \
> "$OUTDIR/httpx-admin-test.txt"

echo "[+] Rodando FFUF padrão em https://$SUB/"
ffuf -w "$WORDLIST" -u "https://$SUB/FUZZ" -mc all -fs 0 -fc 403,404,410 -t "$THREADS" \
> "$OUTDIR/ffuf-standard.txt"

echo "[+] Rodando FFUF com Headers de Bypass"
ffuf -w "$WORDLIST" -u "https://$SUB/FUZZ" \
-H "X-Forwarded-For: 127.0.0.1" \
-H "X-Original-URL: /admin" \
-H "X-Forwarded-Host: internal" \
-mc all -fs 0 -fc 403,404,410 -t "$THREADS" \
> "$OUTDIR/ffuf-bypass.txt"

echo "[+] Coletando URLs do Wayback"
echo "$SUB" | waybackurls | tee "$OUTDIR/waybackurls.txt"

echo "[+] Finalizado. Resultados em $OUTDIR"
