#!/usr/bin/env bash
# Module: Arsenal Updater (bash-pro)
set -Eeuo pipefail
IFS=$'\n\t'
shopt -s inherit_errexit

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${SCRIPT_DIR}/core/utils.sh"

W_DIR="${SCRIPT_DIR}/config/Wordlists"
mkdir -p "$W_DIR"

log_info "[*] Iniciando Atualização do Arsenal (Wordlists)..."

# 1. Sync Assetnote Deltas (Example endpoints)
# Nota: Em um Kali Linux real, usaríamos os caminhos em /usr/share/wordlists/
# Mas para o enumIA, mantemos a capacidade de baixar listas otimizadas para Cloud/API.
log_info "  └─ Verificando caminhos de API em Assetnote..."
curl -s "https://wordlists-cdn.assetnote.io/data/manual/api-endpoints.txt" | anew "$W_DIR/wordlist_final.txt" > /dev/null

# 2. Sync DNS Deltas
log_info "  └─ Verificando novos subdomínios descobertos globalmente..."
curl -s "https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt" | head -n 5000 | anew "$W_DIR/wordlist_sdm.txt" > /dev/null

log_info "[✅] Arsenal atualizado com sucesso."
