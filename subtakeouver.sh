#!/usr/bin/env bash
# subtakeouver.sh — Subdomain Takeover via CNAME enumeration
# Hardened: 2026-03-25  (bash-defensive-patterns + shellscript.md + security.md)
# Usage: ./subtakeouver.sh <domain> [wordlist]
set -Eeuo pipefail
IFS=$'\n\t'
shopt -s inherit_errexit   # Bash 4.4+

# ──────────────────────────────────────────────────────────── logging ──
log_info()  { printf "\033[0;32m[%s][INFO]\033[0m  %s\n"  "$(date '+%H:%M:%S')" "$*" >&2; }
log_warn()  { printf "\033[1;33m[%s][WARN]\033[0m  %s\n"  "$(date '+%H:%M:%S')" "$*" >&2; }
log_error() { printf "\033[0;31m[%s][ERROR]\033[0m %s\n" "$(date '+%H:%M:%S')" "$*" >&2; }

# ──────────────────────────────────────────────── usage / validation ──
usage() {
    printf 'Usage: %s <domain> [wordlist]\n' "$(basename -- "$0")" >&2
    printf '  domain   Target domain (e.g. example.com)\n' >&2
    printf '  wordlist Path to DNS wordlist (default: /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt)\n' >&2
    exit 1
}

# ── C5/C6 fix: validate $1 with domain regex before any use ──────────
validate_domain() {
    local dom="${1:-}"
    if [[ -z "$dom" ]]; then
        log_error "Domínio não informado."
        usage
    fi
    # Allow: labels of a-z0-9- (no leading/trailing hyphen), dot-separated, valid TLD
    if [[ ! "$dom" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$ ]]; then
        log_error "Domínio inválido: '$dom'. Apenas caracteres a-z, 0-9, hifens e pontos são permitidos."
        exit 1
    fi
    printf '%s' "$dom"
}

# ── tool dependency check ─────────────────────────────────────────────
require_cmd() {
    local cmd
    for cmd in "$@"; do
        command -v "$cmd" &>/dev/null || {
            log_error "Ferramenta ausente: $cmd — instale e tente novamente."
            exit 1
        }
    done
}

# ──────────────────────────────────────────────────────────────────────
main() {
    require_cmd host

    # Validate and bind domain (C5 fix)
    local DOMAIN
    DOMAIN=$(validate_domain "${1:-}")

    # Wordlist path (default or user-supplied)
    local WORDLIST="${2:-/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt}"

    if [[ ! -f "$WORDLIST" ]]; then
        log_error "Wordlist não encontrada: $WORDLIST"
        exit 1
    fi

    log_info "Iniciando CNAME takeover scan em: $DOMAIN"
    log_info "Wordlist: $WORDLIST"

    local found=0

    # ── C4 fix: while IFS= read -r (não for/cat) + quotes em $palavra ──
    while IFS= read -r palavra; do
        # Skip empty lines and comments
        [[ -z "$palavra" || "$palavra" == \#* ]] && continue

        # A7 fix: typo corrigido — era "alias fot", deve ser "alias for"
        if host -t cname -- "${palavra}.${DOMAIN}" 2>/dev/null | grep --fixed-strings "alias for"; then
            log_warn "Possível takeover encontrado: ${palavra}.${DOMAIN}"
            (( found++ )) || true
        fi
    done < "$WORDLIST"

    if (( found == 0 )); then
        log_info "Nenhum CNAME takeover candidato encontrado."
    else
        log_warn "Total de candidatos encontrados: $found"
    fi
}

main "$@"
