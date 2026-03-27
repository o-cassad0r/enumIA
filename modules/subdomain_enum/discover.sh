#!/usr/bin/env bash
# Module: Subdomain Discovery (bash-pro)

set -Eeuo pipefail
IFS=$'\n\t'
shopt -s inherit_errexit

source core/utils.sh

discover_subdomains() {
    local domain="$1"
    local workdir="$2"
    local temp_dir="$3"
    local wordlist_sub="$4"

    draw_header "RECON" "Discovering subdomains..."
    
    echo "${domain}" > "${temp_dir}/subs.txt"
    
    subfinder -d "$domain" -silent | anew "$temp_dir/subs.txt" >/dev/null 2>&1 &
    spinner "$!" "RECON" "Subfinder em execução..."
    
    assetfinder --subs-only "$domain" | anew "$temp_dir/subs.txt" >/dev/null 2>&1 &
    spinner "$!" "RECON" "Assetfinder em execução..."

    if [ -f "$wordlist_sub" ]; then
        dnsx -d "$domain" -w "$wordlist_sub" -silent | anew "$temp_dir/subs.txt" >/dev/null 2>&1 &
        spinner "$!" "RECON" "Brute-forcing DNS (dnsx)..."
    fi
    
    draw_header "RECON" "Generating permutations (alterx)..."
    cat "$temp_dir/subs.txt" | alterx -silent | dnsx -silent -rl 500 | anew "$temp_dir/subs.txt" >/dev/null 2>&1 &
    spinner "$!" "RECON" "Alterx processando permutações..."

    dnsx -l "$temp_dir/subs.txt" -silent -a -resp-only -rl 500 | anew "$workdir/ips_unicos.txt" >/dev/null 2>&1 &
    spinner "$!" "RECON" "Resolvendo IPs únicos..."
    
    dnsx -l "$temp_dir/subs.txt" -silent -rl 500 | anew "$workdir/hosts_dns.txt" >/dev/null 2>&1 &

    spinner "$!" "RECON" "Validando registros DNS..."
    
    httpx -l "$workdir/hosts_dns.txt" -silent -o "$workdir/hosts_vivos.txt" >/dev/null 2>&1 &
    spinner "$!" "RECON" "Validando hosts vivos (HTTP)..."
}

# Solo execution support
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    discover_subdomains "$@"
fi
