#!/usr/bin/env bash
# Core Orchestrator (bash-pro)

set -Eeuo pipefail
IFS=$'\n\t'
shopt -s inherit_errexit

# --- Imports ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${SCRIPT_DIR}/core/utils.sh"
source "${SCRIPT_DIR}/modules/subdomain_enum/discover.sh"
source "${SCRIPT_DIR}/modules/infra/intel.sh"
source "${SCRIPT_DIR}/modules/port_scan/scan.sh"
source "${SCRIPT_DIR}/modules/visual/capture.sh"
source "${SCRIPT_DIR}/modules/vulnerability/nuclei.sh"
source "${SCRIPT_DIR}/modules/fuzzing/ffuf.sh"
source "${SCRIPT_DIR}/modules/bypass/waf_guard.sh"

# --- Globals ---
export PATH="$PATH:$HOME/go/bin:$HOME/.local/bin"
CONFIG_DIR="${SCRIPT_DIR}/config"
W_DIR="${CONFIG_DIR}/Wordlists"
WORDLIST_SUB="/usr/share/wordlists/seclists/Discovery/DNS/n0kovo_subdomains.txt"
WORDLIST_FUZZ="/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-big.txt"
WORKDIR_BASE="${SCRIPT_DIR}/data/results"
TEMPLATE_FILE="${SCRIPT_DIR}/templates/template.html"
SECRET_FINDER="$HOME/tools/SecretFinder/SecretFinder.py"

# --- Initialization ---
TEMP_DIR=$(mktemp -d)
trap cleanup EXIT ERR SIGINT SIGTERM

check_dependencies


main() {
    local input_domain="${1:-}"
    [[ -z "$input_domain" ]] && { echo -n "Domínio Alvo: "; read -r input_domain; }
    
    echo -e "\n${BLUE}Escolha o modo de operação:${NC}"
    echo "1) Normal (Rápido/Verboso)"
    echo "2) Stealth (Lento/Furtivo)"
    read -p "Opção [1-2]: " MODE
    export MODE

    local proxy_list="${2:-}"
    export PROXY_LIST="$proxy_list"

    # Domain Validation
    if [[ ! "$input_domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$ ]]; then
        log_error "Domínio inválido: '$input_domain'."
        exit 1
    fi

    DOMAIN=$(printf '%s' "$input_domain" | tr '[:upper:]' '[:lower:]' | xargs)
    export DOMAIN
    WORKDIR="$WORKDIR_BASE/$DOMAIN"
    export WORKDIR
    
    mkdir -p "$WORKDIR"/{fuzzing,nmap,nuclei,vhosts,screenshots,js_secrets,dalfox,edge}

    [[ -t 1 ]] && { tput clear; tput csr 6 $(tput lines); tput cup 6 0; }
    draw_header "INITIALIZING" "Preparando workspace..."

    # Settings adaptat to mode
    if [[ "$MODE" == "2" ]]; then
        nmap_opts=("-T2" "--delay" "500ms")
        naabu_opts=("-rate" "50" "-c" "5")
        NUCLEI_RL=10
        FFUF_RATE=5
        FFUF_THREADS=10
    else
        nmap_opts=("-T4")
        naabu_opts=("-rate" "1000" "-c" "50")
        NUCLEI_RL=100
        FFUF_RATE=150
        FFUF_THREADS=50
    fi

    # --- Execution Pipeline ---
    
    # PHASE 1: RECON
    if [[ ! -s "$WORKDIR/hosts_vivos.txt" ]]; then
        discover_subdomains "$DOMAIN" "$WORKDIR" "$TEMP_DIR" "$WORDLIST_SUB"
    else
        log_info "Hosts vivos detectados de sessão anterior. Pulando DESCOBERTA."
    fi

    if [[ ! -s "$WORKDIR/hosts_vivos.txt" ]]; then

        log_error "Nenhum host vivo encontrado para $DOMAIN. Abortando pipeline."
        exit 1
    fi

    # PHASE 1.5: WAF FINGERPRINTING
    waf_fingerprint "$DOMAIN" "$WORKDIR"

    # PHASE 2: INFRA
    run_advanced_intel "$DOMAIN" "$WORKDIR" "$W_DIR"
    run_deep_intelligence "$DOMAIN" "$WORKDIR" "$SECRET_FINDER" "$MODE"
    run_edge_recon "$WORKDIR"

    # PHASE 3: PORT SCAN
    run_port_scan "$WORKDIR" "${naabu_opts[@]}"

    # PHASE 4: VISUAL
    run_visual_capture "$WORKDIR"

    # PHASE 5: VULN SCAN
    run_vulnerability_scan "$WORKDIR" "$NUCLEI_RL"

    # PHASE 6: FUZZING
    if [[ ! -f "$WORKDIR/fuzzing/results.json" ]]; then
        run_directory_fuzzing "$WORKDIR" "$TEMP_DIR" "$WORDLIST_FUZZ" "$FFUF_THREADS" "$FFUF_RATE"
    else
        log_info "Resultados de fuzzing detectados. Pulando fase."
    fi


    # PHASE 7: REPORT
    generate_dashboard
    
    echo -e "\n${GREEN}=== INVESTIGAÇÃO CONCLUÍDA: $DOMAIN ===${NC}"
}

generate_dashboard() {
    draw_header "REPORT" "Compiling Final Dashboard..."
    
    # DNS Table
    export DNS_TABLE=$(dig +nocmd "$DOMAIN" any +multiline +noall +answer | head -n 15 | awk '{
        type=$4; 
        if(type=="A") color="bg-success";
        else if(type=="MX") color="bg-warning text-dark";
        else if(type=="NS") color="bg-info text-dark";
        else if(type=="TXT") color="bg-primary";
        else if(type=="CNAME") color="bg-secondary";
        else color="bg-dark border border-secondary";
        print "<tr><td><span class=\"badge " color " badge-dns mono\">" type "</span></td><td class=\"mono text-bright\">" $5 "</td></tr>"
    }')

    # Tech Stack
    export TECH_STACK=$(httpx -l "$WORKDIR/hosts_vivos.txt" -silent -td -title 2>/dev/null | grep -oP '\[.*?\]' | sed 's/\[//g; s/\]//g' | grep -ivE "http|https|200|301|302|403|404" | sort -u | awk '{print "<span class=\"tech-badge\">" $0 "</span>"}' || echo "Nenhuma stack detectada")

    # WHOIS
    whois "$DOMAIN" | grep -E "Registrar:|Creation Date:|Expiry Date:" > "$WORKDIR/whois_raw.txt" || echo "Sem dados WHOIS" > "$WORKDIR/whois_raw.txt"

    # Reporter call
    if [[ -f "${SCRIPT_DIR}/engine/reporter.py" ]]; then
        python3 "${SCRIPT_DIR}/engine/reporter.py" "${DOMAIN}" "${WORKDIR}"
    else
        log_error "reporter.py não encontrado em engine/."
    fi
}


main "$@"
