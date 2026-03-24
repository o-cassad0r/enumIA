#!/bin/bash
set -Eeuo pipefail
IFS=$'\n\t'

# --- Cores ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# --- Caminhos ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PATH="$PATH:$HOME/go/bin:$HOME/.local/bin"

W_DIR="$HOME/tools/enum/Wordlists"
WORDLIST_SUB="$W_DIR/wordlist_sdm.txt"
WORDLIST_FUZZ="$W_DIR/wordlist_final.txt"
WORKDIR_BASE="$SCRIPT_DIR/recon_results"
TEMPLATE_FILE="$SCRIPT_DIR/template.html"
# Caminho do SecretFinder (Ajuste se necessário)
SECRET_FINDER="$HOME/tools/SecretFinder/SecretFinder.py"

# --- Funções Auxiliares ---
print_banner() {
    echo -e "\n${CYAN}################################################################"
    echo -e "  [>] PROCESSO: $1"
    echo -e "################################################################${NC}"
}

# log_info: mensagem estruturada com timestamp
log_info()  { printf "${GREEN}[%s][INFO]${NC}  %s\n" "$(date '+%H:%M:%S')" "$*" >&2; }
log_warn()  { printf "${YELLOW}[%s][WARN]${NC}  %s\n" "$(date '+%H:%M:%S')" "$*" >&2; }
log_error() { printf "${RED}[%s][ERROR]${NC} %s\n" "$(date '+%H:%M:%S')" "$*" >&2; }

# spinner: mostra animação enquanto PID roda em background
# Uso: spinner $! "Mensagem"
spinner() {
    local pid="$1"
    local msg="${2:-Aguardando...}"
    local -a frames=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
    local i=0
    # Só mostra spinner se stdout for um terminal
    if [[ -t 1 ]]; then
        while kill -0 "$pid" 2>/dev/null; do
            printf "\r${CYAN}%s${NC} %s " "${frames[i % ${#frames[@]}]}" "$msg"
            (( i++ )) || true
            sleep 0.1
        done
        printf "\r%-80s\r" " "   # Limpa a linha do spinner
    else
        wait "$pid" || true
    fi
}

# progress_bar: exibe barra de progresso no terminal
# Uso: progress_bar ATUAL TOTAL "Label"
progress_bar() {
    local current="$1" total="$2" label="${3:-}"
    [[ -t 1 ]] || return 0       # Só exibe em terminal interativo
    (( total == 0 )) && return 0
    local pct=$(( current * 100 / total ))
    local filled=$(( pct / 5 ))  # Barra de 20 blocos
    local bar=""
    local i
    for (( i=0; i<filled; i++ ));   do bar+="█"; done
    for (( i=filled; i<20; i++ )); do bar+="░"; done
    printf "\r${CYAN}[%s]${NC} %3d%% (%d/%d) %s" "$bar" "$pct" "$current" "$total" "$label"
}

cleanup() { 
    echo -e "\n${YELLOW}[*] Limpando temporários...${NC}"
    rm -rf "$TEMP_DIR" 
}
TEMP_DIR=$(mktemp -d)
trap cleanup EXIT ERR SIGINT SIGTERM

check_tools() {
    local tools=(subfinder assetfinder amass dnsx httpx nuclei anew ffuf nmap hakrevdns gowitness whois dig exiftool metabigor subjack gau cloud_enum subjs paramspider)
    for tool in "${tools[@]}"; do
        command -v "$tool" >/dev/null 2>&1 || { echo -e "${RED}[!] Erro: Instale $tool${NC}"; exit 1; }
    done
}

# --- Módulo OSINT & Cloud Hunter ---
run_advanced_intel() {
    print_banner "ADVANCED OSINT & CLOUD HUNTING"
    
    local main_ip=$(head -n 1 "$WORKDIR/ips_unicos.txt" 2>/dev/null || echo "")
    
    # 1. ASN & Netblock Mapping
    if [ -n "$main_ip" ]; then
        echo -e "${YELLOW}[*] Identificando ASN para $main_ip...${NC}"
        metabigor find -t "$main_ip" -o "$WORKDIR/asn_info.txt" >/dev/null 2>&1 || true
    fi

    # 2. Cloud Hunter (S3, Azure, GCP)
    echo -e "${YELLOW}[*] Buscando Buckets expostos (cloud_enum)...${NC}"
    cloud_enum -k "$DOM" -l "$WORKDIR/cloud_assets.txt" >/dev/null 2>&1 || true

    # 3. Subdomain Takeover
    echo -e "${YELLOW}[*] Verificando Subdomain Takeover...${NC}"
    [ ! -f "$W_DIR/fingerprints.json" ] && curl -s https://raw.githubusercontent.com/haccer/subjack/master/fingerprints.json -o "$W_DIR/fingerprints.json"
    subjack -w "$WORKDIR/hosts_dns.txt" -c "$W_DIR/fingerprints.json" -t 100 -timeout 30 -o "$WORKDIR/takeover_results.txt" -ssl >/dev/null 2>&1 || true
}

# --- Módulo Deep Intelligence (JS & Params) ---
run_deep_intelligence() {
    print_banner "DEEP INTELLIGENCE (JS SECRETS & PARAMS)"

    # 1. JS Secret Finder
    echo -e "${YELLOW}[*] Analisando JavaScript em busca de chaves/secrets...${NC}"
    mkdir -p "$WORKDIR/js_secrets"
    subjs -i "$WORKDIR/hosts_vivos.txt" | head -n 15 | anew "$WORKDIR/js_files.txt" >/dev/null 2>&1 || true
    
    if [ -f "$WORKDIR/js_files.txt" ] && [ -f "$SECRET_FINDER" ]; then
        while read -r js_url; do
            local js_name=$(basename "$js_url" | cut -d'?' -f1)
            python3 "$SECRET_FINDER" -i "$js_url" -o cli > "$WORKDIR/js_secrets/${js_name}_secrets.txt" 2>/dev/null || true
        done < "$WORKDIR/js_files.txt"
    fi

    # 2. Param-Spider
    echo -e "${YELLOW}[*] Minerando parâmetros para injeção...${NC}"
    paramspider -d "$DOM" --level high --quiet >/dev/null 2>&1 || true
    # Move o resultado para o workdir esperado pelo reporter.py
    [ -f "results/$DOM.txt" ] && mv "results/$DOM.txt" "$WORKDIR/param_discovery.txt" || touch "$WORKDIR/param_discovery.txt"

    # 3. Metadados de Documentos
    echo -e "${YELLOW}[*] Extraindo metadados de documentos públicos...${NC}"
    cat "$WORKDIR/hosts_dns.txt" | gau 2>/dev/null | grep -E "\.(pdf|docx|xlsx|txt|zip|bak)$" | head -n 15 | anew "$WORKDIR/interesting_files.txt" >/dev/null 2>&1 || true
}

# --- Geração do Dashboard ---
generate_dashboard() {
    print_banner "COMPILING FINAL DASHBOARD"
    
    # DNS Table com Badges
    export DNS_TABLE=$(dig +nocmd "$DOM" any +multiline +noall +answer | head -n 15 | awk '{
        type=$4; 
        if(type=="A") color="bg-success";
        else if(type=="MX") color="bg-warning text-dark";
        else if(type=="NS") color="bg-info text-dark";
        else if(type=="TXT") color="bg-primary";
        else if(type=="CNAME") color="bg-secondary";
        else color="bg-dark border border-secondary";
        print "<tr><td style=\"width: 100px;\"><span class=\"badge " color " badge-dns mono\">" type "</span></td><td class=\"mono text-bright\">" $5 "</td></tr>"
    }')

    # Tech Stack Dinâmica
    export TECH_STACK=$(httpx -l "$WORKDIR/hosts_vivos.txt" -silent -td -title 2>/dev/null | \
        grep -oP '\[.*?\]' | sed 's/\[//g; s/\]//g' | \
        grep -ivE "http|https|200|301|302|403|404" | sort -u | \
        awk '{print "<span class=\"tech-badge\"><i class=\"bi bi-cpu\"></i> " $0 "</span>"}' || echo "Nenhuma stack detectada")

    # Galeria de Screenshots
    export SCREENSHOT_GALLERY=""
    if [ -d "$WORKDIR/screenshots" ]; then
        for img in "$WORKDIR/screenshots"/*.png; do
            [ -e "$img" ] || continue
            local img_name=$(basename "$img")
            SCREENSHOT_GALLERY+="<div class='col-md-6 col-lg-4 mb-3'><div class='f-card p-2'><small class='mono d-block text-truncate text-muted'>$img_name</small><img src='./screenshots/$img_name' class='screenshot-img mt-2'></div></div>"
        done
    fi

    # Prepara o WHOIS bruto
    whois "$DOM" | grep -E "Registrar:|Creation Date:|Expiry Date:" > "$WORKDIR/whois_raw.txt" || echo "Sem dados WHOIS" > "$WORKDIR/whois_raw.txt"

    # Executa o Reporter Python
    if [ -f "$SCRIPT_DIR/reporter.py" ]; then
        python3 "$SCRIPT_DIR/reporter.py" "$DOM" "$WORKDIR"
    else
        echo -e "${RED}[!] Erro: reporter.py não encontrado na raiz do projeto.${NC}"
    fi
}

main() {
    check_tools
    sudo -v

    local input_domain="${1:-}"
    [ -z "$input_domain" ] && { echo -n "Domínio Alvo: "; read -r input_domain; }
    
    echo -e "\n${BLUE}Escolha o modo de operação:${NC}"
    echo "1) Normal (Rápido/Verboso)"
    echo "2) Stealth (Lento/Furtivo)"
    read -p "Opção [1-2]: " MODE

    DOM=$(echo "$input_domain" | tr '[:upper:]' '[:lower:]' | xargs)
    WORKDIR="$WORKDIR_BASE/$DOM"
    mkdir -p "$WORKDIR/fuzzing" "$WORKDIR/nmap" "$WORKDIR/nuclei" "$WORKDIR/vhosts" "$WORKDIR/screenshots" "$WORKDIR/js_secrets"

    if [ "$MODE" == "2" ]; then
        NMAP_FLAGS="-T2 --delay 500ms"
        NUCLEI_RL=10
        FFUF_RATE=5      # Stealth: 5 req/s — evita WAF/IDS
        FFUF_THREADS=10  # Poucos threads para manter perfil baixo
    else
        NMAP_FLAGS="-T4"
        NUCLEI_RL=100
        FFUF_RATE=150    # Normal: throughput padrão
        FFUF_THREADS=50
    fi

    print_banner "PHASE 1: RECONNAISSANCE"
    subfinder -d "$DOM" -silent | anew "$TEMP_DIR/subs.txt" >/dev/null
    assetfinder --subs-only "$DOM" | anew "$TEMP_DIR/subs.txt" >/dev/null

    if [ -f "$WORDLIST_SUB" ]; then
        echo -e "${YELLOW}[*] Executando Brute-Force de Subdomínios (Mostrando novos resultados ao vivo)...${NC}"
        dnsx -d "$DOM" -w "$WORDLIST_SUB" | anew "$TEMP_DIR/subs.txt"
    else
        echo -e "${YELLOW}[!] Wordlist de subdomínios não encontrada, pulando brute-force ativo.${NC}"
    fi
    dnsx -l "$TEMP_DIR/subs.txt" -silent -a -resp-only | anew "$WORKDIR/ips_unicos.txt" >/dev/null
    dnsx -l "$TEMP_DIR/subs.txt" -silent | anew "$WORKDIR/hosts_dns.txt" >/dev/null
    httpx -l "$WORKDIR/hosts_dns.txt" -silent -o "$WORKDIR/hosts_vivos.txt"

    print_banner "PHASE 2: INFRASTRUCTURE & OSINT"
    cat "$WORKDIR/ips_unicos.txt" | hakrevdns | anew "$WORKDIR/reverse_dns.txt" >/dev/null || true
    run_advanced_intel
    run_deep_intelligence

    print_banner "PHASE 3: PORT SCANNING (NMAP)"
    while read -r ip; do
        echo -e "${YELLOW}[*] Iniciando Nmap no IP: ${ip} ... (Pode demorar uns minutos)${NC}"
        sudo nmap -sS -sC -sV --version-intensity 5 --script banner,vulners -Pn --open $NMAP_FLAGS "$ip" -oN "$WORKDIR/nmap/scan_$ip.txt" >/dev/null 2>&1 || true
    done < "$WORKDIR/ips_unicos.txt"

    print_banner "PHASE 4: VISUAL EVIDENCE (GOWITNESS)"
    gowitness scan file -f "$WORKDIR/hosts_vivos.txt" --screenshot-path "$WORKDIR/screenshots" --write-db=false --quiet --threads 5 --screenshot-format png || true

    print_banner "PHASE 5: VULNERABILITY SCAN (NUCLEI)"
    nuclei -l "$WORKDIR/hosts_vivos.txt" -silent -rl "$NUCLEI_RL" -severity medium,high,critical -o "$WORKDIR/nuclei/vulnerabilidades.txt" || true

    print_banner "PHASE 6: DIRECTORY FUZZING (FFUF)"
    if [ -f "$WORDLIST_FUZZ" ]; then
        # Contagem total de URLs para a barra de progresso
        local total_urls
        total_urls=$(grep -c '.' "$WORKDIR/hosts_vivos.txt" 2>/dev/null || echo 0)
        local current_url=0
        local wl_size
        wl_size=$(grep -c '.' "$WORDLIST_FUZZ" 2>/dev/null || echo 0)

        log_info "Iniciando fuzzing em ${total_urls} host(s) | Wordlist: ${wl_size} entradas"

        while IFS= read -r url; do
            [ -z "$url" ] && continue
            (( current_url++ )) || true

            local safe_name
            safe_name=$(printf '%s' "$url" | sed -r 's|^https?://||; s|[/:]|_|g')
            local out_file="$WORKDIR/fuzzing/${safe_name}_ffuf.json"
            local start_ts
            start_ts=$(date +%s)

            # Progresso antes de iniciar cada host
            progress_bar "$current_url" "$total_urls" "Fuzzing: $url"
            printf "\n"    # Quebra de linha após barra
            log_info "[${current_url}/${total_urls}] Iniciando ffuf → $url"

            # Executa ffuf em background para poder usar o spinner
            # -rate        : req/s adaptat ao modo (Stealth=5 / Normal=150)
            # -mr          : matcher regex — retém respostas com conteúdo relevante
            # -fr          : filtro regex  — descarta false positives de páginas default
            ffuf \
                -w "$WORDLIST_FUZZ" \
                -u "${url}/FUZZ" \
                -c -t "$FFUF_THREADS" \
                -rate "$FFUF_RATE" \
                -mc 200,201,204,301,302,403 \
                -mr "admin|dashboard|api|login|config|backup|dev|test|upload" \
                -fr "Not Found|403 Forbidden|Default page|It works!|Coming Soon|Under Construction" \
                -ac \
                -o "$out_file" \
                -of json \
                -s \
                > /dev/null 2>&1 &
            local ffuf_pid=$!
            spinner "$ffuf_pid" "Fuzzing ${url} ..."
            wait "$ffuf_pid" || true

            local elapsed=$(( $(date +%s) - start_ts ))

            # Conta resultados encontrados no JSON de saída
            local hits=0
            if [[ -f "$out_file" ]]; then
                hits=$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(len(d.get('results',[])))" "$out_file" 2>/dev/null || echo 0)
            fi

            if (( hits > 0 )); then
                log_info "  └─ ✅ ${hits} caminho(s) encontrado(s) em ${elapsed}s → $out_file"
            else
                log_warn "  └─ ⚠️  Sem resultados em ${elapsed}s para $url"
            fi
        done < "$WORKDIR/hosts_vivos.txt"

        # Linha final após a barra de progresso
        [[ -t 1 ]] && printf "\n"
        log_info "✔ Fuzzing concluído: ${current_url}/${total_urls} host(s) processado(s)."
    else
        log_warn "Wordlist de fuzzing não encontrada em $WORDLIST_FUZZ, pulando ffuf."
    fi

    generate_dashboard
    echo -e "\n${GREEN}=== INVESTIGAÇÃO CONCLUÍDA: $DOM ===${NC}"
}

main "$@"