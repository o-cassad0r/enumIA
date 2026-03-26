#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
shopt -s inherit_errexit   # Bash 4.4+

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

# log_info: mensagem estruturada com timestamp
log_info()  { printf "${GREEN}[%s][INFO]${NC}  %s\n" "$(date '+%H:%M:%S')" "$*" >&2; }
log_warn()  { printf "${YELLOW}[%s][WARN]${NC}  %s\n" "$(date '+%H:%M:%S')" "$*" >&2; }
log_error() { printf "${RED}[%s][ERROR]${NC} %s\n" "$(date '+%H:%M:%S')" "$*" >&2; }

# --- UI: Dynamic Header (htop style) ---
draw_header() {
    local phase="${1:-STANDBY}"
    local status="${2:-Running tasks...}"
    local current_time=$(date '+%H:%M:%S')
    
    [[ -t 1 ]] || return 0
    
    # Cálculos de métricas em tempo real
    local c_subs=$(grep -c '.' "$TEMP_DIR/subs.txt" 2>/dev/null || echo 0)
    local c_alive=$(grep -c '.' "$WORKDIR/hosts_vivos.txt" 2>/dev/null || echo 0)
    local c_ports=$(grep -c '.' "$WORKDIR/naabu_ports.txt" 2>/dev/null || echo 0)
    local c_vulns=$(grep -c '\[critical\]\|\[high\]' "$WORKDIR/nuclei/vulnerabilidades.txt" 2>/dev/null || echo 0)

    tput sc          # Save cursor
    tput cup 0 0     # Move to line 0, column 0
    
    # Linha 1: Moldura e Alvo
    printf "${CYAN}┌─ RECON-OPS ─ Target: ${DOMAIN:-N/A} ──────────────────────────────────┐${NC}\n"
    tput el
    
    # Linha 2: Status e Fase
    local status_line="│ ⏱️  ${current_time} | 🚀 PHASE: ${phase} | 📡 MODE: ${MODE:-1}"
    local padding_s=$(( 70 - ${#status_line} ))
    printf "${CYAN}%s" "$status_line"
    if (( padding_s > 0 )); then printf "%${padding_s}s" " "; fi
    printf "│${NC}\n"
    tput el

    # Linha 3: Métricas em Tempo Real
    local metrics_line="│ 📊 Found: ${c_subs} subs | ${c_alive} alive | ${c_ports} ports | 🛡️  ${c_vulns} vulns (C/H)"
    local padding_m=$(( 70 - ${#metrics_line} ))
    printf "${CYAN}%s" "$metrics_line"
    if (( padding_m > 0 )); then printf "%${padding_m}s" " "; fi
    printf "│${NC}\n"
    tput el
    
    # Linha 4: Mensagem de Status Inferior
    local msg_line="│ ➔ ${status}"
    local padding_ms=$(( 70 - ${#msg_line} ))
    printf "${CYAN}%s" "$msg_line"
    if (( padding_ms > 0 )); then printf "%${padding_ms}s" " "; fi
    printf "│${NC}\n"
    tput el

    # Linha 5: Moldura Inferior
    printf "${CYAN}└──────────────────────────────────────────────────────────────────────┘${NC}"
    tput el
    
    tput rc          # Restore cursor
}

# spinner: mostra animação e atualiza o header
spinner() {
    local pid="$1"
    local phase="$2"
    local stats_info="${3:-Scanning...}"
    local -a frames=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
    local i=0
    if [[ -t 1 ]]; then
        while kill -0 "$pid" 2>/dev/null; do
            draw_header "$phase" "${frames[i % ${#frames[@]}]} $stats_info"
            (( i++ )) || true
            sleep 0.1
        done
        draw_header "$phase" "✅ Processo concluído."
    else
        wait "$pid" || true
    fi
}


cleanup() { 
    local exit_code=$?
    # Reset terminal scroll region
    [[ -t 1 ]] && tput csr 0 $(tput lines)
    
    echo -e "\n${YELLOW}[*] Limpando temporários...${NC}"
    rm -rf "$TEMP_DIR" 
    exit $exit_code
}
TEMP_DIR=$(mktemp -d)
trap cleanup EXIT ERR SIGINT SIGTERM

check_tools() {
    local tools=(subfinder assetfinder amass dnsx httpx nuclei anew ffuf nmap naabu alterx hakrevdns gowitness whois dig exiftool metabigor subjack gau katana dalfox cloud_enum subjs paramspider tlsx crlfuzz)
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
    cloud_enum -k "$DOMAIN" -l "$WORKDIR/cloud_assets.txt" >/dev/null 2>&1 || true

    # 3. Subdomain Takeover
    echo -e "${YELLOW}[*] Verificando Subdomain Takeover...${NC}"
    [ ! -f "$W_DIR/fingerprints.json" ] && curl -s https://raw.githubusercontent.com/haccer/subjack/master/fingerprints.json -o "$W_DIR/fingerprints.json"
    subjack -w "$WORKDIR/hosts_dns.txt" -c "$W_DIR/fingerprints.json" -t 100 -timeout 30 -o "$WORKDIR/takeover_results.txt" -ssl >/dev/null 2>&1 || true
}

# --- Módulo Deep Intelligence (JS & Params) ---
run_deep_intelligence() {
    print_banner "DEEP INTELLIGENCE (JS SECRETS, CRAWLING & XSS)"

    # 1. JS Secret Finder
    echo -e "${YELLOW}[*] Analisando JavaScript em busca de chaves/secrets...${NC}"
    mkdir -p "$WORKDIR/js_secrets"
    subjs -i "$WORKDIR/hosts_vivos.txt" | head -n 15 | anew "$WORKDIR/js_files.txt" >/dev/null 2>&1 || true
    
    if [ -f "$WORKDIR/js_files.txt" ] && [ -f "$SECRET_FINDER" ]; then
        while IFS= read -r js_url; do
            [[ -z "$js_url" ]] && continue
            local js_name
            js_name=$(basename "$js_url" | cut -d'?' -f1)
            python3 "$SECRET_FINDER" -i "$js_url" -o cli > "$WORKDIR/js_secrets/${js_name}_secrets.txt" 2>/dev/null || true
        done < "$WORKDIR/js_files.txt"
    fi

    # 2. Param-Spider
    echo -e "${YELLOW}[*] Minerando parâmetros para injeção...${NC}"
    paramspider -d "$DOMAIN" --level high --quiet >/dev/null 2>&1 || true
    # Move o resultado para o workdir esperado pelo reporter.py
    [ -f "results/$DOMAIN.txt" ] && mv "results/$DOMAIN.txt" "$WORKDIR/param_discovery.txt" || touch "$WORKDIR/param_discovery.txt"

    # 3. Active Crawling (Katana) e XSS Scanning (Dalfox)
    echo -e "${YELLOW}[*] Crawling ativo com Katana e scanning XSS com Dalfox...${NC}"
    
    if [ "$MODE" == "2" ]; then
        local katana_opts=("-jc" "-hl" "-d" "3" "-em" "woff,css,png,svg,jpg" "-H" "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36" "-H" "X-Forwarded-For: 127.0.0.1" "-c" "5" "-rl" "10")
    else
        local katana_opts=("-jc" "-hl" "-d" "3" "-em" "woff,css,png,svg,jpg" "-H" "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36" "-c" "20")
    fi

    katana -list "$WORKDIR/hosts_vivos.txt" -silent "${katana_opts[@]}" | anew "$WORKDIR/katana_urls.txt" >/dev/null || true

    # Extraindo metadados de documentos a partir do katana (substitui gau)
    echo -e "${YELLOW}[*] Extraindo metadados de documentos públicos...${NC}"
    cat "$WORKDIR/katana_urls.txt" 2>/dev/null | grep -E "\.(pdf|docx|xlsx|txt|zip|bak)$" | head -n 15 | anew "$WORKDIR/interesting_files.txt" >/dev/null 2>&1 || true

    # Dalfox
    draw_header "XSS SCAN" "Launching Dalfox pipe..."
    cat "$WORKDIR/katana_urls.txt" "$WORKDIR/param_discovery.txt" 2>/dev/null | grep "=" | sort -u | dalfox pipe -o "$WORKDIR/dalfox/xss_results.txt" > /dev/null 2>&1 &
    local dalfox_pid=$!
    spinner "$dalfox_pid" "XSS SCAN" "Dalfox processando parâmetros..."
    wait "$dalfox_pid" || true
}

# --- Módulo Edge/TLS Recon (Phase 2.5) ---
run_edge_recon() {
    print_banner "EDGE / TLS RECONNAISSANCE"
    
    mkdir -p "$WORKDIR/edge"
    
    # 1. TLSX: Extração de SANs
    echo -e "${YELLOW}[*] Extraindo Subject Alternative Names (SANs) via TLS...${NC}"
    tlsx -l "$WORKDIR/hosts_vivos.txt" -san -silent | awk '{print $2}' | tr ',' '\n' | sed 's/"//g' | anew "$WORKDIR/edge/tlsx_sans.txt" >/dev/null || true

    # Reverte os SANs encontrados para a pipeline DNS se houver novos
    if [ -s "$WORKDIR/edge/tlsx_sans.txt" ]; then
        echo -e "${YELLOW}[*] Validando novos SANs descobertos...${NC}"
        cat "$WORKDIR/edge/tlsx_sans.txt" | dnsx -silent | anew "$WORKDIR/hosts_dns.txt" >/dev/null
        httpx -l "$WORKDIR/hosts_dns.txt" -silent -o "$WORKDIR/hosts_vivos.txt" >/dev/null || true
    fi

    # 2. CRLFuzz: Teste passivo de injeção CRLF
    draw_header "EDGE RECON" "Checking CRLF Injection..."
    crlfuzz -l "$WORKDIR/hosts_vivos.txt" -s -o "$WORKDIR/edge/crlfuzz_results.txt" > /dev/null 2>&1 &
    local crlfuzz_pid=$!
    spinner "$crlfuzz_pid" "EDGE RECON" "CRLFuzz em execução..."
    wait "$crlfuzz_pid" || true
}

# --- Geração do Dashboard ---
generate_dashboard() {
    print_banner "COMPILING FINAL DASHBOARD"
    
    # DNS Table com Badges
    export DNS_TABLE=$(dig +nocmd "$DOMAIN" any +multiline +noall +answer | head -n 15 | awk '{
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
    whois "$DOMAIN" | grep -E "Registrar:|Creation Date:|Expiry Date:" > "$WORKDIR/whois_raw.txt" || echo "Sem dados WHOIS" > "$WORKDIR/whois_raw.txt"

    # Executa o Reporter Python
    if [ -f "$SCRIPT_DIR/reporter.py" ]; then
        python3 "$SCRIPT_DIR/reporter.py" "$DOMAIN" "$WORKDIR"
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

    # Domain Validation (T1 Hardening)
    if [[ ! "$input_domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$ ]]; then
        log_error "Domínio inválido: '$input_domain'. Use apenas letras, números e hifens."
        exit 1
    fi

    DOMAIN=$(printf '%s' "$input_domain" | tr '[:upper:]' '[:lower:]' | xargs)
    WORKDIR="$WORKDIR_BASE/$DOMAIN"
    mkdir -p "$WORKDIR/fuzzing" "$WORKDIR/nmap" "$WORKDIR/nuclei" "$WORKDIR/vhosts" "$WORKDIR/screenshots" "$WORKDIR/js_secrets" "$WORKDIR/dalfox" "$WORKDIR/edge"

    # Inicializa Terminal UI
    if [[ -t 1 ]]; then
        tput clear
        # Aumentamos o scroll region para acomodar o cabeçalho maior (6 linhas)
        tput csr 6 $(tput lines)
        tput cup 6 0
    fi
    draw_header "INITIALIZING" "Preparando workspace..."

    if [ "$MODE" == "2" ]; then
        local nmap_opts=("-T2" "--delay" "500ms")
        local naabu_opts=("-rate" "50" "-c" "5")
        NUCLEI_RL=10
        FFUF_RATE=5      # Stealth: 5 req/s — evita WAF/IDS
        FFUF_THREADS=10  # Poucos threads para manter perfil baixo
    else
        local nmap_opts=("-T4")
        local naabu_opts=("-rate" "1000" "-c" "50")
        NUCLEI_RL=100
        FFUF_RATE=150    # Normal: throughput padrão
        FFUF_THREADS=50
    fi

    draw_header "RECON" "Discovering subdomains..."
    subfinder -d "$DOMAIN" -silent | anew "$TEMP_DIR/subs.txt" >/dev/null
    assetfinder --subs-only "$DOMAIN" | anew "$TEMP_DIR/subs.txt" >/dev/null

    if [ -f "$WORDLIST_SUB" ]; then
        draw_header "RECON" "Brute-forcing DNS..."
        dnsx -d "$DOMAIN" -w "$WORDLIST_SUB" -silent | anew "$TEMP_DIR/subs.txt" >/dev/null
    fi
    
    draw_header "RECON" "Generating permutations (alterx)..."
    cat "$TEMP_DIR/subs.txt" | alterx -silent | dnsx -silent | anew "$TEMP_DIR/subs.txt" >/dev/null

    dnsx -l "$TEMP_DIR/subs.txt" -silent -a -resp-only | anew "$WORKDIR/ips_unicos.txt" >/dev/null
    dnsx -l "$TEMP_DIR/subs.txt" -silent | anew "$WORKDIR/hosts_dns.txt" >/dev/null
    httpx -l "$WORKDIR/hosts_dns.txt" -silent -o "$WORKDIR/hosts_vivos.txt" >/dev/null

    draw_header "INFRA" "Running OSINT and Deep Intel..."
    cat "$WORKDIR/ips_unicos.txt" | hakrevdns | anew "$WORKDIR/reverse_dns.txt" >/dev/null || true
    run_advanced_intel
    run_deep_intelligence
    
    run_edge_recon

    draw_header "PORT SCAN" "Running Naabu (Fast Ports)..."
    naabu -l "$WORKDIR/hosts_vivos.txt" -p - -silent "${naabu_opts[@]}" -o "$WORKDIR/naabu_ports.txt" >/dev/null || true

    draw_header "VISUAL" "Capturing screenshots (Gowitness)..."
    gowitness scan file -f "$WORKDIR/hosts_vivos.txt" --screenshot-path "$WORKDIR/screenshots" --write-db=false --quiet --threads 5 --screenshot-format png >/dev/null 2>&1 || true

    draw_header "VULN SCAN" "Running Nuclei..."
    nuclei -l "$WORKDIR/hosts_vivos.txt" -silent -rl "$NUCLEI_RL" -severity medium,high,critical -o "$WORKDIR/nuclei/vulnerabilidades.txt" >/dev/null 2>&1 || true

    draw_header "FUZZING" "Launching FFuf on subdomains..."
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
            # Executa ffuf em background para poder usar o spinner
            ffuf \
                -w "$WORDLIST_FUZZ" \
                -u "${url}/FUZZ" \
                -c -t "$FFUF_THREADS" \
                -rate "$FFUF_RATE" \
                -mc 200,201,204,301,302,403 \
                -mr "admin|dashboard|api|login|config|backup|dev|test|upload" \
                -fr "Not Found|403 Forbidden|Default page|It works!|Coming Soon|Under Construction" \
                -ac \
                -recursion -recursion-depth 2 \
                -maxtime 300 \
                -o "$out_file" \
                -of json \
                -s \
                > /dev/null 2>&1 &
            local ffuf_pid=$!
            spinner "$ffuf_pid" "FUZZING" "Host: $url [${current_url}/${total_urls}]"
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
    echo -e "\n${GREEN}=== INVESTIGAÇÃO CONCLUÍDA: $DOMAIN ===${NC}"
}

main "$@"