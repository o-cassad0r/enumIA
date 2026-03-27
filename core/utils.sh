#!/usr/bin/env bash
# Module: Shared Utilities (bash-pro)

set -Eeuo pipefail
IFS=$'\n\t'
shopt -s inherit_errexit

# --- UI Colors ---
NC='\033[0m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'

# --- Logging ---
log_info()  { printf "${GREEN}[%s][INFO]${NC}  %s\n" "$(date '+%H:%M:%S')" "$*" >&2; }
log_warn()  { printf "${YELLOW}[%s][WARN]${NC}  %s\n" "$(date '+%H:%M:%S')" "$*" >&2; }
log_error() { printf "${RED}[%s][ERROR]${NC} %s\n" "$(date '+%H:%M:%S')" "$*" >&2; }

# --- System Checks ---
check_dependencies() {
    local deps=("jq" "dig" "nmap" "naabu" "httpx" "subfinder" "nuclei" "ffuf" "python3")
    local missing=()
    
    for tool in "${deps[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing+=("$tool")
        fi
    done
    
    if (( ${#missing[@]} > 0 )); then
        log_error "Ferramentas faltando: ${missing[*]}"
        log_info "Por favor, instale-as antes de continuar."
        exit 1
    fi
}


# --- UI: Dynamic Header ---
draw_header() {
    local phase="$1"
    local status="${2:-Iniciando...}"
    local live_stats="${3:-}"
    
    [[ -t 1 ]] || return 0
    local current_time=$(date +%T)
    local c_subs=$(grep -c '^' "$TEMP_DIR/subs.txt" 2>/dev/null || echo 0)
    local c_alive=$(grep -c '^' "$WORKDIR/hosts_vivos.txt" 2>/dev/null || echo 0)
    local c_ports=$(grep -c ":" "$WORKDIR/naabu_ports.txt" 2>/dev/null || echo 0)
    local c_vulns=$(grep -Eci "medium|high|critical" "$WORKDIR/nuclei/vulnerabilidades.txt" 2>/dev/null || echo 0)

    tput sc
    tput cup 0 0
    
    printf "${CYAN}┌─ RECON-OPS ─ Target: ${DOMAIN:-N/A} ──────────────────────────────────┐${NC}\n"
    tput el
    
    local status_line="│ ⏱️  ${current_time} | 🚀 PHASE: ${phase} | 📡 MODE: ${MODE:-1}"
    local padding_s=$(( 70 - ${#status_line} ))
    printf "${CYAN}%s" "$status_line"
    if (( padding_s > 0 )); then printf "%${padding_s}s" " "; fi
    printf "│${NC}\n"
    tput el

    local metrics_line="│ 📊 Found: ${c_subs} subs | ${c_alive} alive | ${c_ports} ports | 🛡️  ${c_vulns} vulns"
    local padding_m=$(( 70 - ${#metrics_line} ))
    printf "${CYAN}%s" "$metrics_line"
    if (( padding_m > 0 )); then printf "%${padding_m}s" " "; fi
    printf "│${NC}\n"
    tput el
    
    if [[ -n "$live_stats" ]]; then
        local padding_l=$(( 70 - ${#live_stats} - 2 ))
        printf "${CYAN}│ %s" "$live_stats"
        if (( padding_l > 0 )); then printf "%${padding_l}s" " "; fi
        printf "│${NC}\n"
    else
        printf "${CYAN}│ ➔ %-68s │${NC}\n" "$status"
    fi
    tput el

    printf "${CYAN}└──────────────────────────────────────────────────────────────────────┘${NC}"
    tput el
    
    tput rc
}

# --- Spinner ---
spinner() {
    local pid="$1"
    local phase="$2"
    local label="${3:-Scanning...}"
    local stats_file="${4:-}"
    local -a frames=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
    local i=0
    local start_time=$SECONDS
    
    if [[ -t 1 ]]; then
        while kill -0 "$pid" 2>/dev/null; do
            local current_stats=""
            local elapsed=$(( SECONDS - start_time ))
            local duration_fmt=$(printf "%d:%02d:%02d" $((elapsed/3600)) $(( (elapsed%3600)/60 )) $((elapsed%60)))
            
            if [[ -n "$stats_file" && -f "$stats_file" ]]; then
                local last_json=$(tail -n 1 "$stats_file" 2>/dev/null || echo "{}")
                if [[ "$last_json" == \{* ]]; then
                    local prog=$(echo "$last_json" | jq -r '.progress // 0' 2>/dev/null || echo 0)
                    local total=$(echo "$last_json" | jq -r '.total // 0' 2>/dev/null || echo 0)
                    local rps=$(echo "$last_json" | jq -r '.req_per_sec // 0' 2>/dev/null || echo 0)
                    local errs=$(echo "$last_json" | jq -r '.error_count // 0' 2>/dev/null || echo 0)
                    current_stats=":: Progress: [${prog}/${total}] :: ${rps} req/sec :: Duration: [${duration_fmt}] :: Errors: ${errs} ::"
                fi
            fi

            draw_header "${phase}" "${frames[i % ${#frames[@]}]} ${label}" "${current_stats}"
            (( i++ )) || true
            sleep 0.2
        done
        draw_header "${phase}" "✅ ${label} concluído."
    else
        wait "${pid}" || true
    fi
}


# --- Cleanup ---
cleanup() { 
    local exit_code=$?
    
    reset_terminal
    
    echo -e "\n${YELLOW}[*] Limpando temporários...${NC}"
    rm -rf "$TEMP_DIR" 2>/dev/null || true
    exit $exit_code
}

reset_terminal() {
    [[ -t 1 ]] && {
        tput csr 0 $(tput lines 2>/dev/null || echo 24) 2>/dev/null
        tput clear
        tput cup 0 0
    } || true
}

