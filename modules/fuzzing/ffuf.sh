#!/usr/bin/env bash
# Module: Directory Fuzzing (bash-pro)
set -Eeuo pipefail
IFS=$'\n\t'
shopt -s inherit_errexit

source core/utils.sh

run_directory_fuzzing() {
    local workdir="$1"
    local temp_dir="$2"
    local wordlist_fuzz="$3"
    local threads="$4"
    local rate="$5"

    [[ -f "$wordlist_fuzz" ]] || { log_warn "Wordlist de fuzzing não encontrada, pulando."; return 0; }

    local total_urls=$(grep -c '.' "$workdir/hosts_vivos.txt" 2>/dev/null || echo 0)
    local current_url=0
    local wl_size=$(grep -c '.' "$wordlist_fuzz" 2>/dev/null || echo 0)

    log_info "Iniciando fuzzing em ${total_urls} host(s) | Wordlist: ${wl_size} entradas"

    while IFS= read -r url; do
        [[ -z "$url" ]] && continue
        (( current_url++ )) || true

        local safe_name=$(printf '%s' "$url" | sed -r 's|^https?://||; s|[/:]|_|g')
        local out_file="$workdir/fuzzing/${safe_name}_ffuf.json"
        local start_ts=$(date +%s)
        local stats_tmp="$temp_dir/ffuf_stats.json"

        draw_header "FUZZING" "Iniciando: $url ($current_url/$total_urls)"
        log_info "[${current_url}/${total_urls}] Iniciando ffuf → $url"

        rm -f "$stats_tmp"
        ffuf \
            -w "$wordlist_fuzz" \
            -u "${url}/FUZZ" \
            -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36" \
            -H "X-Forwarded-For: 127.0.0.1" \
            -c -t "$threads" \
            -rate "$rate" \
            -mc 200,201,204,301,302,403 \
            -mr "admin|dashboard|api|login|config|backup|dev|test|upload" \
            -fr "Not Found|403 Forbidden|Default page|It works!|Coming Soon|Under Construction" \
            -ac \
            -recursion -recursion-depth 2 \
            -maxtime 300 \
            -o "$out_file" \
            -of json \
            -s \
            -stats-file "$stats_tmp" -stats-interval 1 \
            > /dev/null 2>&1 &
        
        spinner "$!" "FUZZING" "$url" "$stats_tmp"
        wait "$!" || true

        local hits=0
        [[ -f "$out_file" ]] && hits=$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(len(d.get('results',[])))" "$out_file" 2>/dev/null || echo 0)

        if (( hits > 0 )); then
            log_info "  └─ ✅ ${hits} caminho(s) encontrado(s) → $out_file"
        else
            log_warn "  └─ ⚠️  Sem resultados para $url"
        fi
    done < "$workdir/hosts_vivos.txt"
}
