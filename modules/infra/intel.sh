#!/usr/bin/env bash
# Module: Infrastructure Intelligence (bash-pro)
set -Eeuo pipefail
IFS=$'\n\t'
shopt -s inherit_errexit

source core/utils.sh

run_advanced_intel() {
    local domain="$1"
    local workdir="$2"
    local w_dir="$3"

    draw_header "INFRA" "Starting Advanced Intelligence gathering..."
    local main_ip=$(head -n 1 "$workdir/ips_unicos.txt" 2>/dev/null || echo "")
    
    # 1. ASN & Netblock Mapping
    if [ -n "$main_ip" ]; then
        metabigor find -t "$main_ip" -o "$workdir/asn_info.txt" >/dev/null 2>&1 &
        spinner "$!" "INFRA" "Mapping ASN and Netblocks for ${main_ip}..."
    fi

    # 2. Cloud Hunter (S3, Azure, GCP)
    cloud_enum -k "$domain" -l "$workdir/cloud_assets.txt" >/dev/null 2>&1 &
    spinner "$!" "INFRA" "Cloud Hunting (S3/Azure/GCP)..."

    # 3. Subdomain Takeover
    [ ! -f "$w_dir/fingerprints.json" ] && curl -s https://raw.githubusercontent.com/haccer/subjack/master/fingerprints.json -o "$w_dir/fingerprints.json"
    subjack -w "$workdir/hosts_dns.txt" -c "$w_dir/fingerprints.json" -t 100 -timeout 30 -o "$workdir/takeover_results.txt" -ssl >/dev/null 2>&1 &
    spinner "$!" "INFRA" "Checking Subdomain Takeover..."
}

run_deep_intelligence() {
    local domain="$1"
    local workdir="$2"
    local secret_finder="$3"
    local mode="$4"

    draw_header "INFRA" "Starting Deep Intelligence analysis..."

    # 1. JS Secret Finder
    mkdir -p "$workdir/js_secrets"
    subjs -i "$workdir/hosts_vivos.txt" | head -n 15 | anew "$workdir/js_files.txt" >/dev/null 2>&1 &
    spinner "$!" "INFRA" "Extracting JS files..."
    
    if [ -f "$workdir/js_files.txt" ] && [ -f "$secret_finder" ]; then
        log_info "Hunting secrets in JS files (this may take a while)..."
        while IFS= read -r js_url; do
            [[ -z "$js_url" ]] && continue
            local js_name=$(basename "$js_url" | cut -d'?' -f1)
            # Run in background to avoid blocking the main UI thread if possible, 
            # but here it's serial. Better to log_info.
            python3 "$secret_finder" -i "$js_url" -o cli >> "$workdir/js_secrets/all_js_secrets.txt" 2>/dev/null || true
        done < "$workdir/js_files.txt"
        log_info "JS Secret search complete."
    fi


    # 2. Param-Spider
    paramspider -d "$domain" --level high --quiet -o "$workdir/param_discovery_raw.txt" >/dev/null 2>&1 &
    spinner "$!" "INFRA" "Mining injection parameters..."
    # Ensure file exists even if tool fails
    [ ! -f "$workdir/param_discovery_raw.txt" ] && touch "$workdir/param_discovery_raw.txt"
    cat "$workdir/param_discovery_raw.txt" | anew "$workdir/param_discovery.txt" >/dev/null


    # 3. Active Crawling (Katana) e XSS Scanning (Dalfox)
    local katana_opts=("-jc" "-hl" "-d" "3" "-em" "woff,css,png,svg,jpg" "-H" "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
    if [ "$mode" == "2" ]; then
        katana_opts+=("-H" "X-Forwarded-For: 127.0.0.1" "-c" "5" "-rl" "10")
    else
        katana_opts+=("-c" "20")
    fi

    katana -list "$workdir/hosts_vivos.txt" -silent "${katana_opts[@]}" | anew "$workdir/katana_urls.txt" >/dev/null 2>&1 &
    spinner "$!" "INFRA" "Active Crawling with Katana..."

    cat "$workdir/katana_urls.txt" 2>/dev/null | grep -E "\.(pdf|docx|xlsx|txt|zip|bak)$" | head -n 15 | anew "$workdir/interesting_files.txt" >/dev/null 2>&1 || true

    # Dalfox
    draw_header "XSS SCAN" "Launching Dalfox pipe..."
    cat "$workdir/katana_urls.txt" "$workdir/param_discovery.txt" 2>/dev/null | grep "=" | sort -u | dalfox pipe -o "$workdir/dalfox/xss_results.txt" > /dev/null 2>&1 &
    spinner "$!" "XSS SCAN" "Dalfox processando parâmetros..."
}

run_edge_recon() {
    local workdir="$1"

    draw_header "EDGE RECON" "Initializing Edge/TLS reconnaissance..."
    mkdir -p "$workdir/edge"
    
    tlsx -l "$workdir/hosts_vivos.txt" -san -silent | awk '{print $2}' | tr ',' '\n' | sed 's/"//g' | anew "$workdir/edge/tlsx_sans.txt" >/dev/null 2>&1 &
    spinner "$!" "EDGE RECON" "Extracting SANs from TLS certificates..."

    if [ -s "$workdir/edge/tlsx_sans.txt" ]; then
        draw_header "EDGE RECON" "Validating newly discovered SANs..."
        cat "$workdir/edge/tlsx_sans.txt" | dnsx -silent | anew "$workdir/hosts_dns.txt" >/dev/null 2>&1 &
        spinner "$!" "EDGE RECON" "DNS resolving SANs..."
        
        httpx -l "$workdir/hosts_dns.txt" -silent -o "$workdir/hosts_vivos.txt" >/dev/null 2>&1 &
        spinner "$!" "EDGE RECON" "Verifying HTTP on new SANs..."
    fi

    draw_header "EDGE RECON" "Checking CRLF Injection..."
    crlfuzz -l "$workdir/hosts_vivos.txt" -s -o "$workdir/edge/crlfuzz_results.txt" > /dev/null 2>&1 &
    spinner "$!" "EDGE RECON" "CRLFuzz em execução..."
}
