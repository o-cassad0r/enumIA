#!/usr/bin/env bash
# Module: WAF Guard (bash-pro)
set -Eeuo pipefail
IFS=$'\n\t'
shopt -s inherit_errexit

source core/utils.sh

waf_fingerprint() {
    local target="$1"
    local workdir="$2"
    local report_file="$workdir/waf_info.txt"

    log_info "[*] Fingerprinting WAF para: $target"
    
    if ! command -v wafw00f &> /dev/null; then
        log_warn "wafw00f não instalado. Pulando detecção de WAF."
        return 0
    fi

    wafw00f "$target" -o "$report_file" > /dev/null 2>&1 || true

    if [[ -f "$report_file" ]]; then
        local waf_detected=$(grep -oP "(?<=is behind ).*" "$report_file" | head -n 1)
        if [[ -n "$waf_detected" ]]; then
            log_info "  └─ 🛡️ WAF Detectado: $waf_detected"
            # Aqui poderíamos injetar lógica de rate-limit dinâmico no futuro
        else
            log_info "  └─ ✅ Nenhum WAF óbvio detectado."
        fi
    fi
}
