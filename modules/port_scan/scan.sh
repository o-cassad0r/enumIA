#!/usr/bin/env bash
# Module: Port Scanning (bash-pro)
set -Eeuo pipefail
IFS=$'\n\t'
shopt -s inherit_errexit

source core/utils.sh

run_port_scan() {
    local workdir="$1"
    local naabu_opts=("${@:2}")

    draw_header "PORT SCAN" "Running Naabu (Fast Ports)..."
    naabu -l "$workdir/hosts_vivos.txt" -p - -silent "${naabu_opts[@]}" -o "$workdir/naabu_ports.txt" >/dev/null 2>&1 &
    spinner "$!" "PORT SCAN" "Naabu escaneando portas web..."
}
