#!/usr/bin/env bash
# Module: Visual Capture

source core/utils.sh

run_visual_capture() {
    local workdir="$1"

    draw_header "VISUAL" "Capturing screenshots (Gowitness)..."
    gowitness scan file -f "$workdir/hosts_vivos.txt" --screenshot-path "$workdir/screenshots" --write-db=false --quiet --threads 5 --screenshot-format png >/dev/null 2>&1 &
    spinner "$!" "VISUAL" "Gowitness tirando screenshots..."
}
