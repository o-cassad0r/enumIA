#!/bin/bash
set -euo pipefail
IFS=$'\n\t'

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}==========================================${NC}"
echo -e "${GREEN}[+] RECON-OPS: SETUP ULTIMATE (FIXED)     ${NC}"
echo -e "${GREEN}==========================================${NC}"

# 1. Dependências de Sistema
sudo apt update -y
sudo apt install -y git curl jq golang-go build-essential python3-pip python3-venv \
    seclists dnsgen whois dnsutils chromium exiftool libpcap-dev

# 2. Configuração de PATH
GO_BIN="$HOME/go/bin"
PY_BIN="$HOME/.local/bin"
mkdir -p "$GO_BIN" "$PY_BIN"

SHELL_CONFIG="$HOME/.bashrc"
[[ -f "$HOME/.zshrc" ]] && SHELL_CONFIG="$HOME/.zshrc"

export PATH="$GO_BIN:$PY_BIN:$PATH"

# 3. Instalação de Ferramentas Go (Sintaxe Corrigida)
echo -e "${YELLOW}[*] Instalando motores Go...${NC}"

# Instalações individuais para maior controle de erro
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/owasp-amass/amass/v4/...@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/lc/subjs@latest
go install github.com/tomnomnom/anew@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/hakluke/hakrevdns@latest
go install github.com/sensepost/gowitness@latest
go install github.com/haccer/subjack@latest
go install github.com/j3ssie/metabigor@latest

# 4. Instalação Python (Bypass de Repositório)
echo -e "${YELLOW}[*] Instalando ferramentas Python via GitHub (Bypass)...${NC}"
pip3 install git+https://github.com/initstring/cloud_enum --break-system-packages
pip3 install git+https://github.com/devanshbatham/paramspider --break-system-packages
pip3 install git-dumper --break-system-packages

# Links Simbólicos (Garante que o fuzzdirectory.sh encontre os comandos)
sudo ln -sf "$PY_BIN/cloud_enum" /usr/local/bin/cloud_enum || true
sudo ln -sf "$PY_BIN/paramspider" /usr/local/bin/paramspider || true

# SecretFinder
mkdir -p "$HOME/tools"
if [ ! -d "$HOME/tools/SecretFinder" ]; then
    git clone https://github.com/m4ll0k/SecretFinder.git "$HOME/tools/SecretFinder"
    pip3 install -r "$HOME/tools/SecretFinder/requirements.txt" --break-system-packages || true
fi

# Nmap NSE Scripts (Vulnerability Mapping)
echo -e "${YELLOW}[*] Instalando scripts NSE (Vulners CVE)...${NC}"
sudo wget -qO /usr/share/nmap/scripts/vulners.nse https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/vulners.nse
sudo nmap --script-updatedb > /dev/null

# 5. Assets e Wordlists
W_DIR="$HOME/tools/enum/Wordlists"
mkdir -p "$W_DIR"
curl -s https://raw.githubusercontent.com/haccer/subjack/master/fingerprints.json -o "$W_DIR/fingerprints.json"
touch "$W_DIR/wordlist_sdm.txt"
touch "$W_DIR/wordlist_final.txt"

# Verificação Final
echo -e "${YELLOW}[*] Validando instalações...${NC}"
if command -v cloud_enum &> /dev/null; then
    echo -e "${GREEN}[V] cloud_enum instalado!${NC}"
else
    echo -e "${RED}[X] Falha no cloud_enum. Tente instalar manualmente via git clone.${NC}"
fi

echo -e "${GREEN}==========================================${NC}"
echo -e "${GREEN}[!] SETUP CONCLUÍDO!                     ${NC}"
echo -e "${YELLOW}[*] Reinicie o terminal ou use: source $SHELL_CONFIG${NC}"
echo -e "${GREEN}==========================================${NC}"
