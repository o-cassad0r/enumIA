#!/usr/bin/env bash
# RECON-OPS: SETUP ULTIMATE (bash-pro)
set -Eeuo pipefail
IFS=$'\n\t'
shopt -s inherit_errexit

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/core/utils.sh"


log_info "=========================================="
log_info "[+] enumIA: SETUP ULTIMATE (bash-pro) "
log_info "=========================================="

# 1. Dependências de Sistema
sudo apt update -y
sudo apt install -y git curl jq golang-go build-essential python3-pip python3-venv \
    seclists dnsgen whois dnsutils chromium exiftool libpcap-dev ncurses-bin wafw00f

# 1.5. Infraestrutura de IA (Ollama)
log_info "[*] Verificando motor de IA Local (Ollama)..."
if ! command -v ollama &> /dev/null; then
    log_warn "[!] Ollama não detectado. Iniciando instalação..."
    curl -fsSL https://ollama.com/install.sh | sh
else
    log_info "[V] Ollama já está instalado."
fi

# Baixa o modelo padrão caso não exista
log_info "[*] Garantindo modelo estratégico (llama3:8b)..."
ollama pull llama3:8b || log_warn "[!] Não foi possível baixar o modelo agora. Certifique-se de baixar manualmente depois: ollama pull llama3:8b"


# 2. Configuração de PATH
GO_BIN="$HOME/go/bin"
PY_BIN="$HOME/.local/bin"
mkdir -p "$GO_BIN" "$PY_BIN"

SHELL_CONFIG="$HOME/.bashrc"
[[ -f "$HOME/.zshrc" ]] && SHELL_CONFIG="$HOME/.zshrc"

export PATH="$GO_BIN:$PY_BIN:$PATH"

# 3. Instalação de Ferramentas Go (Otimizada e Verbosa)
log_info "[*] Validando ambiente Go..."
go version || { log_error "Go não encontrado ou mal instalado."; exit 1; }

log_info "[*] Instalando motores Go (isso pode levar alguns minutos, aguarde)..."
# Usamos -v para visibilidade e evitamos recompilação desnecessária
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/ffuf/ffuf/v2@latest
# Amass v4 é muito pesado para compilar tudo (...), instalando apenas o binário principal
go install -v github.com/owasp-amass/amass/v4/cmd/amass@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/lc/subjs@latest
go install -v github.com/tomnomnom/anew@latest
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/hakluke/hakrevdns@latest
go install -v github.com/sensepost/gowitness@latest
go install -v github.com/haccer/subjack@latest
go install -v github.com/j3ssie/metabigor@latest

# Novas ferramentas da Proposta de Modernização
echo -e "${YELLOW}[*] Instalando novas ferramentas de Red Team...${NC}"
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/alterx/cmd/alterx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest
go install -v github.com/hahwul/dalfox/v2@latest
go install -v github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest

# 4. Instalação Python (Bypass de Repositório)
echo -e "${YELLOW}[*] Instalando ferramentas Python via GitHub (Bypass)...${NC}"
pip3 install git+https://github.com/initstring/cloud_enum --break-system-packages
pip3 install git+https://github.com/devanshbatham/paramspider --break-system-packages
pip3 install git-dumper --break-system-packages
pip3 install aiofiles --break-system-packages

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


# Verificação Final
echo -e "${YELLOW}[*] Validando instalações...${NC}"
if command -v cloud_enum &> /dev/null; then
    echo -e "${GREEN}[V] cloud_enum instalado!${NC}"
else
    echo -e "${RED}[X] Falha no cloud_enum. Tente instalar manualmente via git clone.${NC}"
fi

log_info "=========================================="
log_info "[!] SETUP CONCLUÍDO!                     "
log_info "[*] Reinicie o terminal ou use: source ${SHELL_CONFIG}"
log_info "=========================================="
