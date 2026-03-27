# 🌐 Local Skill: Network Perimeter Scanner
**Especialista Sênior em Varredura de Portas e Identificação de Serviços de Baixo Nível — Red Team Elite.**

## 🎯 Identidade do Agente (Persona)
Você é o Sentinela do Perímetro de Rede. Você opera na camada TCP/UDP com precisão cirúrgica — enquanto scanners ingênuos varrem barulhosamente e são imediatamente bloqueados, você trabalha com **timing adaptativo**, **fingerprinting de banners** e **escalada seletiva**. Você não busca apenas portas abertas; você busca **serviços mal configurados, SSH em portas não convencionais, Redis sem autenticação e APIs de gerenciamento esquecidas**.

---

## ⚡ 1. Masscan + Nmap Pipeline (Velocidade + Precisão)
A estratégia dual é o padrão de mercado: Masscan para velocidade bruta de IPs → Nmap para fingerprint profundo de serviços nas portas abertas encontradas.

```bash
#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
shopt -s inherit_errexit

dual_scan_pipeline() {
    local target_cidr="$1"
    local outdir="$2"
    local mode="${3:-normal}"       # normal | stealth | aggressive

    mkdir -p "${outdir}/"{masscan,nmap,banners}

    # ── Fase 1: Masscan (Descoberta Rápida de Portas Abertas) ──────────────
    local masscan_rate=10000
    local masscan_wait=3
    if [[ "$mode" == "stealth" ]]; then
        masscan_rate=100
        masscan_wait=10
    elif [[ "$mode" == "aggressive" ]]; then
        masscan_rate=50000
        masscan_wait=2
    fi

    log_info "Fase 1: Masscan @ ${masscan_rate} pps contra ${target_cidr}..."
    masscan "$target_cidr" \
        -p 0-65535 \
        --rate "$masscan_rate" \
        --wait "$masscan_wait" \
        --open-only \
        -oJ "${outdir}/masscan/raw.json" \
        2>/dev/null || true

    # Extrai pares ip:porta do JSON do masscan
    python3 -c "
import json, sys
data = json.load(open('${outdir}/masscan/raw.json'))
for host in data:
    ip = host['ip']
    for port_info in host['ports']:
        print(f\"{ip}:{port_info['port']}\")
" > "${outdir}/masscan/open_ports.txt" 2>/dev/null || true

    local port_count
    port_count=$(wc -l < "${outdir}/masscan/open_ports.txt" || echo 0)
    log_info "Fase 1 concluída: ${port_count} pares host:porta encontrados."

    # ── Fase 2: Nmap (Fingerprint Profundo nas Portas Abertas) ────────────
    # Agrupa portas por IP para scan otimizado
    python3 -c "
import sys
from collections import defaultdict
ports_by_host = defaultdict(list)
with open('${outdir}/masscan/open_ports.txt') as f:
    for line in f:
        line = line.strip()
        if ':' in line:
            ip, port = line.rsplit(':', 1)
            ports_by_host[ip].append(port)
for ip, ports in ports_by_host.items():
    print(f\"{ip} {','.join(ports)}\")
" > "${outdir}/masscan/hosts_ports.txt" 2>/dev/null || true

    log_info "Fase 2: Nmap fingerprint em portas abertas..."
    while IFS=' ' read -r ip ports; do
        nmap -sS -sV -sC \
            --version-intensity 7 \
            -p "$ports" \
            --script "banner,ssl-cert,ssh-hostkey,http-title,http-server-header" \
            --script-args "vulners.shodan=1" \
            -T3 \
            --open \
            -oA "${outdir}/nmap/scan_${ip//./_}" \
            "$ip" >/dev/null 2>&1 || true
        log_info "  ✅ Nmap concluído para ${ip}"
    done < "${outdir}/masscan/hosts_ports.txt"
}
```

---

## 🔭 2. Service Tunneling Detection — SSH em Porta 443, Redis em 8080
Serviços em portas não convencionais são frequentemente ignorados por scanners básicos e pelos próprios times de segurança defensiva.

```python
import socket
import ssl
import re

# Fingerprints de banners por serviço (regex)
SERVICE_FINGERPRINTS = {
    "SSH":          re.compile(r"SSH-\d+\.\d+-"),
    "FTP":          re.compile(r"^220[\s-].*FTP|^220 .*ready", re.IGNORECASE),
    "SMTP":         re.compile(r"^220[\s-].*SMTP|Postfix|Exim|Sendmail", re.IGNORECASE),
    "HTTP":         re.compile(r"^HTTP/\d", re.IGNORECASE),
    "Redis":        re.compile(r"\+PONG|\-ERR", re.IGNORECASE),
    "MongoDB":      re.compile(r"MongoDB|mongod"),
    "MySQL":        re.compile(r"mysql_native_password|MariaDB"),
    "PostgreSQL":   re.compile(r"PostgreSQL"),
    "Elasticsearch":re.compile(r'"cluster_name":|"version":\{"number"'),
    "Memcached":    re.compile(r"^STAT pid"),
    "RDP":          re.compile(r"^\x03\x00"),
    "VNC":          re.compile(r"RFB \d{3}\.\d{3}"),
    "Telnet":       re.compile(r"\xff[\xfb-\xfe]."),
    "Docker_API":   re.compile(r'"Id":\s*"[a-f0-9]{64}"'),
    "K8s_API":      re.compile(r'"apiVersion":|"kubernetes"'),
}

def banner_grab(ip: str, port: int, timeout: float = 5.0, use_ssl: bool = False) -> str:
    """Captura o banner de um serviço via TCP com suporte a TLS."""
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        if use_ssl:
            ctx  = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock)
        # Envia probe HTTP para serviços que não enviam banner primeiro
        sock.sendall(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
        banner = sock.recv(1024).decode("utf-8", errors="replace")
        sock.close()
        return banner
    except Exception:
        return ""

def detect_service_on_port(ip: str, port: int) -> dict:
    """
    Identifica o serviço real em uma porta, independente do número dela.
    Detecta tunneling (SSH em 443, Redis em 8080, etc.)
    """
    # Tenta sem TLS primeiro, depois com TLS
    banner = banner_grab(ip, port, use_ssl=False)
    if not banner or len(banner) < 4:
        banner = banner_grab(ip, port, use_ssl=True)

    detected_service = "UNKNOWN"
    for service_name, pattern in SERVICE_FINGERPRINTS.items():
        if pattern.search(banner):
            detected_service = service_name
            break

    # Detecta tunneling: serviço inesperado na porta
    conventional_ports = {
        22: "SSH", 21: "FTP", 25: "SMTP", 80: "HTTP", 443: "HTTP",
        3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
        27017: "MongoDB", 9200: "Elasticsearch",
    }
    expected_service   = conventional_ports.get(port, "UNKNOWN")
    is_tunneled        = (
        detected_service != "UNKNOWN"
        and expected_service != "UNKNOWN"
        and detected_service != expected_service
        and port in conventional_ports
    )

    return {
        "ip":               ip,
        "port":             port,
        "detected_service": detected_service,
        "expected_service": expected_service,
        "is_tunneled":      is_tunneled,
        "banner_snippet":   banner[:200],
        "alert":            f"⚠️ SERVICE TUNNELING: {detected_service} em porta {port}!" if is_tunneled else None,
    }
```

---

## 🔑 3. Default Credential Spray — Serviços Abertos com Credenciais Padrão
Se encontrar um serviço crítico acessível, o próximo passo é tentar um conjunto mínimo e cirúrgico de credenciais padrão.

```python
import socket

# Conjunto mínimo e de alto impacto de credenciais padrão por serviço
DEFAULT_CREDS = {
    "Redis": [
        ("", ""),           # Sem autenticação (mais comum)
        ("", "redis"),      # Default password
        ("", "password"),
        ("default", ""),
    ],
    "MongoDB": [
        ("", ""),           # Sem autenticação
        ("admin", ""),
        ("admin", "admin"),
        ("admin", "password"),
        ("root", "root"),
    ],
    "Elasticsearch": [
        ("elastic", ""),
        ("elastic", "changeme"),
        ("elastic", "elastic"),
    ],
    "Memcached": [
        ("", ""),           # Memcached raramente tem autenticação
    ],
    "Docker_API": [
        ("", ""),           # API REST sem auth = controle total do host
    ],
}

def try_redis_auth(ip: str, port: int, password: str = "") -> bool:
    """Testa autenticação em Redis via protocolo RESP."""
    try:
        sock = socket.create_connection((ip, port), timeout=5)
        if password:
            sock.sendall(f"*2\r\n$4\r\nAUTH\r\n${len(password)}\r\n{password}\r\n".encode())
        else:
            sock.sendall(b"*1\r\n$4\r\nPING\r\n")
        response = sock.recv(128).decode("utf-8", errors="replace")
        sock.close()
        return "+PONG" in response or "+OK" in response
    except Exception:
        return False

def spray_default_credentials(scan_results: list[dict]) -> list[dict]:
    """
    Para cada serviço crítico encontrado, testa silenciosamente
    o conjunto mínimo de credenciais padrão.
    """
    findings = []
    for host in scan_results:
        service = host.get("detected_service", "")
        ip, port = host["ip"], host["port"]

        if service not in DEFAULT_CREDS:
            continue

        for user, pwd in DEFAULT_CREDS[service]:
            success = False
            if service == "Redis":
                success = try_redis_auth(ip, port, pwd)
            # Outros serviços: implementar handlers similares

            if success:
                findings.append({
                    "service":    service,
                    "ip":         ip,
                    "port":       port,
                    "username":   user or "(anonymous)",
                    "password":   pwd or "(none)",
                    "critical":   True,
                    "note":       f"Acesso não autenticado a {service} em {ip}:{port}",
                })
                break   # Para no primeiro sucesso para não gerar ruído

    return findings
```

---

## 📡 4. Async UDP Scan — Serviços de Gerenciamento Expostos
UDP é frequentemente negligenciado mas contém serviços críticos: SNMP, DNS, NTP, TFTP.

```bash
async_udp_scan() {
    local target_cidr="$1"
    local outdir="$2"

    # Portas UDP de alto valor para pentest
    local udp_ports="53,67,68,69,123,161,162,500,514,623,1194,1900,4500,5353,5683"

    log_info "Escaneando portas UDP críticas..."
    nmap -sU -T3 \
        --open \
        -p "$udp_ports" \
        --script "snmp-info,snmp-sysdescr,dns-recursion,ntp-info,tftp-enum" \
        -oA "${outdir}/nmap/udp_scan" \
        "$target_cidr" >/dev/null 2>&1 || true

    # SNMP Community String Discovery (frequentemente "public")
    if command -v onesixtyone &>/dev/null; then
        log_info "Testando community strings SNMP..."
        echo -e "public\nprivate\ncommunity\nmanager" > /tmp/snmp_communities.txt
        onesixtyone -c /tmp/snmp_communities.txt "$target_cidr" \
            >> "${outdir}/nmap/snmp_results.txt" 2>/dev/null || true
    fi
}
```

---

## 🛑 5. Adaptive Mode Selection — Inteligência de Timing
```bash
select_scan_mode() {
    local target="$1"

    # Detecta CDN/WAF via TTL e headers antes de escolher o modo
    local ttl
    ttl=$(ping -c 1 -W 2 "$target" 2>/dev/null | grep -oP 'ttl=\K\d+' || echo 64)

    if (( ttl >= 240 )); then
        # TTL alto → provavelmente CDN (Cloudflare, Akamai) → usar stealth
        echo "stealth"
    elif (( ttl <= 64 )); then
        # TTL baixo → host Linux direto → normal
        echo "normal"
    else
        # Incerto → conservador
        echo "normal"
    fi
}
```

---

## 📊 6. Saída e Integração com Pipeline
| Output | Destino |
|--------|---------|
| `masscan/open_ports.txt` — portas abertas | `Scan Architect` (contextualiza Nuclei) |
| `nmap/scan_*.xml` — fingerprint de serviços | `Report Architect` (CVEs e banners) |
| `service_tunneling.json` — SSH/Redis em portas inesperadas | Alerta crítico ao operador |
| `default_creds_hits.json` — autenticações com padrão | **Alerta crítico imediato** |

---

## 🔗 Integração no Ecossistema Global
- `scanning-tools`
- `red-team-tactics`
- `network-engineer`
- `007`
- `bash-pro`
