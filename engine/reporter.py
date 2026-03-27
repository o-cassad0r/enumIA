#!/usr/bin/env python3
"""
reporter.py — Gerador de dashboard HTML para o projeto Enum.

Uso: python3 reporter.py <dominio> <workdir>

Dependência externa: pip install aiofiles
"""
# ─────────────────────────────────────────────────────────────────────────────
# SESSÃO A — Estrutura de dados (dataclasses + Path)
# ─────────────────────────────────────────────────────────────────────────────
import asyncio
import logging
import os
import string
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

import aiofiles  # pip install aiofiles

# Configuração de Logging (python-pro)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stderr)],
)
log = logging.getLogger(__name__)


# ── A1. Caminhos ─────────────────────────────────────────────────────────────

@dataclass
class ReconPaths:
    """Todos os caminhos de entrada derivados de workdir."""
    workdir: Path

    # Campos calculados em __post_init__
    ips:         Path = field(init=False)
    whois:       Path = field(init=False)
    hosts_dns:   Path = field(init=False)
    hosts_vivos: Path = field(init=False)
    nuclei_log:  Path = field(init=False)
    reverse_dns: Path = field(init=False)
    cloud_assets: Path = field(init=False)
    asn_info:    Path = field(init=False)
    takeover:    Path = field(init=False)
    params:      Path = field(init=False)
    files_found: Path = field(init=False)
    js_secrets:  Path = field(init=False)
    vhosts_dir:  Path = field(init=False)
    nmap_dir:    Path = field(init=False)
    naabu:       Path = field(init=False)
    dalfox:      Path = field(init=False)
    tlsx:        Path = field(init=False)
    crlfuzz:     Path = field(init=False)
    fuzzing_dir: Path = field(init=False)
    drift_report: Path = field(init=False)
    explorer_report: Path = field(init=False)
    waf_info:      Path = field(init=False)


    def __post_init__(self) -> None:
        w = self.workdir
        self.ips          = w / "ips_unicos.txt"
        self.whois        = w / "whois_raw.txt"
        self.hosts_dns    = w / "hosts_dns.txt"
        self.hosts_vivos  = w / "hosts_vivos.txt"
        self.nuclei_log   = w / "nuclei" / "vulnerabilidades.txt"
        self.reverse_dns  = w / "reverse_dns.txt"
        self.cloud_assets = w / "cloud_assets.txt"
        self.asn_info     = w / "asn_info.txt"
        self.takeover     = w / "takeover_results.txt"
        self.params       = w / "param_discovery.txt"
        self.files_found  = w / "interesting_files.txt"
        self.js_secrets   = w / "js_secrets"
        self.vhosts_dir   = w / "vhosts"
        self.nmap_dir     = w / "nmap"
        self.naabu        = w / "naabu_ports.txt"
        self.dalfox       = w / "dalfox" / "xss_results.txt"
        self.tlsx         = w / "edge" / "tlsx_sans.txt"
        self.crlfuzz      = w / "edge" / "crlfuzz_results.txt"
        self.fuzzing_dir  = w / "fuzzing"
        self.drift_report = w / "json_analysis" / "drift_delta.json"
        self.explorer_report = w / "json_analysis" / "deep_intelligence.json"
        self.waf_info     = w / "waf_info.txt"



# ── A2. Modelo de dados do relatório ─────────────────────────────────────────

@dataclass
class ReconReport:
    """Todos os valores já processados, prontos para injeção no template."""
    dom:          str
    scan_time:    str
    main_ip:      str

    # Contagens
    total_subs:   str = "0"
    total_vivos:  str = "0"

    # Nuclei
    nuclei_log:   str = "Scan limpo. Nenhuma vulnerabilidade crítica detectada."
    threat_level: str = "LOW"
    v_crit: int = 0
    v_high: int = 0
    v_med:  int = 0
    v_low:  int = 0
    v_info: int = 0

    # Infra
    whois_html:   str = "Sem dados de WHOIS."
    nmap_cve_log: str = "Nenhuma CVE ou Banner reportado pelo escâner de serviço."
    recommendations: str = "<p class='text-muted small'>Nenhuma recomendação crítica.</p>"

    # OSINT / Deep Intel
    asn_data:         str = "Nenhum dado de ASN disponível."
    takeover:         str = "Nenhum potencial de Takeover identificado."
    sensitive_files:  str = "<p class='text-muted small'>Nenhum documento sensível mapeado.</p>"
    reverse_dns:      str = "Nenhum registro reverso (PTR) encontrado."
    cloud_assets:     str = "Nenhum bucket S3/Azure/GCP detectado."
    js_secrets:       str = "Nenhuma credencial exposta em arquivos JS."
    vhosts:           str = "Nenhum Virtual Host identificado."
    params:           str = "Nenhum parâmetro minerado para o alvo."
    fuzzing_hits:     str = "Nenhum diretório/arquivo descoberto via Fuzzing."

    # Advanced Attack Surface
    naabu:            str = "Nenhuma porta atípica encontrada pelo Naabu."
    dalfox:           str = "Nenhum XSS detectado."
    tlsx:             str = "Nenhum SAN adicional descoberto."
    crlfuzz:          str = "Nenhuma injeção CRLF detectada."

    # Injeção via env vars (Bash → Python)
    screenshot_gallery: str = "<p class='text-muted small p-4'>Nenhuma evidência visual capturada.</p>"
    
    # New Intelligence
    drift_html:    str = "Nenhuma mudança estrutural detectada."
    explorer_html: str = "Nenhuma inteligência profunda extraída."
    waf_html:      str = "Nenhum WAF óbvio detectado."



# ─────────────────────────────────────────────────────────────────────────────
# SESSÃO B — Leitura async (aiofiles + asyncio.gather)
# ─────────────────────────────────────────────────────────────────────────────

async def async_read(path: Path, default: str = "Nenhum dado encontrado.") -> str:
    """Lê o conteúdo de um arquivo de forma assíncrona e segura."""
    try:
        if path.exists() and path.stat().st_size > 0:
            async with aiofiles.open(path, errors="ignore") as f:
                return (await f.read()).strip()
    except Exception as exc:
        log.warning(f"Erro ao ler arquivo {path}: {exc}")
        return f"Erro ao ler arquivo: {exc}"
    return default


# ── Funções de análise (sync — recebem conteúdo já lido) ─────────────────────

def build_recommendations(nmap_contents: list[str]) -> str:
    """Gera HTML de recomendações a partir do conteúdo já lido dos arquivos Nmap."""
    recs: set[str] = set()
    for content in nmap_contents:
        if "21/tcp open"   in content:
            recs.add("⚠️ FTP detectado: Testar login anônimo e sniffing de tráfego.")
        if "445/tcp open"  in content:
            recs.add("🚨 SMB detectado: Verificar por EternalBlue e compartilhamentos sem senha.")
        if "3306/tcp open" in content:
            recs.add("🛢️ MySQL exposto: Validar se aceita conexões externas e tentar brute-force de root.")
        if "22/tcp open"   in content:
            recs.add("🔑 SSH aberto: Verificar se permite autenticação por senha e versão do OpenSSH.")

    if not recs:
        return "<p class='text-muted small'>Nenhuma recomendação crítica para os serviços mapeados.</p>"

    items = "".join(
        f"<li class='list-group-item bg-transparent text-bright border-secondary small py-1'>{r}</li>"
        for r in recs
    )
    return f"<ul class='list-group list-group-flush'>{items}</ul>"


def build_nmap_cves(nmap_files: dict[str, str]) -> str:
    """Extrai CVEs e Banners do conteúdo Nmap já lido."""
    cve_data: list[str] = []

    for filename, content in nmap_files.items():
        host_ip   = filename.replace("scan_", "").replace(".txt", "")
        host_cves: list[str] = []
        capture   = False

        for line in content.splitlines():
            low = line.lower()
            if "vulners:" in low or "banner:" in low or "cve-" in low:
                capture = True
                host_cves.append(line.strip())
            elif capture and line.startswith("|"):
                host_cves.append(line.strip())
            elif capture and not line.startswith("|"):
                capture = False

        if host_cves:
            cve_data.append(f"--- [ HOST: {host_ip} ] ---")
            cve_data.extend(c for c in host_cves if c)
            cve_data.append("")

    return "\n".join(cve_data) if cve_data else "Nenhuma CVE ou Banner reportado pelo escâner de serviço."


async def _read_nmap_dir(nmap_dir: Path) -> dict[str, str]:
    """Lê todos os .txt do diretório nmap em paralelo."""
    if not nmap_dir.is_dir():
        return {}
    txt_files = [f for f in nmap_dir.iterdir() if f.suffix == ".txt"]
    contents  = await asyncio.gather(*(async_read(f, "") for f in txt_files))
    return {f.name: c for f, c in zip(txt_files, contents)}


async def _read_js_secrets_dir(js_dir: Path) -> str:
    """Lê todos os arquivos de js_secrets em paralelo e retorna HTML."""
    if not js_dir.is_dir():
        return "Nenhuma credencial exposta em arquivos JS."

    files    = list(js_dir.iterdir())
    contents = await asyncio.gather(*(async_read(f, "") for f in files))

    found = [
        f"<div class='mb-1 text-warning border-bottom border-secondary pb-1'>↳ {f.name}</div>"
        for f, c in zip(files, contents)
        if any(kw in c for kw in ("Found", "Key", "Secret", "Token"))
    ]
    return "".join(found) if found else "Nenhuma credencial exposta em arquivos JS."


async def _read_vhosts_dir(vhosts_dir: Path) -> str:
    """Lê todos os arquivos de vhosts em paralelo e retorna string consolidada."""
    if not vhosts_dir.is_dir():
        return "Nenhum Virtual Host identificado."

    files = [f for f in vhosts_dir.iterdir() if f.is_file()]
    if not files:
        return "Nenhum Virtual Host identificado."

    contents = await asyncio.gather(*(async_read(f, "") for f in files))
    
    found = []
    for f, c in zip(files, contents):
        if c:
            found.append(f"--- [ {f.name} ] ---\n{c}\n")
    
    return "\n".join(found) if found else "Nenhum Virtual Host identificado."


import json

async def _read_fuzzing_dir(fuzzing_dir: Path) -> str:
    """Lê arquivos JSON do ffuf e consolida os resultados em uma tabela HTML."""
    if not fuzzing_dir.is_dir():
        return "Nenhum diretório/arquivo descoberto via Fuzzing."

    json_files = [f for f in fuzzing_dir.iterdir() if f.suffix == ".json"]
    if not json_files:
        return "Nenhum diretório/arquivo descoberto via Fuzzing."

    contents = await asyncio.gather(*(async_read(f, "") for f in json_files))
    
    rows = []
    for f, c in zip(json_files, contents):
        if not c:
            continue
        try:
            data = json.loads(c)
            results = data.get("results", [])
            for r in results:
                url = r.get("url", "")
                status = r.get("status", 0)
                size = r.get("length", 0)
                
                # Cor para o status
                color = "text-success" if status in [200, 201, 204] else "text-warning" if status in [301, 302] else "text-danger" if status in [401, 403] else "text-main"
                
                rows.append(f"<tr><td class='mono {color}'>{status}</td><td class='mono'>{size}</td><td class='mono'><a href='{url}' target='_blank' class='text-cyan text-decoration-none'>{url}</a></td></tr>")
        except json.JSONDecodeError:
            log.warning(f"JSON inválido em {f.name}")
            continue

    if not rows:
        return "Nenhum resultado de fuzzing válido encontrado."

    html = f"""
    <div class="table-responsive f-card p-0 overflow-hidden">
        <table class="table table-dark table-hover table-borderless mono small m-0">
            <thead>
                <tr class="border-bottom border-secondary">
                    <th class="ps-4">STATUS</th>
                    <th>SIZE</th>
                    <th>URL Encontrada</th>
                </tr>
            </thead>
            <tbody>
                {''.join(rows)}
            </tbody>
        </table>
    </div>
    """
    return html


def build_drift_html(drift_json: str) -> str:
    """Transforma o JSON de drift em blocos HTML informativos."""
    try:
        data = json.loads(drift_json)
        if not data: return "Nenhuma mudança estrutural detectada."
        
        items = []
        for file, changes in data.items():
            items.append(f"<div class='mb-2'><span class='text-cyan'>[ FILE: {file} ]</span>")
            for change in changes:
                items.append(f"<div class='ms-3 small text-warning'>↳ {change}</div>")
            items.append("</div>")
        return "".join(items) if items else "Nenhuma mudança estrutural detectada."
    except:
        return "Erro ao processar dados de drift."


def build_explorer_html(explorer_json: str) -> str:
    """Transforma a análise profunda de JSON em HTML estruturado."""
    try:
        data = json.loads(explorer_json)
        if not data: return "Nenhuma inteligência profunda extraída."
        
        sections = []
        if "schemas" in data:
            sections.append("<h6 class='text-bright mb-2'>Schemas Detectados:</h6>")
            for url, schema in data["schemas"].items():
                sections.append(f"<div class='ms-2 small text-muted mb-1'>🌍 {url}</div>")
                sections.append(f"<pre class='terminal small mb-2'>{json.dumps(schema, indent=2)}</pre>")
        
        if "potential_idor" in data:
            sections.append("<h6 class='text-red mt-3 mb-2'>Potencial IDOR/BOLA:</h6>")
            for idor in data["potential_idor"]:
                sections.append(f"<div class='alert alert-danger py-1 small'>{idor}</div>")
                
        return "".join(sections) if sections else "Nenhuma inteligência profunda extraída."
    except:
        return "Erro ao processar inteligência profunda."



async def collect_data(paths: ReconPaths, dom: str) -> ReconReport:
    """
    Lança todas as leituras de arquivo em paralelo com asyncio.gather
    e monta o ReconReport tipado.
    """
    # Leituras de arquivo simples (paralelas)
    (
        ips_raw, whois_raw, nuclei_raw,
        rdns_raw, cloud_raw, asn_raw,
        takeover_raw, params_raw,
        hosts_dns_raw, hosts_vivos_raw,
        files_raw, naabu_raw, dalfox_raw,
        tlsx_raw, crlfuzz_raw, drift_raw, explorer_raw, waf_raw
    ) = await asyncio.gather(

        async_read(paths.ips,          "N/A"),
        async_read(paths.whois,        "Sem dados de WHOIS."),
        async_read(paths.nuclei_log,   ""),
        async_read(paths.reverse_dns,  "Nenhum registro reverso (PTR) encontrado."),
        async_read(paths.cloud_assets, "Nenhum bucket S3/Azure/GCP detectado."),
        async_read(paths.asn_info,     "Nenhum dado de ASN disponível."),
        async_read(paths.takeover,     "Nenhum potencial de Takeover identificado."),
        async_read(paths.params,       "Nenhum parâmetro minerado para o alvo."),
        async_read(paths.hosts_dns,    ""),
        async_read(paths.hosts_vivos,  ""),
        async_read(paths.files_found,  ""),
        async_read(paths.naabu,        "Nenhuma porta atípica encontrada pelo Naabu."),
        async_read(paths.dalfox,       "Nenhum XSS detectado."),
        async_read(paths.tlsx,         "Nenhum SAN adicional descoberto."),
        async_read(paths.crlfuzz,      "Nenhuma injeção CRLF detectada."),
        async_read(paths.drift_report, "{}"),
        async_read(paths.explorer_report, "{}"),
        async_read(paths.waf_info, "Nenhum WAF óbvio detectado."),
    )


    # Diretórios com múltiplos arquivos (paralelos entre si)
    nmap_files, js_secrets_html, vhosts_raw, fuzzing_raw = await asyncio.gather(
        _read_nmap_dir(paths.nmap_dir),
        _read_js_secrets_dir(paths.js_secrets),
        _read_vhosts_dir(paths.vhosts_dir),
        _read_fuzzing_dir(paths.fuzzing_dir),
    )

    # ── Processamento ────────────────────────────────────────────────────────
    main_ip      = ips_raw.split("\n")[0] if ips_raw != "N/A" else "N/A"
    whois_html   = whois_raw.replace("\n", "<br>")
    total_subs   = str(len(hosts_dns_raw.splitlines()))    if hosts_dns_raw   else "0"
    total_vivos  = str(len(hosts_vivos_raw.splitlines())) if hosts_vivos_raw else "0"

    # Contagem de severidade Nuclei
    nl = nuclei_raw.lower()
    v_crit = nl.count("[critical]")
    v_high = nl.count("[high]")
    v_med  = nl.count("[medium]")
    v_low  = nl.count("[low]")
    v_info = nl.count("[info]")

    threat_level = "LOW"
    if v_crit > 0:   threat_level = "CRITICAL"
    elif v_high > 0: threat_level = "HIGH"
    elif v_med  > 0: threat_level = "MEDIUM"

    # HTML de arquivos sensíveis
    if files_raw:
        items = "".join(f"<li>{ln}</li>" for ln in files_raw.splitlines())
        sensitive_files = f"<ul class='mono small'>{items}</ul>"
    else:
        sensitive_files = "<p class='text-muted small'>Nenhum documento sensível mapeado.</p>"

    # Análises que consomem conteúdo já lido
    recommendations = build_recommendations(list(nmap_files.values()))
    nmap_cve_log    = build_nmap_cves(nmap_files)

    # Variáveis de ambiente injetadas pelo Bash
    dns_table          = os.getenv("DNS_TABLE",          "<tr><td colspan='2'>Sem registros DNS</td></tr>")
    tech_stack         = os.getenv("TECH_STACK",         "<span class='text-muted small'>Stack tecnológica não identificada.</span>")
    screenshot_gallery = os.getenv("SCREENSHOT_GALLERY", "<p class='text-muted small p-4'>Nenhuma evidência visual capturada.</p>")

    return ReconReport(
        dom           = dom,
        scan_time     = datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        main_ip       = main_ip,
        total_subs    = total_subs,
        total_vivos   = total_vivos,
        nuclei_log    = nuclei_raw or "Scan limpo. Nenhuma vulnerabilidade crítica detectada.",
        threat_level  = threat_level,
        v_crit        = v_crit,
        v_high        = v_high,
        v_med         = v_med,
        v_low         = v_low,
        v_info        = v_info,
        whois_html    = whois_html,
        nmap_cve_log  = nmap_cve_log,
        recommendations     = recommendations,
        asn_data            = asn_raw,
        takeover            = takeover_raw,
        sensitive_files     = sensitive_files,
        reverse_dns         = rdns_raw,
        cloud_assets        = cloud_raw,
        js_secrets          = js_secrets_html,
        vhosts              = vhosts_raw,
        params              = params_raw,
        fuzzing_hits        = fuzzing_raw,
        naabu               = naabu_raw,
        dalfox              = dalfox_raw,
        tlsx                = tlsx_raw,
        crlfuzz             = crlfuzz_raw,
        dns_table           = dns_table,
        tech_stack          = tech_stack,
        screenshot_gallery  = screenshot_gallery,
        drift_html          = build_drift_html(drift_raw),
        explorer_html       = build_explorer_html(explorer_raw),
        waf_html            = waf_raw.replace("\n", "<br>"),
    )



# ─────────────────────────────────────────────────────────────────────────────
# SESSÃO C — Geração HTML (string.Template com delimitador @@)
# ─────────────────────────────────────────────────────────────────────────────

class ReconTemplate(string.Template):
    """
    Template com delimitador @@ para evitar colisão com chaves CSS/JS legítimas.
    Uso no template.html: @@{DOM}, @@{THREAT_LEVEL}, etc.
    """
    delimiter = "@@"


def render_html(template_text: str, report: ReconReport) -> str:
    """Substitui todos os @@{KEY} com safe_substitute (placeholders faltantes ficam intactos)."""
    return ReconTemplate(template_text).safe_substitute(
        DOM               = report.dom,
        SCAN_TIME         = report.scan_time,
        MAIN_IP           = report.main_ip,
        TOTAL_SUBS        = report.total_subs,
        TOTAL_VIVOS       = report.total_vivos,
        NUCLEI_LOG        = report.nuclei_log,
        NMAP_CVE_LOG      = report.nmap_cve_log,
        THREAT_LEVEL      = report.threat_level,
        RECOMMENDATIONS   = report.recommendations,
        WHOIS_DATA        = report.whois_html,
        ASN_DATA          = report.asn_data,
        TAKEOVER          = report.takeover,
        SENSITIVE_FILES   = report.sensitive_files,
        REVERSE_DNS       = report.reverse_dns,
        CLOUD_ASSETS      = report.cloud_assets,
        JS_SECRETS        = report.js_secrets,
        VHOSTS            = report.vhosts,
        PARAMS            = report.params,
        FUZZING           = report.fuzzing_hits,
        NAABU             = report.naabu,
        DALFOX            = report.dalfox,
        TLSX              = report.tlsx,
        CRLFUZZ           = report.crlfuzz,
        VULN_CRIT         = str(report.v_crit),
        VULN_HIGH         = str(report.v_high),
        VULN_MED          = str(report.v_med),
        VULN_LOW          = str(report.v_low),
        VULN_INFO         = str(report.v_info),
        DNS_TABLE         = report.dns_table,
        TECH_STACK        = report.tech_stack,
        SCREENSHOT_GALLERY= report.screenshot_gallery,
        DRIFT_LOG         = report.drift_html,
        EXPLORER_LOG      = report.explorer_html,
        WAF_DATA          = report.waf_html,
    )



# ─────────────────────────────────────────────────────────────────────────────
# Entrypoint
# ─────────────────────────────────────────────────────────────────────────────

async def main() -> None:
    # 1. Validação de argumentos
    if len(sys.argv) < 3:
        print("Uso: python3 reporter.py <dominio> <workdir>")
        sys.exit(1)

    dom      = sys.argv[1]
    workdir  = Path(sys.argv[2])
    script_dir    = Path(__file__).resolve().parent
    template_path = script_dir.parent / "templates" / "template.html"
    report_out    = workdir / "report.html"

    if not template_path.exists():
        log.error(f"Template {template_path} não encontrado.")
        sys.exit(1)

    # 2. Estrutura de caminhos (Sessão A)
    paths = ReconPaths(workdir=workdir)

    # 3. Coleta async de todos os dados (Sessão B)
    report = await collect_data(paths, dom)

    # 4. Leitura do template e renderização (Sessão C)
    try:
        async with aiofiles.open(template_path, encoding="utf-8") as f:
            template_text = await f.read()

        html_out = render_html(template_text, report)

        async with aiofiles.open(report_out, "w", encoding="utf-8") as f:
            await f.write(html_out)

        log.info(f"Dashboard consolidado com sucesso em: {report_out}")

    except Exception as exc:
        log.exception(f"Falha crítica ao gerar o dashboard: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
