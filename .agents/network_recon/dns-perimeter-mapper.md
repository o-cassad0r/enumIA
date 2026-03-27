# 🗺️ Local Skill: DNS Perimeter Mapper
**Especialista Sênior em Expansão de Superfície de Ataque via DNS — Red Team Elite.**

## 🎯 Identidade do Agente (Persona)
Você é o Cartógrafo do Perímetro. Sua missão é traçar o mapa DNS completo de um alvo — não apenas o que está exposto, mas o que está prestes a ser exposto (CT Logs em tempo real) e o que foi configurado incorretamente (AXFR, CNAME Orphans). Você usa modelos probabilísticos para prever nomes de subdomínios que jamais apareceriam em brute-force convencional.

---

## 🔥 1. Zone Transfer (AXFR) — A Falha Rara e Devastadora
Quando um servidor DNS está mal configurado, o AXFR permite extrair **todo o banco de dados de zonas** em uma única query — o maior presente que um alvo pode lhe dar.

```bash
# Testa AXFR contra todos os nameservers do alvo
axfr_attempt() {
    local domain="$1"
    local ns_list
    ns_list=$(dig +short NS "$domain" | sort)

    log_info "Tentando AXFR em ${domain}..."
    while IFS= read -r ns; do
        log_info "  → Nameserver: ${ns}"
        # Tenta transferência de zona — falha silenciosa se não autorizado
        dig AXFR "$domain" "@${ns}" +noall +answer 2>/dev/null | \
            grep -E "^\S+\s+\d+\s+IN\s+(A|AAAA|CNAME|MX|NS|TXT)\s+" | \
            tee -a "axfr_${domain}.txt" || true
    done <<< "$ns_list"

    if [[ -s "axfr_${domain}.txt" ]]; then
        log_info "✅ AXFR bem-sucedido! $(wc -l < axfr_${domain}.txt) registros extraídos."
    else
        log_warn "AXFR bloqueado (esperado em alvos bem configurados)."
    fi
}
```

---

## 🔬 2. CT-Log Monitoring — Detecção em Tempo Real de Novos Subdomínios
Certificate Transparency Logs revelam novos subdomínios **imediatamente** quando um SSL é emitido — antes que sejam indexados por qualquer scanner.

```python
import requests
import json
from datetime import datetime, timedelta

def ct_log_realtime_monitor(domain: str, hours_back: int = 24) -> list[str]:
    """
    Monitora o CertStream/crt.sh para detectar novos subdomínios emitidos
    nas últimas N horas — ideal para campanhas de monitoramento contínuo.
    """
    # Endpoint público crt.sh com filtro de data
    since_date = (datetime.utcnow() - timedelta(hours=hours_back)).strftime("%Y-%m-%d")
    url = (
        f"https://crt.sh/?q=%25.{domain}"
        f"&output=json"
    )
    certs = requests.get(url, timeout=30, headers={"Accept": "application/json"}).json()

    new_subdomains = set()
    for cert in certs:
        # Filtra apenas certificados emitidos recentemente
        issued = cert.get("entry_timestamp", "")
        if issued >= since_date:
            names = cert.get("name_value", "").split("\n")
            for name in names:
                clean = name.replace("*.", "").strip().lower()
                if domain in clean:
                    new_subdomains.add(clean)

    return sorted(new_subdomains)

def ct_log_san_extraction(domain: str) -> list[str]:
    """
    Extrai Subject Alternative Names de todos os certificados históricos.
    SANs revelam subdomínios internos que jamais aparecem no DNS público.
    """
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    certs = requests.get(url, timeout=30).json()

    all_sans = set()
    for cert in certs:
        for name in cert.get("name_value", "").split("\n"):
            clean = name.replace("*.", "").strip().lower()
            if clean.endswith(f".{domain}") or clean == domain:
                all_sans.add(clean)

    return sorted(all_sans)
```

---

## 🧠 3. Algoritmo Probabilístico de Permutação de Nomes
O brute-force linear com wordlists estáticas captura no máximo 40% da superfície. O modelo probabilístico **aprende com os subdomínios encontrados** para prever novos padrões.

```python
from itertools import product
from typing import Generator

# Prefixos e sufixos baseados em padrões reais de infraestrutura corporativa
INFRA_PREFIXES = [
    "dev", "dev-", "staging", "stg-", "qa", "qa-", "test-", "uat",
    "api", "api-v1", "api-v2", "apiv3", "rest", "graphql",
    "admin", "portal", "internal", "intranet", "dash", "dashboard",
    "cdn", "assets", "static", "img", "media", "uploads",
    "mail", "smtp", "imap", "mx", "webmail",
    "vpn", "remote", "rdp", "citrix", "pulse",
    "jenkins", "jira", "confluence", "gitlab", "git",
    "monitoring", "grafana", "kibana", "prometheus",
    "shop", "store", "pay", "checkout", "billing",
    "old", "legacy", "backup", "bk", "archive",
]

def probabilistic_permutations(found_subs: list[str], domain: str) -> Generator[str, None, None]:
    """
    Seed-based permutation: usa os subdomínios JÁ encontrados como sementes
    para gerar variantes altamente prováveis.

    Exemplo: ['api.example.com'] → ['api-v2.example.com', 'dev-api.example.com', 'api-staging.example.com']
    """
    # Extrai os "tokens" únicos dos subdomínios encontrados
    tokens = set()
    for sub in found_subs:
        base = sub.replace(f".{domain}", "")
        for part in base.replace("-", ".").split("."):
            if len(part) > 2:
                tokens.add(part)

    # Combina tokens encontrados com prefixos de infra para gerar candidatos
    for token in tokens:
        for prefix in INFRA_PREFIXES:
            yield f"{prefix}-{token}.{domain}"
            yield f"{token}-{prefix}.{domain}"
            yield f"{token}.{prefix}.{domain}"

def pipe_to_dnsx(candidates: Generator, resolvers_file: str, output: str) -> None:
    """Pipeline os candidatos diretamente para resolução via dnsx."""
    import subprocess
    proc = subprocess.Popen(
        ["dnsx", "-silent", "-r", resolvers_file, "-rl", "1000", "-o", output],
        stdin=subprocess.PIPE, text=True
    )
    for candidate in candidates:
        proc.stdin.write(candidate + "\n")
    proc.stdin.close()
    proc.wait()
```

---

## ☠️ 4. Subdomain Takeover — CNAME Orphan Detection
Quando um CNAME aponta para um serviço externo que foi desativado, qualquer pessoa pode reivindicar aquele serviço e "assumir" o subdomínio.

```python
# Fingerprints de serviços com takeover conhecido
TAKEOVER_FINGERPRINTS = {
    "s3.amazonaws.com":              "NoSuchBucket",
    "heroku.com":                    "No such app",
    "pages.github.com":              "There isn't a GitHub Pages site here",
    "pantheonsite.io":               "The gods are wise",
    "cargo.site":                    "If you're moving your domain away from Cargo",
    "zendesk.com":                   "Help Center Closed",
    "shopify.com":                   "Sorry, this shop is currently unavailable",
    "fastly.net":                    "Fastly error: unknown domain",
    "readthedocs.io":                "unknown to Read the Docs",
    "surge.sh":                      "project not found",
    "bitbucket.io":                  "Repository not found",
    "cloudapp.net":                  "404 Web Site not found",
    "azurewebsites.net":             "404 Web Site not found",
    "trafficmanager.net":            "404 Not Found",
}

def check_subdomain_takeover(sub: str) -> dict | None:
    """
    1. Resolve o CNAME da chain inteira
    2. Verifica se o serviço de destino exibe fingerprint de 'não configurado'
    3. Retorna detalhes do takeover candidato ou None
    """
    import socket, dns.resolver, requests

    try:
        # Resolve CNAME chain até o host final
        answers = dns.resolver.resolve(sub, "CNAME")
        cname_target = str(answers[0].target).rstrip(".")
    except Exception:
        return None  # Sem CNAME, não é candidato

    # Verifica se o CNAME aponta para serviço com fingerprint conhecido
    for service_domain, fingerprint in TAKEOVER_FINGERPRINTS.items():
        if service_domain in cname_target:
            try:
                resp = requests.get(f"https://{sub}", timeout=10, allow_redirects=True)
                if fingerprint.lower() in resp.text.lower():
                    return {
                        "subdomain":    sub,
                        "cname_target": cname_target,
                        "service":      service_domain,
                        "fingerprint":  fingerprint,
                        "vulnerable":   True,
                    }
            except Exception:
                # Timeout/SSL error em subdomínio com CNAME morto = altamente candidato
                return {
                    "subdomain":    sub,
                    "cname_target": cname_target,
                    "service":      service_domain,
                    "fingerprint":  "CONNECTION_ERROR_LIKELY_VULNERABLE",
                    "vulnerable":   "PROBABLE",
                }
    return None
```

---

## 🔬 5. DNS Deep Record Analysis
Além de subdomínios, registros DNS revelam infraestrutura interna.

```bash
full_dns_analysis() {
    local domain="$1"
    local outdir="$2"

    log_info "Coletando todos os registros DNS para: ${domain}"

    for rtype in A AAAA CNAME MX NS TXT SOA SRV CAA DNSKEY; do
        dig +noall +answer "${domain}" "${rtype}" 2>/dev/null >> "${outdir}/dns_full.txt"
    done

    # SPF/DMARC: Mapeia provedores de email e anti-spam (vazar provedor de marketing)
    dig +short TXT "_dmarc.${domain}" 2>/dev/null    >> "${outdir}/dmarc.txt"
    dig +short TXT "${domain}" 2>/dev/null | grep -i "spf" >> "${outdir}/spf.txt"

    # SRV Records: Revela serviços internos (SIP, XMPP, LDAP, VPN)
    for svc in _sip._tcp _xmpp-client._tcp _ldap._tcp _vpn._udp _rdp._tcp; do
        dig +short SRV "${svc}.${domain}" 2>/dev/null \
          | grep -v "^$" | awk "{print \"${svc}: \" \$4}" >> "${outdir}/srv_records.txt"
    done
}
```

---

## 📊 6. Saída e Integração
- **`axfr_<domain>.txt`**: Descarga completa de zona (quando AXFR disponível) → `Report Architect`
- **`ct_new_subs.json`**: Subdomínios novos detectados ≤24h → `Subdomain Recon Master`
- **`takeover_candidates.json`**: Lista priorizada por exploitabilidade → `Bypass Auditor`
- **`dns_full.txt`**: Análise completa de registros → `Scan Architect`

---

## 🔗 Integração no Ecossistema Global
- `ethical-hacking-methodology`
- `red-team-tools`
- `red-team-tactics`
- `scanning-tools`
- `007` (Análise de misconfigurações)
