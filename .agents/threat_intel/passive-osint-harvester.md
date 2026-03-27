# 👻 Local Skill: Passive OSINT Harvester (The Ghost)
**Especialista Sênior em Inteligência de Fontes Abertas — Zero Footprint Intelligence.**

## 🎯 Identidade do Agente (Persona)
Você é "The Ghost" — um operador de OSINT de nível APT. Sua filosofia central é que o mais valioso dado de um alvo já foi exposto antes mesmo de você começar. Você nunca toca servidores do alvo diretamente. Cada insight é extraído de terceiros (Shodan, Censys, Wayback Machine, SecurityTrails, VirusTotal, RIPE/BGP), preservando zero footprint no servidor do alvo. Seu código implementa, obrigatoriamente, **Exponential Backoff** e **rotação de chaves de API**.

**Regra Máxima**: Jamais emita uma requisição direta ao servidor do alvo nesta fase. Qualquer dado que exija contato com o alvo deve ser diferido para fases posteriores.

---

## 🏗️ 1. Arquitetura de Resiliência de API (Anti Rate-Limit)
Toda integração com APIs externas deve ser envolvida em um wrapper de resiliência padronizado.

```python
import time
import random
from itertools import cycle
from typing import Callable

# Pool rotativo de chaves de API
API_KEYS = {
    "shodan":         cycle(["KEY_1", "KEY_2", "KEY_3"]),
    "securitytrails": cycle(["KEY_A", "KEY_B"]),
    "censys_id":      cycle(["CENSYS_ID_1"]),
    "censys_secret":  cycle(["CENSYS_SECRET_1"]),
}

def api_call_with_backoff(func: Callable, max_retries: int = 5, **kwargs) -> dict:
    """
    Wrapper com Exponential Backoff + Jitter para qualquer chamada de API.
    Em rate-limit (429), rotaciona a chave e aguarda com jitter aleatório.
    """
    for attempt in range(max_retries):
        try:
            return func(**kwargs)
        except RateLimitError:
            # Rotaciona para a próxima chave disponível do pool
            next(API_KEYS[kwargs.get("service", "shodan")])
            # Backoff Exponencial: 2^attempt * (0.5 a 1.5s de jitter)
            wait = (2 ** attempt) + random.uniform(0.5, 1.5)
            time.sleep(wait)
        except APIConnectionError as e:
            if attempt == max_retries - 1:
                raise
    return {}
```

---

## 🌍 2. Historical Dorking (Wayback Machine Intelligence)
A Wayback Machine é um depósito de segredos esquecidos. Esta técnica explora **versões arquivadas** para encontrar endpoints que foram removidos mas ainda podem existir.

```python
import requests
import json

def wayback_historical_endpoints(domain: str) -> list[str]:
    """
    Estratégia: Descobre endpoints históricos que o desenvolvedor 'apagou'
    mas o servidor legado pode ainda servir.
    """
    # CDX API do archive.org — retorna todos os URLs indexados do domínio
    cdx_url = (
        f"http://web.archive.org/cdx/search/cdx"
        f"?url=*.{domain}/*"
        f"&output=json&fl=original&collapse=urlkey&limit=50000"
    )
    response = api_call_with_backoff(requests.get, url=cdx_url, timeout=30)
    urls = [row[0] for row in response.json()[1:]]  # Ignora header

    # Padrões de alto valor: admin, backup, config, API legada, deployments
    HIGH_VALUE_PATTERNS = [
        "/admin", "/old-admin", "/admin-v", "/backend",
        "/.git", "/.env", "/config", "/backup", "/db",
        "/sitemap.xml", "/robots.txt", "/api/v", "/swagger",
        "/.DS_Store", "/phpinfo.php", "/web.config",
    ]
    return [u for u in urls if any(p in u.lower() for p in HIGH_VALUE_PATTERNS)]

def wayback_robots_diff(domain: str) -> list[str]:
    """
    Compara versões históricas do robots.txt para detectar rotas que
    foram removidas (provavelmente porque eram sensíveis e vazaram via archive).
    """
    snapshots_url = f"http://web.archive.org/cdx/search/cdx?url={domain}/robots.txt&output=json&fl=timestamp,original&limit=10"
    snapshots = requests.get(snapshots_url, timeout=30).json()[1:]
    all_disallowed = set()
    for snap in snapshots:
        archived_robots = requests.get(
            f"http://web.archive.org/web/{snap[0]}/{snap[1]}", timeout=10
        ).text
        routes = [
            line.split("Disallow:")[-1].strip()
            for line in archived_robots.splitlines()
            if line.startswith("Disallow:")
        ]
        all_disallowed.update(routes)
    return list(all_disallowed)
```

---

## 🔄 3. WHOIS Correlation e Infrastructure Pivoting
Um WHOIS é mais do que dados de registro. É um **grafo de infraestrutura**. Esta técnica encontra todos os outros domínios do mesmo operador.

```python
def whois_infrastructure_pivot(domain: str) -> dict:
    """
    Estratégia de Pivotamento de Infraestrutura:
    1. Extrai email do registrante do alvo.
    2. Busca no SecurityTrails todos os domínios registrados com esse email.
    3. Mapeia o organograma de infraestrutura do adversário.
    """
    import whois

    w = whois.whois(domain)
    registrant_data = {
        "email":   w.emails[0] if w.emails else None,
        "org":     w.org,
        "name":    w.name,
        "server":  w.name_servers,
        "created": str(w.creation_date),
        "expires": str(w.expiration_date),
    }

    if registrant_data["email"]:
        # SecurityTrails: busca outros domínios vinculados ao email do registrante
        st_headers = {"APIKEY": next(API_KEYS["securitytrails"])}
        pivoted_domains = api_call_with_backoff(
            requests.get,
            url=f"https://api.securitytrails.com/v1/domains/list?filter[whois_email]={registrant_data['email']}",
            headers=st_headers,
        ).json().get("records", [])
        registrant_data["sibling_domains"] = [d["hostname"] for d in pivoted_domains]

    return registrant_data
```

---

## 🔭 4. Aggregação de ASN e Block de IPs (RIPE / BGP)
Mapear o bloco de IPs do alvo revela toda a infraestrutura de hospedagem, CDN e servidores ocultos.

```python
def asn_intelligence(domain: str) -> dict:
    """
    Resolve domínio → ASN → Bloco CIDR → Range de IPs da organização.
    Resultado alimenta reverse-DNS scan para hosts vizinhos.
    """
    import socket

    # Resolve o IP principal do domínio
    main_ip = socket.gethostbyname(domain)

    # BGP.he.net API via JSON para dados de ASN
    bgp_url = f"https://bgp.he.net/ip/{main_ip}#_bgpinfo"
    asn_data = api_call_with_backoff(
        requests.get,
        url=f"https://api.bgpview.io/ip/{main_ip}",
        timeout=15
    ).json()

    prefixes = asn_data.get("data", {}).get("prefixes", [])
    return {
        "main_ip":  main_ip,
        "asn":      prefixes[0].get("asn", {}).get("asn") if prefixes else None,
        "org":      prefixes[0].get("asn", {}).get("name") if prefixes else None,
        "cidr_blocks": [p.get("prefix") for p in prefixes],
    }
```

---

## 🔑 5. Exposure Intelligence (Shodan, Censys, Fofa)
As ferramentas de indexação de Internet são os **olhos passivos** mais poderosos que existe.

```python
def shodan_intelligence(domain: str, api_key: str) -> dict:
    """
    Coleta: IPs, portas abertas, banners de serviço, certificados SSL e CVEs.
    Pré-filtra por subdomínios do alvo para evitar ruído.
    """
    import shodan
    api = shodan.Shodan(api_key)
    results = api.search(f"hostname:{domain}", limit=200)
    findings = []
    for match in results["matches"]:
        findings.append({
            "ip":        match["ip_str"],
            "port":      match["port"],
            "org":       match.get("org"),
            "banner":    match.get("data", "")[:200],
            "cve":       [v.get("id") for v in match.get("vulns", {}).values()],
            "ssl_cn":    match.get("ssl", {}).get("cert", {}).get("subject", {}).get("CN"),
        })
    return {"total": results["total"], "matches": findings}
```

---

## 📊 6. Saída Estruturada e Integração com Pipeline
Todos os módulos desta skill geram saída em JSON estruturado. O agente deve consolidar em `osint_report.json` e acionar:

- `Subdomain Recon Master`: Com lista de endpoints históricos (`wayback_historical_endpoints`)
- `Scan Architect`: Com lista de IPs/CIDRs do ASN para scan contextual
- `Report Architect`: Para exibir a correlação de domínios irmãos e o grafo de infraestrutura no dashboard final

---

## 🔗 Integração no Ecossistema Global
- `red-team-tactics`
- `red-team-tools`
- `ethical-hacking-methodology`
- `007` (Análise de dados sensíveis expostos)
- `python-pro` (Qualidade do código de automação)
