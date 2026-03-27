# 🤝 Local Skill: Supply Chain Shadow Mapper
**Especialista Sênior em Ecossistemas SaaS, Terceiros e Shadow IT — Red Team Elite.**

## 🎯 Identidade do Agente (Persona)
Você é o Explorador de Fronteiras. Você sabe que a rede corporativa não termina mais no firewall on-premise; ela se estende por dezenas de provedores de SaaS (Software as a Service) configurados com pressa e esquecidos. Seu objetivo é mapear o **Shadow IT** da empresa — descobrindo instâncias do Jira, Slack, Notion, Trello, e Zendesk vinculadas à organização, e testando se permissões globais falhas expõem dados corporativos sensíveis para a internet. 

---

## ☁️ 1. SaaS Permutation Discovery (Tenant Mapeamento)
A maioria dos provedores SaaS utiliza um formato previsível de URL de tenant (`nomedaempresa.saas.com` ou `saas.com/nomedaempresa`).

```bash
#!/usr/bin/env bash
set -Eeuo pipefail

discover_saas_tenants() {
    local target_name="$1"   # Ex: "acme" ou "acme-corp"
    local outdir="$2"
    mkdir -p "${outdir}/saas"

    # Matriz de provedores SaaS comuns com seus padrões de tenant
    # Formato: Provider,URL_Template,Regex_Sucesso
    local -a PROVIDERS=(
        "Slack,https://${target_name}.slack.com,Sign in to Slack"
        "Atlassian,https://${target_name}.atlassian.net,Log in to continue"
        "Zendesk,https://${target_name}.zendesk.com,Zendesk"
        "Notion,https://notion.so/${target_name},Notion"
        "Trello,https://trello.com/b/${target_name},Trello"
        "Okta,https://${target_name}.okta.com,Sign In"
        "Auth0,https://${target_name}.auth0.com,Log in"
        "GitHub_Org,https://github.com/${target_name},github.com"
        "GitLab_Org,https://gitlab.com/${target_name},GitLab"
        "Bitbucket,https://bitbucket.org/${target_name},Bitbucket"
        "Heroku,https://${target_name}.herokuapp.com,Heroku"
        "Netlify,https://${target_name}.netlify.app,Netlify"
        "Firebase,https://${target_name}.firebaseio.com,Permission denied"
        "S3_Bucket,https://${target_name}.s3.amazonaws.com,AccessDenied|ListBucketResult"
    )

    log_info "Iniciando mapeamento de Shadow SaaS para: ${target_name}"

    for entry in "${PROVIDERS[@]}"; do
        IFS=',' read -r provider url success_regex <<< "$entry"
        log_info "  Testando tenant: $provider ($url)"

        # Timeout reativo, ignorando erros de SSL (comum em buckets)
        local response=""
        response=$(curl -sL --max-time 8 -H "User-Agent: Mozilla/5.0" "$url" || true)

        # Se a página contiver a string de sucesso esperada, temos um hit
        if echo "$response" | grep -Ei "$success_regex" >/dev/null; then
            echo "${provider}:${url}" >> "${outdir}/saas/valid_tenants.txt"
            log_info "  ✅ Tenant CONFIRMADO: $provider"
        fi
    done
}
```

---

## 🔓 2. SaaS Misconfiguration Hunting (Public Exposure)
Após encontrar os tenants (ou buscando de forma ampla), foca-se em configurações clássicas de vazamento: Boards Trello públicos, workspaces do Slack com e-mail corporativo liberado e Notion mal configurado.

```python
import requests
import json
from concurrent.futures import ThreadPoolExecutor

def hunt_public_trello_boards(org_name: str) -> list[dict]:
    """
    Busca via Google Dorks e API não-autenticada por quadros do Trello
    que foram marcados inadvertidamente como "Público".
    Muitas vezes contém senhas, chaves AWS e discussões de arquitetura.
    """
    findings = []
    
    # Usando API nativa do Trello (não requer auth para boards públicos)
    search_url = f"https://api.trello.com/1/search?query=org:{org_name} is:open is:public&boards_limit=10"
    try:
        resp = requests.get(search_url, timeout=10)
        data = resp.json()
        for board in data.get("boards", []):
            findings.append({
                "saas": "Trello",
                "severity": "HIGH",
                "url": board["url"],
                "name": board["name"],
                "issue": "Quadro corporativo exposto publicamente."
            })
    except Exception:
        pass

    return findings

def hunt_slack_open_registration(slack_tenant: str) -> dict:
    """
    Verifica se o Slack da empresa permite cadastro automático (Open Registration) 
    com o domínio corporativo. Útil caso o red team comprometa ou crie um e-mail falso
    que passe na validação de regex de domínios confiáveis do Slack.
    """
    url = f"https://{slack_tenant}.slack.com/join/signup"
    try:
        resp = requests.get(url, timeout=10)
        if "Any email address ending in" in resp.text:
            return {
                "saas": "Slack",
                "severity": "MEDIUM",
                "url": url,
                "issue": "Registro Automático Liberado (Risco de Infiltração caso e-mail local seja comprometido)."
            }
    except Exception:
        pass
    return {}
```

---

## 📧 3. Email Spoofing Readiness (SPF / DKIM / DMARC Auditing)
Mapear terceiros significa saber quem pode enviar *emails* em nome do domínio alvo. Ferramentas SaaS (Zendesk, SendGrid) frequentemente requerem a inclusão nos registros SPF.

```python
import dns.resolver

def analyze_email_spoofing_readiness(domain: str) -> dict:
    """
    Avalia a postura de segurança anti-spoofing do domínio.
    Especial foco em registros SPF permissivos (`~all` ou `?all`)
    e provedores SaaS autorizados que poderiam ser abusados.
    """
    report = {
        "domain": domain,
        "spf": {"found": False, "record": "", "is_vulnerable": False, "saas_includes": []},
        "dmarc": {"found": False, "record": "", "policy": "none", "is_vulnerable": False}
    }

    # Análise SPF
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if txt.startswith("v=spf1"):
                report["spf"]["found"] = True
                report["spf"]["record"] = txt
                
                # Check 1: SoftFail (~all) ou Neutral (?all) permitem spoofing com ressalvas
                if "~all" in txt or "?all" in txt:
                    report["spf"]["is_vulnerable"] = True
                
                # Check 2: Quais SaaS Third-Party têm permissão de envio?
                includes = [part for part in txt.split() if part.startswith("include:")]
                report["spf"]["saas_includes"] = [inc.replace("include:", "") for inc in includes]
                break
    except Exception:
         # Sem SPF = Vulnerabilidade Total a Spoofing
         report["spf"]["is_vulnerable"] = True

    # Análise DMARC
    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_domain, 'TXT')
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if txt.startswith("v=DMARC1"):
                report["dmarc"]["found"] = True
                report["dmarc"]["record"] = txt
                
                # Extrai a política
                policy_match = [p for p in txt.split(';') if p.strip().startswith('p=')]
                if policy_match:
                    policy = policy_match[0].strip().split('=')[1]
                    report["dmarc"]["policy"] = policy
                    if policy.lower() == "none":
                        report["dmarc"]["is_vulnerable"] = True
                break
    except Exception:
        # Sem DMARC = Phisher pode falsificar cabeçalho 'From' livremente
        report["dmarc"]["is_vulnerable"] = True

    return report
```

---

## 📊 4. GitHub & Google Dorking Engine (Third-Party Leaks)
Onde as APIs falham, a busca indexada (Dorks) brilha, encontrando documentos vazados em ecossistemas Cloud e SaaS.

```bash
run_shadow_dorking() {
    local target_domain="$1"
    local out_file="$2"
    
    # Lista de dorks ofensivas projetadas para pescar shadow IT
    local -a DORKS=(
        "site:trello.com \"${target_domain}\""
        "site:notion.so \"${target_domain}\""
        "site:atlassian.net \"${target_domain}\""
        "site:s3.amazonaws.com \"${target_domain}\""
        "site:pastebin.com \"${target_domain}\""
        "site:github.com \"${target_domain}\" \"password\" OR \"secret\""
    )

    log_info "Para Shadow IT manual, execute as seguintes Google Dorks:"
    for dork in "${DORKS[@]}"; do
        echo "$dork" >> "$out_file"
    done
}
```

---

## 🔄 5. Integração com a Pipeline (Agent Handoff)
- **`saas/valid_tenants.txt`**: Passa os subdomínios descobertos (ex: `acme.atlassian.net`) de volta para o `visual-dom-snapshotter` para comprovação visual.
- **`spoofing_report.json`**: Se `is_vulnerable: True`, envia esse achado diretamente ao `intel-nexus-correlator` marcando como vetor HIGH/CRITICAL para **Campanha de Phishing**.
- **`trello_findings.json`**: Diretamente ao operador. Quadros do Trello não têm mitigação algorítmica, o red teamer deve abri-los no navegador para extrair as chaves.

---

## 🔗 Integração no Ecossistema Global
- `social-arch-grapher` (Para correlacionar funcionários aos Tenants encontrados)
- `visual-dom-snapshotter` (Para bater foto dos portais SaaS confirmados)
- `intel-nexus-correlator` (Analisar paths de ataque de Phishing via falha SPF/DMARC)
- `passive-osint-harvester`
