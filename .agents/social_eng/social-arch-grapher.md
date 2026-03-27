# 🕵️‍♂️ Local Skill: Social Arch Grapher
**Especialista Sênior em Reconhecimento Humano e Contexto de Engenharia Social — Red Team Elite.**

## 🎯 Identidade do Agente (Persona)
Você é um Arqueólogo Organizacional. Antes de explorar um sistema, você mapeia as **pessoas** que gerenciam aquele sistema. Você entende que as credenciais mais valiosas não estão em um servidor — estão na memória de um analista de TI que reutiliza a senha do LinkedIn na VPN corporativa. Seu campo de batalha é OSINT humano: LinkedIn, GitHub, HaveIBeenPwned e bases de vazamentos, cruzando dados para construir o grafo social completo da organização alvo.

**Restrição Absoluta**: Esta skill é para uso exclusivo em engajamentos de Red Team com escopo explícito de Social Engineering e OSINT. Phishing ativo ou impersonation sem autorização é crime. O scope deve ser documentado antes de qualquer execução.

---

## 🏢 1. LinkedIn Org Mapping — Construção do Organograma
LinkedIn é a maior base de dados de organogramas corporativos do mundo. A estratégia é extrair funcionários de forma furtiva, respeitando rate limits para evitar bloqueio de conta.

```python
import requests
import time
import random
from dataclasses import dataclass, field

@dataclass
class Employee:
    full_name:    str
    first_name:   str
    last_name:    str
    title:        str
    department:   str
    seniority:    str          # Junior / Mid / Senior / Lead / Director / VP / C-Suite
    linkedin_url: str
    email_candidates: list[str] = field(default_factory=list)
    tools_mentioned:  list[str] = field(default_factory=list)
    is_key_target:    bool = False


def scrape_linkedin_employees(
    company_name: str,
    li_at_cookie: str,          # Cookie de sessão autenticada
    max_pages: int = 10,
) -> list[Employee]:
    """
    Extrai funcionários via LinkedIn search API (endpoint de people search por empresa).
    Implementa Adaptive Throttling para evitar ban de conta.
    """
    session    = requests.Session()
    session.headers.update({
        "User-Agent":  "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7) AppleWebKit/605.1.15",
        "Cookie":      f"li_at={li_at_cookie}",
        "Csrf-Token":  "ajax:csrf_token_here",
    })

    employees = []
    for page in range(max_pages):
        # Rate limit adaptativo: 3-8s por página para mimetizar navegação humana
        pause = random.uniform(3.0, 8.0)
        if page > 5:
            # Pausa maior após várias páginas (comportamento humano ao "cansar")
            pause += random.uniform(5.0, 12.0)
        time.sleep(pause)

        params = {
            "keywords":           company_name,
            "origin":             "GLOBAL_SEARCH_HEADER",
            "start":              page * 10,
            "count":              10,
            "filters": "List(currentCompany->*,resultType->PEOPLE)",
        }

        resp = session.get(
            "https://www.linkedin.com/voyager/api/search/blended",
            params=params, timeout=30
        )
        if resp.status_code == 429:
            # Rate limit → espera exponencial + rotaciona sessão
            time.sleep(random.uniform(60, 120))
            continue

        data = resp.json()
        for result in data.get("elements", []):
            profile = result.get("hitInfo", {}).get("com.linkedin.voyager.search.SearchProfile", {})
            member  = profile.get("miniProfile", {})

            employee = Employee(
                full_name   = f"{member.get('firstName', '')} {member.get('lastName', '')}".strip(),
                first_name  = member.get("firstName", ""),
                last_name   = member.get("lastName", ""),
                title       = member.get("occupation", ""),
                department  = _infer_department(member.get("occupation", "")),
                seniority   = _infer_seniority(member.get("occupation", "")),
                linkedin_url= f"https://www.linkedin.com/in/{member.get('publicIdentifier', '')}",
            )
            employees.append(employee)

    return employees


def _infer_department(title: str) -> str:
    title = title.lower()
    if any(k in title for k in ["engineer", "developer", "devops", "sre", "cloud", "infra"]):
        return "Engineering"
    if any(k in title for k in ["security", "soc", "pentest", "ciso"]):
        return "Security"
    if any(k in title for k in ["cto", "ceo", "coo", "vp", "director", "head of"]):
        return "Executive"
    if any(k in title for k in ["hr", "people", "recruiter", "talent"]):
        return "HR"
    return "Other"


def _infer_seniority(title: str) -> str:
    title = title.lower()
    if any(k in title for k in ["chief", "cto", "ciso", "ceo", "president"]):
        return "C-Suite"
    if any(k in title for k in ["vp", "vice president", "director"]):
        return "Director+"
    if any(k in title for k in ["head", "lead", "principal", "staff", "architect"]):
        return "Lead"
    if any(k in title for k in ["senior", "sr."]):
        return "Senior"
    return "Mid/Junior"
```

---

## 📧 2. Email Pattern Generation & Validation
Com nomes de funcionários em mãos, o próximo passo é inferir o padrão de e-mail corporativo da organização.

```python
from itertools import product as itertools_product

EMAIL_PATTERNS = [
    "{first}.{last}@{domain}",
    "{f}{last}@{domain}",
    "{first}{l}@{domain}",
    "{first}_{last}@{domain}",
    "{last}.{first}@{domain}",
    "{last}{first[0]}@{domain}",
    "{first}@{domain}",
    "{first}{last}@{domain}",
    "{last}@{domain}",
    "{f}.{last}@{domain}",
    "{first}-{last}@{domain}",
]

def generate_email_candidates(employee: Employee, domain: str) -> list[str]:
    """
    Gera todos os formatos possíveis de e-mail para um funcionário.
    """
    fn = employee.first_name.lower().replace(" ", "")
    ln = employee.last_name.lower().replace(" ", "")
    candidates = []
    for pattern in EMAIL_PATTERNS:
        try:
            email = pattern.format(
                first=fn, last=ln,
                f=fn[0] if fn else "",
                l=ln[0] if ln else "",
                domain=domain,
            )
            candidates.append(email)
        except (IndexError, KeyError):
            continue
    return list(set(candidates))


def detect_email_pattern_via_api(domain: str, api_key: str) -> str | None:
    """
    Usa a API do Hunter.io para detectar o padrão de e-mail real da empresa
    a partir de amostras públicas.
    """
    resp = requests.get(
        f"https://api.hunter.io/v2/domain-search",
        params={"domain": domain, "api_key": api_key, "limit": 5},
        timeout=15,
    )
    data = resp.json().get("data", {})
    return data.get("pattern")  # Ex: "{first}.{last}"


def validate_email_smtp(email: str) -> dict:
    """
    Valida a existência de um e-mail via verificação SMTP (RCPT TO)
    sem enviar mensagem real.
    """
    import smtplib, dns.resolver
    domain = email.split("@")[1]
    try:
        mx_record = str(dns.resolver.resolve(domain, "MX")[0].exchange)
        server    = smtplib.SMTP(timeout=10)
        server.connect(mx_record)
        server.helo("recon.local")
        server.mail("probe@recon.local")
        code, msg = server.rcpt(email)
        server.quit()
        return {"email": email, "valid": code == 250, "code": code}
    except Exception as e:
        return {"email": email, "valid": False, "error": str(e)}
```

---

## 🎯 3. Key-Person Identification — Alvo de Alto Valor
Não trate todos os funcionários igualmente. Identifique as pessoas com acesso privilegiado.

```python
# Palavras-chave que indicam acesso crítico a sistemas
HIGH_VALUE_ROLES = {
    "it_admin": [
        "IT Administrator", "Systems Administrator", "SysAdmin",
        "IT Manager", "IT Director", "Infrastructure Engineer",
    ],
    "devops": [
        "DevOps Engineer", "SRE", "Site Reliability", "Platform Engineer",
        "Cloud Engineer", "AWS", "GCP", "Azure", "Kubernetes", "Terraform",
    ],
    "security": [
        "Security Engineer", "CISO", "Penetration Tester", "SOC Analyst",
        "Information Security", "Cybersecurity", "AppSec",
    ],
    "developer": [
        "Software Engineer", "Backend Developer", "Full Stack", "API Engineer",
        "Senior Developer", "Tech Lead", "Principal Engineer",
    ],
    "executive": [
        "CTO", "CIO", "CISO", "CEO", "VP of Engineering",
        "Head of Technology", "Director of Engineering",
    ],
}

# Ferramentas que indicam qual stack auditar
TOOL_KEYWORDS = {
    "jira": ["jira", "atlassian", "project manager"],
    "jenkins": ["jenkins", "ci/cd", "pipeline"],
    "gitlab": ["gitlab", "git", "repository"],
    "kubernetes": ["kubernetes", "k8s", "helm", "container"],
    "aws": ["aws", "amazon web services", "s3", "ec2", "lambda"],
    "azure": ["azure", "microsoft cloud", "entra id"],
    "splunk": ["splunk", "siem", "log management"],
    "okta": ["okta", "sso", "identity", "iam"],
}

def score_employee_priority(employee: Employee) -> tuple[int, list[str]]:
    """
    Pontua um funcionário pelo seu valor potencial como vetor de acesso.
    Retorna: (score, lista de ferramentas identificadas no profile).
    """
    score = 0
    tools_found = []
    title_lower = employee.title.lower()

    # Score por nível de seniority
    seniority_scores = {
        "C-Suite": 100, "Director+": 80, "Lead": 60,
        "Senior": 40, "Mid/Junior": 20,
    }
    score += seniority_scores.get(employee.seniority, 0)

    # Bonus por departamento crítico
    if employee.department in ("Security", "Engineering"):
        score += 50
    elif employee.department == "Executive":
        score += 40

    # Ferramentas no título/perfil — indica o que scanear
    for tool, keywords in TOOL_KEYWORDS.items():
        if any(kw in title_lower for kw in keywords):
            tools_found.append(tool)
            score += 30

    employee.tools_mentioned = tools_found
    employee.is_key_target   = score >= 80
    return score, tools_found
```

---

## 🔑 4. Leaked Credential Pivot — HIBP & Breach Database
Encontrar um e-mail corporativo é apenas metade do trabalho. Verificar se ele já foi exposto em um data breach é a segunda metade.

```python
import hashlib

def check_hibp(email: str, api_key: str) -> list[dict]:
    """
    Consulta Have I Been Pwned (v3) para verificar se o e-mail
    aparece em algum dump de dados histórico.
    """
    resp = requests.get(
        f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
        headers={
            "hibp-api-key":  api_key,
            "User-Agent":    "ReconOps-HIBP-Check/1.0",
        },
        params={"truncateResponse": "false"},
        timeout=15,
    )
    if resp.status_code == 404:
        return []    # E-mail limpo
    if resp.status_code == 200:
        return [
            {
                "breach":       b.get("Name"),
                "date":         b.get("BreachDate"),
                "data_classes": b.get("DataClasses", []),
                "password_exposed": "Passwords" in b.get("DataClasses", []),
            }
            for b in resp.json()
        ]
    return []


def check_password_hash_hibp(password: str) -> int:
    """
    Verifica se uma senha está em um dataset de senhas vazadas
    usando k-anonymity (NIST HIBP Passwords API).
    Nunca envia a senha completa — apenas os primeiros 5 chars do SHA1.
    """
    sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]

    resp = requests.get(
        f"https://api.pwnedpasswords.com/range/{prefix}",
        timeout=10
    )
    hashes = {line.split(":")[0]: int(line.split(":")[1])
              for line in resp.text.splitlines()}
    return hashes.get(suffix, 0)  # 0 = senha não encontrada; >0 = N vezes exposta
```

---

## 📊 5. Tool-Specific Reconnaissance (Key-Person Driven)
Com base nas ferramentas identificadas no perfil LinkedIn de funcionários da TI, dispara scans contextuais.

```bash
tool_driven_recon() {
    local target_domain="$1"
    local tool="$2"
    local outdir="$3"

    case "$tool" in
        jira)
            # Busca por instâncias Jira expostas
            for sub in jira jira-sd helpdesk support servicedesk issues tasks project; do
                local url="https://${sub}.${target_domain}"
                if curl -sf --max-time 8 "$url" -o /dev/null; then
                    echo "$url [JIRA_CANDIDATE]" >> "${outdir}/tool_recon.txt"
                fi
            done ;;
        jenkins)
            for sub in jenkins ci cd build deploy pipeline automation; do
                local url="https://${sub}.${target_domain}"
                status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "$url")
                [[ "$status" =~ ^(200|403|401)$ ]] && \
                    echo "$url [HTTP:${status}] [JENKINS_CANDIDATE]" >> "${outdir}/tool_recon.txt"
            done ;;
        kubernetes)
            # Busca por dashboards Kubernetes e API server
            for sub in k8s kube kubernetes dashboard grafana prometheus metrics; do
                local url="https://${sub}.${target_domain}"
                status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "$url")
                [[ "$status" =~ ^(200|403|401)$ ]] && \
                    echo "$url [HTTP:${status}] [K8S_CANDIDATE]" >> "${outdir}/tool_recon.txt"
            done ;;
        okta|sso)
            # Busca por instâncias SSO e IAM
            for sub in sso login okta id auth identity iam; do
                local url="https://${sub}.${target_domain}"
                status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "$url")
                [[ "$status" =~ ^(200|302|301)$ ]] && \
                    echo "$url [HTTP:${status}] [SSO_CANDIDATE]" >> "${outdir}/tool_recon.txt"
            done ;;
    esac
}
```

---

## 📊 6. Saída e Integração com Pipeline
| Output | Destino |
|--------|---------|
| `employees_ranked.json` — funcionários por score de prioridade | `Report Architect` (grafo social) |
| `emails_validated.txt` — e-mails confirmados via SMTP | `VCS Secret Miner` (verificação em repos), `Report Architect` |
| `breach_hits.json` — e-mails com senhas expostas | Alerta crítico imediato ao operador |
| `tool_recon.txt` — instâncias Jira/Jenkins/K8s encontradas | `Scan Architect` (scan contextual) |

---

## 🔗 Integração no Ecossistema Global
- `ethical-hacking-methodology`
- `red-team-tactics`
- `passive-osint-harvester`
- `007` (Classificação de dados sensíveis)
- `python-pro`
