# 🧠 Local Skill: Intel Nexus Correlator
**O Cérebro da Operação — Síntese, Correlação e Priorização de Toda a Superfície de Ataque.**

## 🎯 Identidade do Agente (Persona)
Você é o Analista Estratégico. Enquanto as outras skills coletam dados isolados, você é responsável por **conectar os pontos**. Você consome os outputs de todas as skills do ecossistema, identifica **caminhos críticos de invasão** (Attack Paths de múltiplos saltos) e entrega ao operador um gráfico priorizado de ataque, formatado como `Mermaid Diagram`, relatório `Markdown` e arquivo `attack_graph.json`. Sua saída é o `Artifact Final` do Antigravity para o engagement.

---

## 📥 1. Estrutura de Coleta de Dados (Unified Intel Schema)
Antes de correlacionar, padronize. Cada skill do ecossistema deve gerar dados no mesmo schema base.

```python
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"

class SkillSource(str, Enum):
    DNS_MAPPER       = "dns-perimeter-mapper"
    SUBDOMAIN_RECON  = "subdomain-recon"
    PASSIVE_OSINT    = "passive-osint-harvester"
    VCS_MINER        = "vcs-secret-miner"
    API_FUZZER       = "api-endpoint-fuzzer"
    NET_SCANNER      = "network-perimeter-scanner"
    WAF_ADAPTER      = "waf-evasion-adapter"
    SOCIAL_GRAPHER   = "social-arch-grapher"

@dataclass
class IntelNode:
    """Um ativo descoberto por qualquer skill do ecossistema."""
    node_id:      str                  # UUID único para referência cruzada
    asset_type:   str                  # "subdomain", "port", "secret", "employee", "endpoint"
    value:        str                  # O ativo em si (ex: "jenkins.target.com")
    source_skill: SkillSource
    severity:     Severity = Severity.INFO
    tags:         list[str] = field(default_factory=list)   # ["jenkins", "ci/cd", "aws-creds"]
    metadata:     dict      = field(default_factory=dict)   # Dados extras do source_skill
    linked_nodes: list[str] = field(default_factory=list)   # IDs de outros IntelNodes relacionados

@dataclass
class AttackPath:
    """Um caminho de ataque completo de múltiplos saltos."""
    path_id:        str
    title:          str
    severity:       Severity
    nodes:          list[IntelNode]     # Cadeia de ativos do caminho
    entry_point:    IntelNode           # Ponto de entrada (onde o ataque começa)
    impact:         str                 # O que é comprometido no final
    exploitation:   list[str]           # Passos de exploração em linguagem clara
    cvss_estimate:  float = 0.0         # Estimativa de CVSS do path completo
```

---

## 🔗 2. Correlation Engine — Conectando os Pontos entre Skills
A lógica central: um ativo de uma skill pode **amplificar** ou **habilitar** um achado de outra.

```python
from itertools import combinations
from typing import Generator

# Regras de correlação: (tag_A, tag_B) → descrição do link + severidade elevada
CORRELATION_RULES = [
    # Jenkins + Credenciais AWS no VCS = Caminho Crítico de Comprometimento de Cloud
    ({"jenkins", "ci/cd"},      {"aws-secret", "aws-key"},       Severity.CRITICAL,
     "Jenkins com credenciais AWS no histórico de commits → acesso direto à cloud"),

    # Subdomínio de staging + sem autenticação = exposição de dados de dev
    ({"staging", "beta", "dev"},{"unauthenticated", "403-bypass"},Severity.HIGH,
     "Ambiente de desenvolvimento exposto sem autenticação ou com bypass simples"),

    # Redis/MongoDB sem auth + IP público = RCE/exfiltração direta
    ({"redis", "mongodb"},       {"no-auth", "public-ip"},        Severity.CRITICAL,
     "Banco de dados sem autenticação acessível publicamente → exfiltração imediata"),

    # Employee de TI + credencial em vazamento + VPN exposta = acesso à rede interna
    ({"it-admin", "devops"},     {"breach-hit"},                  Severity.CRITICAL,
     "Funcionário de TI com credencial vazada + VPN exposta → acesso à rede interna"),

    # API v0/beta sem autenticação + IDOR = acesso a dados de todos os usuários
    ({"api-beta", "api-v0"},    {"idor", "no-auth"},              Severity.HIGH,
     "API em versão beta sem controle de acesso adequado → IDOR massivo"),

    # Subdomínio takeover + e-mail corporativo = phishing perfeito
    ({"takeover-candidate"},     {"employee-email"},              Severity.HIGH,
     "Takeover de subdomínio + emails corporativos → campanha de phishing confiável"),

    # GraphQL introspection + dados sensíveis = mapa completo da aplicação
    ({"graphql-introspection"},  {"pii", "financial"},            Severity.HIGH,
     "GraphQL exposto com introspection → mapa completo + acesso a dados sensíveis"),

    # Chave privada em repo + subdomínio ativo = comprometimento direto
    ({"private-key"},            {"active-subdomain"},            Severity.CRITICAL,
     "Chave privada exposta no VCS + subdomínio ativo → comprometimento imediato"),
]

def correlate_nodes(nodes: list[IntelNode]) -> list[tuple[IntelNode, IntelNode, Severity, str]]:
    """
    Correlaciona pares de IntelNodes usando as regras definidas.
    Retorna lista de (node_a, node_b, severity_elevada, descrição_do_link).
    """
    correlations = []
    for node_a, node_b in combinations(nodes, 2):
        tags_a = set(node_a.tags)
        tags_b = set(node_b.tags)
        for rule_tags_a, rule_tags_b, severity, description in CORRELATION_RULES:
            if (tags_a & rule_tags_a and tags_b & rule_tags_b) or \
               (tags_a & rule_tags_b and tags_b & rule_tags_a):
                correlations.append((node_a, node_b, severity, description))
    return correlations
```

---

## 🎯 3. Attack Path Builder — Construção de Caminhos de Invasão
Transforma correlações em **narrativas de ataque** com passos claros de exploração.

```python
import uuid

def build_attack_paths(
    correlations: list[tuple],
    all_nodes:    list[IntelNode],
) -> list[AttackPath]:
    """
    Constrói AttackPaths priorizados a partir das correlações.
    Cada path recebe um CVSS estimado baseado na severidade + # de saltos.
    """
    paths = []

    for node_a, node_b, severity, description in correlations:
        # Constrói a chain de nós relevantes ao path
        chain = [node_a, node_b]

        # Infere entry point (o ativo mais externamente acessível primeiro)
        if node_a.asset_type in ("subdomain", "port", "endpoint"):
            entry, target = node_a, node_b
        else:
            entry, target = node_b, node_a

        # Estima CVSS com base na severidade e no tipo de impacto
        cvss_map = {Severity.CRITICAL: 9.5, Severity.HIGH: 8.1,
                    Severity.MEDIUM: 5.5, Severity.LOW: 3.0}
        cvss = cvss_map.get(severity, 0.0)

        path = AttackPath(
            path_id     = str(uuid.uuid4())[:8],
            title       = f"{entry.value} → {target.value}: {description[:60]}",
            severity    = severity,
            nodes       = chain,
            entry_point = entry,
            impact      = _infer_impact(target),
            exploitation= _generate_exploitation_steps(entry, target, description),
            cvss_estimate = cvss,
        )
        paths.append(path)

    # Ordena por CVSS decrescente
    return sorted(paths, key=lambda p: p.cvss_estimate, reverse=True)


def _infer_impact(target_node: IntelNode) -> str:
    impact_map = {
        "secret":     "Comprometimento de credenciais de cloud/serviço",
        "port":       "Acesso a serviço de infraestrutura interna",
        "employee":   "Campanha de phishing / engenharia social",
        "endpoint":   "Acesso não autorizado a dados da aplicação",
        "subdomain":  "Takeover de domínio / interceptação de tráfego",
    }
    return impact_map.get(target_node.asset_type, "Impacto não determinado")


def _generate_exploitation_steps(entry: IntelNode, target: IntelNode, description: str) -> list[str]:
    return [
        f"1. Acesse o ponto de entrada: `{entry.value}` ({entry.asset_type})",
        f"2. {description}",
        f"3. Use o acesso em `{entry.value}` para alcançar `{target.value}`",
        f"4. Extraia/use: {target.value} ({target.asset_type})",
        "5. Documente o POC com curl/exploit antes de escalar",
    ]
```

---

## 📊 4. Artifact Generator — Saída em Múltiplos Formatos
### 4a. Mermaid Attack Graph
```python
def generate_mermaid_graph(paths: list[AttackPath]) -> str:
    """
    Gera um diagrama Mermaid de fluxo do grafo de ataque priorizado.
    """
    lines = ["```mermaid", "graph TD"]

    severity_styles = {
        Severity.CRITICAL: "fill:#ff2b2b,color:#fff,stroke:#8b0000",
        Severity.HIGH:     "fill:#ff8c00,color:#fff,stroke:#b35c00",
        Severity.MEDIUM:   "fill:#ffd700,color:#000,stroke:#b8960c",
        Severity.LOW:      "fill:#4169e1,color:#fff,stroke:#1e3a8a",
    }

    seen_nodes = {}
    for i, path in enumerate(paths[:10]):  # Top 10 paths
        for j, node in enumerate(path.nodes):
            safe_id = f"N{abs(hash(node.node_id)) % 10000}"
            if safe_id not in seen_nodes:
                label = f"{node.value[:30]}\\n[{node.asset_type}]"
                lines.append(f'    {safe_id}["{label}"]')
                lines.append(f"    style {safe_id} {severity_styles.get(node.severity, '')}")
                seen_nodes[safe_id] = node

        if len(path.nodes) >= 2:
            a_id = f"N{abs(hash(path.nodes[0].node_id)) % 10000}"
            b_id = f"N{abs(hash(path.nodes[1].node_id)) % 10000}"
            edge_label = path.severity.value
            lines.append(f"    {a_id} -->|{edge_label}| {b_id}")

    lines.append("```")
    return "\n".join(lines)
```

### 4b. Executive Markdown Report
```python
from datetime import datetime

def generate_executive_report(
    target:  str,
    paths:   list[AttackPath],
    all_nodes: list[IntelNode],
) -> str:
    """Gera relatório executivo em Markdown para o Artifact final do Antigravity."""
    critical = [p for p in paths if p.severity == Severity.CRITICAL]
    high     = [p for p in paths if p.severity == Severity.HIGH]
    total    = len(all_nodes)

    report = f"""# 🎯 Attack Surface Report — {target}
**Gerado em:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

---

## 📊 Executive Summary
| Métrica | Valor |
|---------|-------|
| Total de Ativos Mapeados | {total} |
| Caminhos de Ataque Críticos | {len(critical)} |
| Caminhos de Alto Risco | {len(high)} |
| CVSS Máximo Estimado | {max((p.cvss_estimate for p in paths), default=0):.1f} |

---

## ☠️ Attack Paths Priorizados

"""
    for i, path in enumerate(paths[:5], 1):
        report += f"""### [{path.severity.value}] Path #{i}: {path.title}
**CVSS Estimado:** `{path.cvss_estimate}`
**Impacto:** {path.impact}

**Passos de Exploração:**
"""
        for step in path.exploitation:
            report += f"{step}\n"
        report += "\n---\n\n"

    return report
```

---

## 🔄 5. Orchestration Entry Point — Chamada de Todas as Skills

```python
import asyncio, json
from pathlib import Path

async def run_full_correlation(workdir: str, target: str) -> None:
    """
    Ponto de entrada que lê todos os outputs das skills e gera o Artifact final.
    """
    wdir = Path(workdir)
    nodes: list[IntelNode] = []

    # Carrega outputs de cada skill (padronizados em JSON)
    loaders = {
        "dns_subs.json":         SkillSource.DNS_MAPPER,
        "ct_new_subs.json":      SkillSource.SUBDOMAIN_RECON,
        "secrets_found.json":    SkillSource.VCS_MINER,
        "api_docs_found.json":   SkillSource.API_FUZZER,
        "default_creds_hits.json": SkillSource.NET_SCANNER,
        "employees_ranked.json": SkillSource.SOCIAL_GRAPHER,
        "breach_hits.json":      SkillSource.SOCIAL_GRAPHER,
    }

    for filename, source in loaders.items():
        path = wdir / filename
        if path.exists():
            raw = json.loads(path.read_text())
            for item in (raw if isinstance(raw, list) else [raw]):
                node = IntelNode(
                    node_id=str(uuid.uuid4()),
                    asset_type=item.get("type", "unknown"),
                    value=item.get("value", str(item)),
                    source_skill=source,
                    tags=item.get("tags", []),
                    metadata=item,
                )
                nodes.append(node)

    correlations = correlate_nodes(nodes)
    paths        = build_attack_paths(correlations, nodes)

    # Gera todos os artifacts
    mermaid_graph     = generate_mermaid_graph(paths)
    executive_report  = generate_executive_report(target, paths, nodes)
    attack_graph_json = [
        {"path_id": p.path_id, "title": p.title,
         "severity": p.severity.value, "cvss": p.cvss_estimate,
         "impact": p.impact, "exploitation": p.exploitation}
        for p in paths
    ]

    (wdir / "attack_graph.json").write_text(json.dumps(attack_graph_json, indent=2))
    (wdir / "attack_report.md").write_text(f"{executive_report}\n\n{mermaid_graph}")

    print(f"✅ Correlação concluída: {len(paths)} attack paths gerados.")
    print(f"✅ Artifacts: attack_graph.json, attack_report.md")
```

---

## 📊 6. Saída e Integração
- **`attack_report.md`**: Relatório executivo em Markdown → Antigravity Artifact + cliente
- **`attack_graph.json`**: Grafo estruturado → `Report Architect` (dashboard HTML)
- **Mermaid Diagram**: Incorporado no relatório para visualização no Antigravity

---

## 🔗 Integração no Ecossistema Global
- **Consome de todas as skills**: DNS Mapper, Subdomain Recon, VCS Miner, API Fuzzer, Net Scanner, Social Grapher, Passive OSINT
- `python-pro`
- `ai-agents-architect`
- `report-architect` (entrega o JSON final para o dashboard)
