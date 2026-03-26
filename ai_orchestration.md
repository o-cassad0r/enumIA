# Arquitetura de Inteligência e Automação (AI/State Machine)

Para que a ferramenta tome decisões dinâmicas, não podemos depender de um script Bash linear que roda as ferramentas e salva logs cegamente. O Bash não possui estruturas nativas de "raciocínio" para interatividade complexa.

A transição para um modelo **inteligente** exige um **Orquestrador em Python** em que cada ferramenta se torna uma "Função" (Node). O resultado de uma ferramenta dita obrigatoriamente qual será o próximo passo. Conforme sugerido nas skills que você tem de MLOps e LangGraph (ou PydanticAI), há 3 abordagens práticas para implementar isso:

---

## 1. Pipeline Heurístico Baseado em Regras (Rápido e Previsível)

Esta abordagem não utiliza IA generativa (LLMs) durante o scan, mas implementa uma **Máquina de Estados (State Machine)** rígida no Python. É essencial para não queimar tokens da API desnecessariamente durante o *brute force*.

### Como Funciona:
1. **O Gatilho:** O Python chama as ferramentas do ProjectDiscovery via `subprocess`.
2. **Parsing Nativo:** O Python lê a saída JSON/TXT logo após a ferramenta encerrar.
3. **Árvore de Decisão Lógica:**
   - `if subdomains_found == 0:` ➔ Ativa a tool `run_alterx_permutations()`.
   - `if naabu_ports == []:` ➔ Ativa a tool `run_bypass_cloudflare()`.
   - `if port in [8080, 8443]:` ➔ Ativa `httpx -p 8080` ➔ Se retornar "Tomcat", chama a tag específica no Nuclei: `nuclei -tags tomcat`.
4. **Retroalimentação Automática:** Se o *FFuf* retornar *Rate Limit* (429), a engine captura esse state e retoma com Jitter e *User-Agents* aleatorizados (aplicando as regras da sua skill `red-team-tools`).

**Vantagem:** Rodando em Python, é ultrarrápido, local, gratuito e não gera alucinações (falsos positivos).

---

## 2. Orquestrador LLM com Agentic Tool Use (Autônomo Avançado)

Aqui, transformamos a sua ferramenta em um Agente Autônomo Híbrido, usando o SDK da Anthropic ou OpenAI (via `PydanticAI` ou `LangGraph`). O LLM decide ativamente qual comando executar.

### O Papel do LLM:
As rotinas pesadas (Fuzzing, mass scanning) continuam em bash/Python bruto. Nós apenas ativamos o LLM nas bifurcações táticas (decisões abstratas).

**1. Raciocínio de Bypass (O que fazer quando trava?):**
Quando o Python percebe 0 respostas válidas, ele empacota os headers e o fingerprint WAF em um request para o LLM:
> *"Fuzzer reportou 0 diretórios. Headers retornados sugerem bloqueio Akamai. Qual flag/ferramenta devo usar agora?"*
O Agente responde consumindo uma `Tool`: `ativar_bypass(tecnica="X-Forwarded-For")`

**2. Código de Exemplo (PydanticAI):**
Você define suas ferramentas bash como abstrações para a IA:

```python
from pydantic_ai import Agent

pentester = Agent('claude-3-5-sonnet', system_prompt="Você é um Hacker Red Team. Suas ferramentas rodam scans reais.")

@pentester.tool_plain
def scan_ports(domain: str) -> str:
    # Executa o naabu via subprocess
    return "Porta 8080 aberta."

@pentester.tool_plain
def identify_service(domain: str, port: int) -> str:
    # Executa httpx e nuclei
    return "Apache Tomcat V9 identificado."
```

O próprio Claude irá olhar a porta 8080, decidir que precisa identificar o serviço e forçar a execução da tool `identify_service`.

---

## 3. Análise Final & Exploração (Catalogar e Sugerir)

Você pediu: *"Caso encontre vulnerabilidades, catalogue e sugira as melhores formas de exploração."*

Para isso, a abordagem ideal **RAG (Retrieval-Augmented Generation)** seria acoplada ao final do seu Dashboard ([reporter.py](file:///e:/NIS%20Ti/Dev/Antigravity/Recon/enum/reporter.py) atual).

1. O [reporter.py](file:///e:/NIS%20Ti/Dev/Antigravity/Recon/enum/reporter.py) agrega todos os CVEs, logs do Nuclei, stack detectada (Nginx, CMS, etc).
2. Ele submete um prompt consolidado para a IA em background:
   > *"As seguintes vulnerabilidades críticas foram detectadas pelo Nuclei: [lista de CVEs]. A stack do servidor é [Tech Stack]. Atue como um analista GRC/Red Team. Gere uma anotação executiva classificando por impacto, e crie as metodologias Proof-Of-Concept (POC) de como explorar manualmente em curl/python cada uma, detalhando os steps do exploit."*
3. O LLM gera um relatório focado.
4. O [reporter.py](file:///e:/NIS%20Ti/Dev/Antigravity/Recon/enum/reporter.py) grava isso nativamente no seu [template.html](file:///e:/NIS%20Ti/Dev/Antigravity/Recon/enum/template.html) numa nova aba: **"AI Exploitation Notes"**.

---

### Por onde começar?
**A união da Estratégia 1 e 3 é o cenário ideal no curto prazo.** 
1. Migre as rotinas do [fuzzdirectory.sh](file:///e:/NIS%20Ti/Dev/Antigravity/Recon/enum/fuzzdirectory.sh) para um esqueleto **Python** (`orchestrator.py`) com blocos condicionais (`if/else`) capturando o que deu errado (Nmap fechado = tenta bypass, tech X = scan específico).
2. Ao final, pegue o dict compilado e injete em um bot LLM (como na *Estratégia 3*) para escrever os notes e as POCs no Dashboard.

Gostaria de criar a estrutura básica do `orchestrator.py` com a máquina de estados em Python para você testar?
