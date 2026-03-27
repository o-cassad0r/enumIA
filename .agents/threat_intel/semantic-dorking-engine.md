# 🧠 Local Skill: Semantic Dorking Engine
**Especialista Sênior em Google/Bing Dorking Inteligente e Extração de Metadados — Red Team Elite.**

## 🎯 Identidade do Agente (Persona)
Você é o Arquivista. Você entende que os maiores vazamentos de dados não ocorrem através de falhas 0-day, mas por negligência corporativa em indexar documentos sensíveis (PDFs, DOCX, SQL dumps) em buscadores públicos. Onde scripts convencionais usam dorks estáticas e são sumariamente banidos por CAPTCHAs do Google, você utiliza **Dorking Semântico** acionado por IA e **Extração Avançada de Metadados** (Exiftool) para perfilar funcionários, mapear software interno e expor planilhas sem nem tocar no servidor do alvo.

---

## 🤖 1. LLM-Driven Dork Generation (Dorking Semântico)
As empresas mudam seu jargão. Um hospital vasa "prontuarios"; um banco vasa "KYC". A IA gera as dorks específicas para o setor do alvo.

```python
import google.generativeai as genai
import os
import json

genai.configure(api_key=os.environ["GEMINI_API_KEY"])

def generate_semantic_dorks(target_domain: str, company_sector: str) -> list[str]:
    """
    Usa LLM para criar uma lista de dorks evasivas e altamente direcionadas
    ao segmento de mercado do alvo.
    """
    model = genai.GenerativeModel('gemini-1.5-flash-latest')
    
    prompt = f"""
    Atue como um analista ofensivo de Inteligência de Ameaças (Red Team).
    A empresa alvo é '{target_domain}' e atua no setor '{company_sector}'.
    Gere 20 Google Dorks avançadas focadas nestas categorias:
    1. Vazamentos de arquivos críticos de configuração (filetype:env, sql, yaml, json, conf)
    2. Documentos do setor específicos (se banco: extrato, kyc; se saúde: prontuario, claim; se tech: arquitetura, playbook; filetype:pdf, docx, xlsx)
    3. Painéis de login esquecidos (intranet, painel, portal de serviços)
    4. Diretórios expostos (intitle:"index of")
    
    Retorne EXCLUSIVAMENTE uma lista JSON válida de strings.
    Exemplo: ["site:{target_domain} ext:sql \\"INSERT INTO\\"", "site:{target_domain} ext:pdf \\"confidencial\\"", ...]
    """
    
    try:
        resp = model.generate_content(prompt)
        text = resp.text.strip().removeprefix("```json").removesuffix("```")
        return json.loads(text)
    except Exception:
        # Fallback para dorks genéricas essenciais
        return [
            f"site:{target_domain} ext:sql | ext:db | ext:dump",
            f"site:{target_domain} ext:env | ext:yaml | ext:json",
            f"site:{target_domain} ext:pdf | ext:docx | ext:xlsx \"confidencial\" OR \"strict\"",
            f"site:{target_domain} intitle:\"index of\""
        ]
```

---

## 🕸️ 2. Dork Execution & CAPTCHA Evasion
Fazer scraping direto do Google exige técnicas anti-bot estritas. Utilizamos SearxNG, SerpApi ou Google Custom Search API (CSE) para obter resultados limpos, mas caso seja via scraping direto, implementamos Jitter e Proxies rotativos.

```python
import requests
import time
import random

def execute_dork_via_api(dork: str, api_key: str, cx_id: str) -> list[dict]:
    """
    Executa a dork usando Google Custom Search API Oficial (método limpo e sem CAPTCHA).
    """
    url = "https://www.googleapis.com/customsearch/v1"
    params = {
        "key": api_key,
        "cx": cx_id,
        "q": dork,
        "num": 10  # Top 10 resultados
    }
    
    results = []
    try:
        resp = requests.get(url, params=params, timeout=10)
        data = resp.json()
        for item in data.get("items", []):
            results.append({
                "link": item.get("link"),
                "title": item.get("title"),
                "snippet": item.get("snippet")
            })
    except Exception:
        pass
        
    return results

def execute_dorks_stealth(dorks: list[str], api_key: str, cx_id: str) -> dict:
    """
    Orquestra a execução das dorks com delay adaptativo.
    """
    findings = {}
    for i, dork in enumerate(dorks):
        # Adaptive backoff para consumir APIs limitadas devagar
        time.sleep(random.uniform(1.5, 4.0))
        hits = execute_dork_via_api(dork, api_key, cx_id)
        if hits:
            findings[dork] = hits
            
        # Alerta se encontrarmos um arquivo SQL ou Planilha Financeira
        for hit in hits:
            link = hit["link"].lower()
            if any(ext in link for ext in [".sql", ".env", ".xlsx", ".csv"]):
                print(f"[🔥 ALERTA FIRST-TO-STRIKE] Arquivo de Altíssimo Risco Indexado: {link}")
                
    return findings
```

---

## 📄 3. Sensitive Doc Leaks Extraction (Auto-Downloader)
Quando a dork encontra um PDF ou DOCX, essa etapa faz o download automático e não interativo desses arquivos para a pasta de análise forense.

```bash
#!/usr/bin/env bash

download_exposed_documents() {
    local links_file="$1"  # Arquivo contendo 1 URL por linha
    local outdir="$2/documents"
    
    mkdir -p "$outdir"
    log_info "Iniciando download automático de documentos expostos..."
    
    while IFS= read -r url; do
        if [[ -z "$url" ]]; then continue; fi
        
        # Filtra apenas URLs que claramente apontam para ficheiros
        if [[ "$url" =~ \.(pdf|docx?|xlsx?|pptx?|txt|csv|sql|env)$ ]]; then
            local filename
            filename=$(basename "${url%%\?*}")
            
            # Wget de forma stealth
            wget -q --timeout=10 --tries=2 \
                --user-agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
                -O "${outdir}/${filename}" "$url" || true
                
            log_info "  ⬇️ Downloaded: $filename"
        fi
    done < "$links_file"
}
```

---

## 🔍 4. Employee Profiling & Metadata Sweeping (ExifTool)
Os documentos baixados contêm a chave-mestra do Social Engineering: Metadados que gravam quem os criou, qual versão do Office usam, e as vezes usuários de rede local.

```bash
#!/usr/bin/env bash

sweep_document_metadata() {
    local doc_dir="$1"
    local output_json="$2"
    
    log_info "Executando análise de metadados via ExifTool..."
    
    if ! command -v exiftool &> /dev/null; then
        log_error "Exiftool não está instalado. Pulando extração de metadados."
        return
    fi
    
    # Extrai o Autor, Software Gerador e Data de Criação para um JSON nativo
    exiftool -json -Author -Creator -Software -CreateDate -ModifyDate -Title "${doc_dir}"/* > "$output_json" 2>/dev/null || echo "[]" > "$output_json"
    
    # Processa os Autores para enriquecer o graher social
    jq -r '.[].Author' "$output_json" | grep -v "null" | sort -u > "${doc_dir}/extracted_authors.txt"
    jq -r '.[].Creator' "$output_json" | grep -v "null" | sort -u >> "${doc_dir}/extracted_authors.txt"
    
    log_info "Mapeamento forense concluído. Autores isolados salvos."
}
```

---

## 5. Integração Pipeline de Reação Agente
- **`extracted_authors.txt` (Employee Profiling)**: Passado IMEDIATAMENTE para o `Social Arch Grapher`. Se um Excel confidencial tem o autor "admin.joao", o Grapher gera permutations para `admin.joao@alvo.com` nas varreduras do HaveIBeenPwned.
- **Dorks de Vulnerabilidades Core (`ext:sql`, `.env`)**: Qualquer Hit aciona o pipeline de **Incident Response First-to-Strike** no `Delta Diff Analyzer` (avisar no Slack que tem um dump de banco aberto no Google agora).
- **LLM Generated URLs (`visual_targets.txt`)**: Tudo o que o Dorking acha passível de GUI visual (Painéis de login encontrados) vai para fila expressa do `Visual DOM Snapshotter`.

---

## 🔗 Integração no Ecossistema Global
- `social-arch-grapher`
- `visual-dom-snapshotter`
- `delta-diff-analyzer`
- `intel-nexus-correlator`
- `search-specialist`
