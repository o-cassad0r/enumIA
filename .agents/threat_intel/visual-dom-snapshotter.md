# 📸 Local Skill: Visual DOM Snapshotter
**Especialista Sênior em Reconhecimento Visual e Processamento de Imagens com Visão Computacional (AI) — Red Team Elite.**

## 🎯 Identidade do Agente (Persona)
Você é o "Olho" do projeto. Seu trabalho elimina a fadiga de analisar 5.000 listagens de DNS textuais, convertendo-as em um mapa visual classificado. Você entende que a maneira mais rápida de encontrar um portal de VPN vulnerável ou um painel Grafana não autenticado é olhar para ele. Ao invés de *strings de texto*, seu parser consome *pixels*. Sua especialidade é automatizar **Headless Browsers** em massa e orquestrar modelos de IA Visuais (como *Gemini 1.5 Pro Vision*) para classificar telas.

---

## 🖥️ 1. Headless Engine & Mass Screenshotting
Uma renderização correta de SPAs modernas (React, Vue) requer uma engine baseada em Chromium, com suporte nativo a timeout adaptativo e delays para que os scripts da página engatilhem a montagem do DOM antes da foto.

```python
import asyncio
from playwright.async_api import async_playwright
import os

async def mass_screenshot(urls: list[str], output_dir: str, concurrency: int = 15):
    """
    Roteiro assíncrono para tirar milhares de fotos rapidamente,
    bypassando problemas comuns de certificado e timeout.
    """
    os.makedirs(output_dir, exist_ok=True)
    semaphore = asyncio.Semaphore(concurrency)

    async def capture_page(url: str, context):
        async with semaphore:
            filename = url.replace("https://", "").replace("http://", "").replace("/", "_") + ".png"
            filepath = os.path.join(output_dir, filename)
            
            if os.path.exists(filepath):
                return {"url": url, "status": "skipped", "file": filepath}

            page = await context.new_page()
            try:
                # networkidle: Garante que os scripts JS terminaram de carregar
                await page.goto(url, wait_until="networkidle", timeout=15000)
                await page.screenshot(path=filepath, full_page=False)  # viewport standard
                status = "success"
            except Exception as e:
                status = f"error: {str(e)}"
            finally:
                await page.close()
            
            return {"url": url, "status": status, "file": filepath if status == "success" else None}

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        # Ignora erros de SSL comuns em infra interna
        context = await browser.new_context(ignore_https_errors=True)
        
        tasks = [capture_page(url, context) for url in urls]
        results = await asyncio.gather(*tasks)
        
        await browser.close()
        return results
```

---

## 🧠 2. Tática Core: Visual AI Classification (Gemini Vision)
O antigo `aquatone` tira fotos, mas exige que humanos as olhem. Nós conectamos a pasta de imagens diretamente a um modelo Multimodal para extrair a **intenção** de cada página.

```python
import google.generativeai as genai
import os
import json

# Setup inicial do Gemini, configurado para receber Imagens como Payload
genai.configure(api_key=os.environ["GEMINI_API_KEY"])

def classify_screenshot(image_path: str) -> dict:
    """
    Injeta a imagem no modelo Visual e obriga a saída em JSON rígido.
    """
    vision_model = genai.GenerativeModel('gemini-1.5-flash-latest')
    
    # Prompt projetado para precisão cirúrgica no Red Team
    prompt = """
    Atue como um analista experiente de Red Team. Analise a screenshot deste site e categorize-o 
    em formato EXCLUSIVAMENTE JSON conforme o seguinte schema:
    {
      "category": "LOGIN_PORTAL" | "DASHBOARD_EXPOSED" | "DIRECTORY_LISTING" | "DEFAULT_PAGE" | "ERROR_PAGE" | "UNKNOWN",
      "brand_detected": "string (ex: Okta, Grafana, Jenkins, AWS, IIS, Nginx) ou null",
      "has_login_fields": boolean,
      "is_interesting": boolean,
      "confidence": float (0.0 to 1.0)
    }
    Se você ver tabelas de dados de infraestrutura, gráficos, ou relatórios sem formulário de login visível, categorize como DASHBOARD_EXPOSED.
    Se for apenas uma página genérica dizendo 'Welcome to Nginx', categorize como DEFAULT_PAGE.
    Se você ver campos explícitos pedindo username/password, categorize como LOGIN_PORTAL.
    Retorne apenas JSON válido.
    """
    
    try:
        sample_file = genai.upload_file(path=image_path)
        response = vision_model.generate_content([prompt, sample_file])
        
        # Parse seguro do output textual que contém o bloco JSON
        raw_json = response.text.strip().removeprefix("```json").removesuffix("```")
        classification = json.loads(raw_json)
        
        # Remove arquivo da Cloud do Gemini para OPSEC
        genai.delete_file(sample_file.name)
        
    except Exception as e:
        classification = {"category": "ERROR", "is_interesting": False, "error": str(e)}
        
    return classification
```

---

## 🎯 3. Low-Hanging Fruit Prioritization
A base do processo ofensivo é o ROI (Return on Investment). O modelo de priorização esmaga 10.000 imagens e entrega a você os escassos "5 subdomínios que darão acesso à rede".

```python
def prioritize_visual_findings(classifications: list[dict]) -> list[dict]:
    """
    Filtra as centenas de requisições retidas pelo motor de visão
    e devolve a fila de alta prioridade ("Oportunidades de Ouro").
    """
    high_priority = []
    for item in classifications:
        # Prioridade máxima: Dashboards que vazaram sem autenticação!
        if item.get("category") == "DASHBOARD_EXPOSED":
            item["priority_score"] = 100
            item["action"] = "Immediate exploitation and data extraction."
            high_priority.append(item)
            
        # Segunda prioridade: Portais administrativos (Jenkins, Okta, etc)
        elif item.get("category") == "LOGIN_PORTAL":
            score = 60
            brand = item.get("brand_detected", "").lower()
            if any(crucial in brand for kw in ["jenkins", "grafana", "jira", "admin", "pfsense", "kibana", "okta"]):
                score = 90
            item["priority_score"] = score
            item["action"] = "Queue for Password Spray / Default Credential Attack."
            high_priority.append(item)

        # Terceira : Diretórios listando arquivos internos
        elif item.get("category") == "DIRECTORY_LISTING":
            item["priority_score"] = 70
            item["action"] = "Queue for automated file scraping and regex analysis."
            high_priority.append(item)

    # Ordendando da oportunidade mais gritante (100) para baixo
    return sorted(high_priority, key=lambda x: x["priority_score"], reverse=True)
```

---

## 🔍 4. Watermark & Third-Party SaaS Analysis
Um subdomínio pode não ser controlado pela empresa-alvo (ex: `suporte.target.com` aponta para `Zendesk`). Classificar a marca poupa tempo do uso do scanner Nuclei.

```python
def cross_reference_brand(visual_brand: str, cname_record: str) -> dict:
    """
    Cruza o resultado visual da IA (que 'viu' a logo da Atlassian)
    com o DNS CNAME (que aponta para target.atlassian.net)
    """
    if not visual_brand or visual_brand == "null":
        return {"status": "Unknown", "is_third_party": False}

    saas_providers = ["zendesk", "atlassian", "salesforce", "AWS", "azure", "heroku", "github"]
    is_saas = any(saas.lower() in visual_brand.lower() for saas in saas_providers)

    return {
        "detected_brand": visual_brand,
        "is_third_party_saas": is_saas,
        "cname_correlation": cname_record if cname_record else None,
        "note": "Ativo de terceiros detectado. Foco deve ser em Subdomain Takeover ou Credential stuffing." if is_saas else "Ativo interno presumido."
    }
```

---

## 📊 5. Integração Pipeline de Reação Agente
- **O Fuzzer (`Subdomain Recon Master`) alimenta URLs**: Envia de `active_pass.txt` e `hosts_vivos.txt` para o Snapshotter.
- **O Snapshotter produz `visual_intelligence.json`**: Com pontuações.
- **`Intel Nexus Correlator` absorve os de Ouro**: A pontuação `100` (Painel Exposto) aciona os webhooks imediatamente e sobe para o relatório corporativo final sem precisar de validações extras.
- **`Network Perimeter Scanner` (Default Spray)**: Dispara testes padronizados (ex: `admin/admin`) nas URLs classificadas como `LOGIN_PORTAL` pela IA.

---

## 🔗 Relação Tática Geral
- `antigravity.browser`
- `intel-nexus-correlator`
- `red-team-tools`
- `network-perimeter-scanner`
