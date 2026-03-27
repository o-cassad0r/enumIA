# 🔄 Project Enum: Execution Routine Map

Este mapa descreve o ciclo de vida de uma execução completa do **Enum**. Use este guia para identificar onde inserir novas funções ou como depurar o fluxo de dados.

---

## 🚀 1. Inicialização (Bootstrap)
*Ponto de entrada único para garantir integridade.*
1.  **Entry Point**: `fuzzdirectory.sh` chama `core/enum.sh`.
2.  **Strict Check**: `core/utils.sh` é carregado (Modo Estrito ativado).
3.  **Dependency Check**: Validação de binários necessários (`check_dependencies`).
4.  **Workspace Setup**: Criação da estrutura de pastas em `data/results/<domain>/`.

---

## 🔍 2. Fase de Descoberta (Discovery Phase)
*Objetivo: Alargar a superfície sem ruído excessivo.*
1.  **Passive Recon**: `modules/subdomain_enum/discover.sh` (Subfinder, Assetfinder, Amass).
2.  **DNS Resolution**: Consolidação via `dnsx` e `anew`.
3.  **Probing**: Filtro de hosts vivos via `httpx`.
4.  **Decision Gate**: Se `hosts_vivos.txt` estiver vazio, o pipeline encerra com aviso.

---

## 🧠 3. Fase de Inteligência (Intelligence Phase)
*Objetivo: Extração de metadados e ativos paralelos.*
1.  **OSINT & ASN**: `modules/infra/intel.sh` mapeia blocos de IP e ASN.
2.  **Cloud Scan**: Busca por buckets S3/Azure/GCP.
3.  **JS Analytics**: Extração de segredos e links de arquivos JavaScript.
4.  **Takeover Check**: Verificação de subdomínios órfãos (CNAME).

---

## ⚔️ 4. Fase Ofensiva (Offensive Phase)
*Objetivo: Fuzzing e busca por vulnerabilidades conhecidas.*
1.  **Port Scan**: Naabu/Nmap mapeiam serviços abertos.
2.  **Directory Fuzzing**: `modules/fuzzing/ffuf.sh` (Respeitando OPSEC/ Poisson Distribution).
3.  **Vulnerability Scan**: `modules/vulnerability/nuclei.sh` (Template matching).
4.  **Bypass Testing**: Tentativas automáticas de 403 Forbidden bypass.

---

## 📊 5. Fase de Conclusão (Reporting Phase)
*Objetivo: Transformar dados brutos em inteligência visual.*
1.  **Data Ingestion**: `engine/reporter.py` varre o `WORKDIR` em busca de JSON/TXT.
2.  **Schema Analysis**: Detecção de Drift estrutural e IDOR.
3.  **Render**: `template.html` é preenchido e salvo como `report.html`.
4.  **Cleanup**: `trap cleanup` remove arquivos temporários em `/tmp`.

---

## 🛠 Onde Inserir Novas Funções?
*   **Novas Ferramentas de Recon**: Adicione ao `discover.sh`.
*   **Novos Payloads de Exploração**: Adicione ao `nuclei.sh` ou crie um novo script em `modules/active_exploitation/`.
*   **Nova Lógica de Análise**: Crie um script Python em `engine/scripts/` e chame via `reporter.py`.
