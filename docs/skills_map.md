# 🗺️ Project Enum: Skills Navigation & AI Strategy Map

Este documento serve como a bússola estratégica para qualquer IA que interaja com o ecossistema **Enum**. Ele define a hierarquia, o fluxo de inteligência e as diretrizes de tomada de decisão para garantir consistência operacional e eficiência tática.

---

## 🏗️ 1. Arquitetura de Pesquisa (Skill Hierarchy)

A operação é dividida em **Clusters de Especialidade**, coordenados por um ponto único de comando.

### 👑 Nível 0: Orquestração e Governança
*   **`recon-commander.md`**: O cérebro estratégico. Define o roteamento e a ordem das operações. **Nunca** executa comandos diretamente sem ler a skill subordinada.
*   **`shellscript.md` (Bash-Pro)**: A bíblia de execução. Toda e qualquer alteração em arquivos `.sh` deve consultar esta skill para garantir o modo estrito e segurança contra injeção.

### 📡 Nível 1: Captação de Superfície (`threat_intel/` & `network_recon/`)
*   **Trigger**: Início de engajamento ou descoberta de novo asset.
*   **Ação**: Mapeamento passivo (OSINT) e descoberta de infraestrutura (DNS/IP).
*   **Decision Gate**: Sair deste nível apenas quando a lista de `hosts_vivos.txt` estiver consolidada.

### 🧩 Nível 2: Refino de Inteligência (`json_analysis/`)
*   **Trigger**: Recebimento de payloads JSON, Dumps de JS ou Diffs de configuração.
*   **Ação**: Inferência de schema, detecção de drift estrutural e mapeamento de IDOR.
*   **Decision Gate**: Enviar endpoints "shadow" ou parâmetros vulneráveis para o próximo nível.

### ⚔️ Nível 3: Operação Ofensiva (`active_exploitation/` & `bypass-auditor.md`)
*   **Trigger**: Identificação de endpoints sensíveis ou bloqueios de WAF (403/401).
*   **Ação**: Fuzzing avançado, evasão de L7, mimetização de TLS (L4).
*   **Decision Gate**: Garantir sigilo (Stealth) absoluto via `dynamic-behavioral-shaper.md`.

### 📊 Nível 4: Consolidação e Report (`report-architect.md`)
*   **Trigger**: Finalização de qualquer ciclo de scan.
*   **Ação**: Agregação de dados via `reporter.py` e atualização do Dashboard Dashboard.

---

## 🚦 Algoritmo de Decisão para a IA

Sempre que uma nova tarefa for solicitada, siga este fluxo:

1.  **Fase de Identificação**:
    *   A tarefa envolve lógica de execução? ➔ Consulte `recon-commander.md`.
    *   A tarefa envolve alteração de código bash? ➔ Consulte `shellscript.md`.
2.  **Fase de Escopo (Token Saving)**:
    *   **NUNCA** carregue todas as skills de uma subpasta. Leia o `README.md` ou `MAPA` da pasta e use `view_file` apenas na skill necessária.
3.  **Fase de Execução**:
    *   Priorize scripts Python (`engine/scripts/`) para processamento pesado de dados.
    *   Use Shell (`modules/`) apenas para orquestrar ferramentas externas.
4.  **Fase de Validação**:
    *   Toda saída de ferramenta deve ser convertida para um formato legível pelo `reporter.py` (preferencialmente JSON).

---

## 🛡️ Regras de Ouro (OPSEC & Estabilidade)

1.  **Stealth First**: Toda requisição ativa **deve** passar pelos filtros de `User-Agent` randômico e Poisson Jitter.
2.  **Fail-Fast**:Scripts Bash devem falhar imediatamente ao encontrar erros não tratados (`set -e`).
3.  **Data Integrity**: Nunca sobrescreva resultados de fases anteriores sem backups/checkpoints (`anew` é a ferramenta de escolha).
4.  **Code Quality**: Nenhum script .sh sai de auditoria com avisos do `shellcheck`.

---

## 🔄 Ciclo de Atualização do Mapa
Este mapa deve ser atualizado sempre que uma nova **Core Skill** for adicionada ao diretório `.agents/`.
