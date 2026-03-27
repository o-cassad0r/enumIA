# 🧠 Plano de Implementação: Fase 3 (Cérebro Agêntico Local)

Este plano detalha a integração de um **LLM de Código Aberto (via Ollama)** para atuar como o estrategista em tempo real do **Enum**.

---

## 🏗️ Arquitetura do "Cérebro"

### 1. Motor de Decisão: `engine/scripts/agent_brain.py` [Novo]
*   **Função**: Um script Python que consome a API local do **Ollama**.
*   **Ação**: Ele lê o `routine_map.md` e os resultados atuais (`data/results/`) para decidir se deve:
    -   Aprofundar o scan em uma porta específica.
    -   Mudar a wordlist para uma tecnologia detectada.
    -   Finalizar e gerar o relatório.

### 2. Otimizador de Estratégia: `engine/scripts/strategy_optimizer.py` [Novo]
*   **Função**: Analisa os logs de sucessos/falhas globais para sugerir ajustes de threads, rate-limits ou wordlists para o próximo alvo.

---

## 🎭 Expansão de Habilidades

### 1. Nova Skill: `active_exploitation/agentic-orchestrator.md` [Novo]
*   **Identidade**: O Guardião do Cérebro Local.
*   **Regras**: Define como a IA local deve ser consultada e quais são os limites de autonomia (ex: nunca executar exploits destrutivos sem aprovação).

### 2. Novo Workflow: `/brain` [Novo]
*   **Ação**: Abre um canal de chat direto com o LLM local dentro do contexto do projeto para "perguntar sobre o alvo".

---

## 🛠 Integração de Infraestrutura (Kali Linux)

### Atualização `setup.sh`:
*   Adicionar verificação e instalador do **Ollama**.
*   Sugestão de Modelos: `deepseek-coder-v2:16b` (Pesado) ou `llama3:8b` (Leve).

---

## 🔄 Fluxo Agêntico no Orquestrador (`core/enum.sh`)
*   No início de cada fase, o `core/enum.sh` consulta o `agent_brain.py`.
*   O cérebro responde com flags de otimização (ex: `--stealth`).

---

**Deseja que eu proceda com a instalação do ambiente Ollama e desenvolvimento desta camada de inteligência local?**
