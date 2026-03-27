# 🧠 Plano de Implementação: Fase 2 (Inteligência Cognitiva)

Seguindo as diretrizes do **`AGENTE.md`**, este plano detalha as novas engrenagens lógicas para transformar observações em ataques adaptativos.

---

## 🛠 Novas Implementações (Código)

### 1. Motor de Forja: `engine/scripts/nuclei_dynamic_forge.py` [Novo]
*   **Função**: O "cérebro" que converte deltas de JSON (BOLA, IDOR, Int Overflows) em templates YAML do Nuclei.
*   **Local**: `engine/scripts/`.

### 2. Sincronizador de Arsenal: `core/update_wordlists.sh` [Novo]
*   **Função**: Script em Bash-Pro para baixar deltas das wordlists do Kali/Assetnote sem inflar os arquivos originais.
*   **Local**: `core/`.

---

## 🎭 Expansão de Habilidades (Skills & Workflows)

### 1. Nova Skill: `json_analysis/dynamic-exploit-forge.md` [Novo]
*   **Identidade**: Especialista em traduzir estruturas de dados em vetores de ataque Nuclei.
*   **Regras**: Define limites de mutação e sanitização de payloads.

### 2. Novo Workflow: `/forge` [Novo]
*   **Ação**: Comando rápido para processar dados de inteligência já coletados e fabricar exploits sob demanda.

### 3. Ajuste: `recon-commander.md` [Modificar]
*   Integrar a etapa de **Cognitive Feedback Loop** na orquestração mestre.

---

## 🗑 Limpeza e Otimização
*   **`intel-nexus-correlator.md`**: Proponho **EXCLUIR**. Ele é redundante agora que temos as skills granulares dentro de `json_analysis/` e consome muitos tokens desnecessários (~14KB).

---

## 📅 Roadmap de Execução (Lote 2)
1.  Criar `engine/scripts/nuclei_dynamic_forge.py`.
2.  Criar `core/update_wordlists.sh`.
3.  Implementar Skill `dynamic-exploit-forge.md` e Workflow `/forge`.
4.  Atualizar orquestrador central `core/enum.sh`.
5.  Sincronizar Mapas (`skills`, `sync`, `routine`).

**Deseja que eu execute este plano agora?**
