# 🧠 Estratégia da Fase 2: Inteligência Cognitiva

Esta fase eleva o projeto **Enum** de um executor de ferramentas estático para um mecanismo de aprendizado contínuo e adaptação de ataques. O foco muda de "atacar tudo" para "atacar exatamente onde dói".

---

## 🎯 Objetivo Principal

Criar um **Feedback Loop Dinâmico** onde a descoberta de estrutura de dados (`json_analysis`) instrui e engatilha automaticamente testes de vulnerabilidade cirúrgicos (`nuclei`), limitando o ruído e maximizando o impacto (BOLA/IDOR, Integer Overflow). Além disso, garantir que o arsenal (wordlists) esteja sempre atualizado sem intervenção manual.

---

## 🏗️ Pilares de Implementação

### 1. O Forjador Dinâmico (Dynamic Nuclei Forge)
A ponte crítica entre o que a skill `schema-drift-analyzer` vê e o que o `nuclei` ataca.

*   **Componente**: `engine/scripts/nuclei_dynamic_forge.py`
*   **Funcionamento**:
    1. O orquestrador detecta alterações via `drift_delta.json` gerado na inspeção de API/JSON.
    2. O *Forge* em Python lê este arquivo na memória.
    3. Se encontrar:
        *   **Novos UUIDs ou `*_id`**: Gera um template Nuclei focado em *BOLA/IDOR* tentando acessar `/api/v1/user/{ID+1}`.
        *   **Novos campos inteiros (`limit`, `count`)**: Gera um template focado em *Integer Overflow / Rate Limit Bypass* mandando valores absurdos ou negativos (ex: `-1`, `99999999`).
        *   **Novas rotas descritas no JSON**: Transforma as rotas em *paths* para o `ffuf`.
    4. O template `.yaml` gerado em tempo de execução é salvo em `/tmp/dynamic_vuln_scans/`.
    5. O orquestrador aciona o `nuclei` rodando **apenas** estes templates gerados cirurgicamente contra os hosts afetados.

### 2. Arsenal Auto-Atualizável (Continuous Wordlist Sync)
Um red team vive do frescor de suas listas. Se não há atualizações, os novos caminhos ficam invisíveis.

*   **Componente**: `core/update_wordlists.sh`
*   **Funcionamento**:
    1. Script otimizado rodando idealmente via requisição de flag manual (ex: `./fuzzdirectory.sh --update-arsenal`) ou como Cronjob pelo usuário.
    2. Baixa listas dinâmicas recém-geradas:
        *   **Assetnote**: Busca os "Best of", "API endpoints", e listas de tecnologias específicas detectadas (GraphQL, Swagger).
        *   **SecLists / Custom Gists**: Sincroniza listas via `git pull` rápido e silencioso.
    3. Usa a ferramenta `anew` para adicionar apenas caminhos novos (deltas) ao seu `wordlist_final.txt` e `wordlist_sdm.txt`, evitando inchar ou corromper as listas principais.

### 3. Integração no Pipeline (Control Plane Update)
O `core/enum.sh` precisa se tornar o regente dessa orquestra.

*   **Ação**: Adicionar a "Fase 5.5" (Cognitive Exploit).
*   **Fluxo Modificado**:
    1. Fuzzing & Recon.
    2. Despejo de JSON e Intel gerado por JS/Apis.
    3. O *Forge* (`nuclei_dynamic_forge.py`) escaneia os JSONs na pasta `json_analysis`.
    4. Se templates forem gerados, acionar `nuclei -t /tmp/dynamic_vuln_scans/ -l hosts_vivos.txt`.

---

## 🚦 Regras de Engajamento e OPSEC

Para que este salto na agressividade não custe o Stealth do nosso projeto (Regra base do Nível 3 no Skills Map):

1.  **Limite de Retentativas Seguras**: Ao forjar testes IDOR, o script criará apenas 3 variações do objeto mutado (ex. uuid puro, uuid-1, uuid zeroing). Não faremos brute-force numérico imenso.
2.  **Wordlist Diet**: O script `update_wordlists.sh` passará por regras de sanitização, excluindo strings extremamente ruidosas ou que acionam assinaturas de WAF de nível 7 sem necessidade.
3.  **Arquitetura Otimizada**: Todo esse processo será isolado; se a forge falhar ou não achar json interessante, o scanner básico continua normalmente sem quebrar a execução geral.

---

## 🛠️ Plano de Ação a Ser Executado

1. `engine/scripts/nuclei_dynamic_forge.py` (Criação do gerador).
2. `core/update_wordlists.sh` (Script de atualização auto-gerenciada).
3. Modificação em `core/enum.sh` para acionar a forja e ligar a nova engrenagem visual no Relatório se houver resultados dinâmicos.
