# 🤖 enumIA: Recon Control Center (AGENTE.md)

Este arquivo é a bússola autoral para qualquer inteligência operando neste ecossistema.

## 🛠 Comandos de Missão
*   **Preparação**: `./setup.sh`
*   **Engajamento**: `./fuzzdirectory.sh <domain>` (or `bash core/enum.sh <domain>`)
*   **Inteligência**: Relatórios consolidados em `data/results/<domain>/report.html`

## 🗺 Mapas de Batalha
Priorize a precisão tática e economia de recursos seguindo estes guias:
1.  **Skills Map**: `docs/skills_map.md` (Catálogo de Especialidade Red Team).
2.  **Sync Map**: `docs/sync_map.md` (Hierarquia de Dependências de Código).
3.  **Routine Map**: `docs/routine_map.md` (Fluxo de Execução e Ciclo de Vida).

## ⚡ Atalhos de Missão (Workflows)
Use estes comandos rápidos para disparar sequências táticas:
*   **/engage**: Inicia um novo Recon completo em um domínio.
*   **/bypass-waf**: Ativa protocolos de evasão para alvos bloqueados (403).
*   **/report**: Consolida achados e gera o Dashboard final.
*   **/migration**: Executa refatoração atômica e modularização.



## 🛡 Protocolos Operacionais
1.  **Doutrina Bash**: Todo script deve herdar `core/utils.sh` e operar em modo estrito.
2.  **Sigilo (OPSEC)**: Use as skills de `active_exploitation/` para mimetismo e evasão.
3.  **Eficiência Cognitiva**: Use `view_file` cirurgicamente. Evite ler diretórios inteiros.
4.  **Consolidação**: Toda nova coleta deve ser integrada ao `engine/reporter.py`.

## 📂 Arquitetura do Sistema
*   `core/`: Orquestração e Lógica Central.
*   `modules/`: Unidades táticas de execução (SRP).
*   `engine/`: Motor de processamento de inteligência.
*   `templates/`: Camada de visualização de resultados.
*   `.agents/`: Skills de especialistas Red Team.
