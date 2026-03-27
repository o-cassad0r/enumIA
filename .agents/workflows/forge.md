---
description: Aciona a Inteligência Cognitiva para forjar e testar exploits baseados em dados coletados.
---
1. Analise o diretório de dados do alvo em busca de `json_intelligence/`.
2. Se houver dados novos, invoque `python3 engine/scripts/nuclei_dynamic_forge.py`.
// turbo
3. Execute o Nuclei usando os templates gerados na pasta `data/results/<domain>/dynamic_templates/`.
4. Atualize o relatório final com as novas vulnerabilidades lógicas encontradas.
