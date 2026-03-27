---
description: Workflow para finalizar a missão e gerar o Dashboard visual
---

1. Conferir se todas as fases anteriores (Discovery, Intel, Vuln) foram concluídas.
2. Carregar a skill `report-architect.md`.
3. Validar a integridade dos dados em `data/results/<domain>/`:
   - Verificar arquivos `.json` e `.txt`.
4. Disparar o motor de relatórios:
   - `python3 engine/reporter.py <domain> data/results/<domain>`.
5. Visualizar o relatório gerado em `data/results/<domain>/report.html`.
6. Enviar o link do arquivo para o usuário.
7. Executar a rotina de limpeza final:
   - Apagar arquivos temporários em `/tmp` e logs verbosos não essenciais.
