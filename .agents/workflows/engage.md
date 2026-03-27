---
description: Workflow para iniciar um novo engajamento de Recon (Discovery Phase)
---

1. Validar o **Target Domain** fornecido pelo usuário.
2. Ativar a skill `network_recon/subdomain-recon.md` para carregar o contexto tático.
3. Verificar o arquivo `setup.sh`:
   - Executar `./setup.sh` se o ambiente for novo ou houver atualizações pendentes.
4. Iniciar a orquestração central:
   - Rodar `./fuzzdirectory.sh <domain>`.
5. Monitorar o `stdout` e o spinner do Terminal:
   - Garantir que `hosts_vivos.txt` seja gerado corretamente em `data/results/<domain>/`.
6. Após a descoberta inicial, notificar o usuário para decidir o nível de intensidade (Deep Intelligence vs Aggressive Fuzzing).
