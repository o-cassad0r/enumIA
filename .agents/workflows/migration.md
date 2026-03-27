---
description: Workflow para refatoração atômica e modularização do projeto Enum.
---
# 🔄 Workflow de Refatoração Atômica

Este workflow define como migrar e refatorar arquivos legados para a nova estrutura modular, minimizando o consumo de tokens e garantindo a aplicação das regras das Skills Locais.

## Passos

1. **Contextualização de Borda**:
   - Leia o arquivo `docs/shellscript.md` (ou equivalente arquivado) para carregar os padrões de codificação do projeto.
   
2. **Processamento de Módulo**:
   - Escolha um arquivo único (ex: `sub_enum_full.sh`).
   - Aplique a Skill `recon-auditor` para identificar violações de segurança ou falta de hardening.
   - Use a Skill global `bash-pro` para reescrever o código seguindo SRP (Responsabilidade Única).
   
3. **Migração Física**:
   - Mova o arquivo refatorado para sua subpasta dentro de `modules/` (ex: `modules/subdomain_enum/`).
   
4. **Integração no Core**:
   - Atualize o orquestrador em `core/enum.sh` para invocar o novo módulo em vez de conter a lógica interna.

5. **Reset de Contexto**:
   - Solicite que o agente limpe o contexto de execução antes de prosseguir para o próximo arquivo.
