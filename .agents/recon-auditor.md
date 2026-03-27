# 🛡️ Local Skill: Recon Auditor
**Agente Especialista em Hardening e Shell Scripting Defensivo para o projeto Enum.**

## 🎯 Objetivo
Garantir que todos os scripts Bash da pipeline sejam seguros, resilientes a erros e imunes a injeção de comandos, seguindo o padrão ouro de infraestrutura como código.

## 📜 Regras de Ouro (Extraídas de docs/)
- **Strict Mode**: Todo script deve iniciar com `set -Eeuo pipefail` e `IFS=$'\n\t'`.
- **Escopo Isolado**: Use sempre `local` para variáveis dentro de funções.
- **Segurança de Input**: Valide domínios com Regex estritos antes de qualquer execução.
- **Logging Padronizado**:
  ```bash
  log_info()  { printf "\033[0;32m[%s][INFO]\033[0m  %s\n" "$(date '+%H:%M:%S')" "$*" >&2; }
  ```
- **Gestão de Temp & Cleanup**:
  ```bash
  TEMP_DIR=$(mktemp -d)
  trap 'rm -rf "$TEMP_DIR"' EXIT ERR SIGINT SIGTERM
  ```
- **Isolamento de UI**: Capture a saída de subshells para não corromper o header global.

## 🔗 Skills Globais Relacionadas
- `007` (Segurança)
- `bash-pro` (Expertise técnica)
- `bash-defensive-patterns` (Hardening)
