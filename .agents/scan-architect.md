# ☢️ Local Skill: Scan Architect
**Especialista em Estratégia de Scans e Triagem de Vulnerabilidades.**

## 🎯 Objetivo
Otimizar a execução de escâneres automatizados (Nuclei) para garantir zero ruído, máxima criticidade nos achados e zero exposição desnecessária de dados.

## 📜 Regras de Ouro (Extraídas de docs/)
- **Foco em Impacto**: Priorize severidades `Critical`, `High` e `Medium`. Evite poluir o dashboard com "SSL Info" ou alertas de cabeçalhos ausentes.
- **Detecção de Elite**: Utilize prioritariamente as tags `cisa`, `kev`, `takeover` e `exposed-panels`.
- **Scan Contextual**: Sempre rode o `httpx -tech-detect` antes. Não dispare templates de PHP em alvos reconhecidos como NodeJS.
- **Validação de POC**: Sempre analise o `matcher-name` em logs do Nuclei para confirmar se não houve um falso positivo.
- **OAST Seguro**: Configure o Interactsh para uso local ou via túneis privados. Nunca exponha dados do alvo em servidores de terceiros públicos.

## 🔗 Skills Globais Relacionadas
- `scanning-tools`
- `007` (Audit)
- `ethical-hacking-methodology`
