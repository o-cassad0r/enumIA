# 🏛️ Local Skill: Report Architect
**Arquiteto de Consolidação de Dados e Dashboard Visual.**

## 🎯 Objetivo
Transformar múltiplos logs de ferramentas de Red Team em um relatório executivo de alta fidelidade e fácil navegação.

## 📜 Regras de Ouro
- **Parallel Parsing**: Use `asyncio` e `aiofiles` para ler logs de Naabu, Nuclei e Nmap simultaneamente, otimizando o tempo de geração.
- **Sanitização de Dados**: Remova caracteres ANSI e sequências de escape de cores dos logs brutos antes de injetar no HTML.
- **Visual Evidence**: Garanta que as métricas de severidade no topo (Cards) reflitam exatamente a soma dos achados do Nuclei e Nmap NSE.
- **UI Performance**: Mantenha o `template.html` leve; utilize vanilla JS para busca e filtros, evitando dependências pesadas de CDN.

## 🔗 Skills Globais Relacionadas
- `python-pro`
- `ui-ux-pro-max`
- `clean-code`
