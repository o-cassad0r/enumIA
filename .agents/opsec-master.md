# 🥷 Local Skill: OpSec Master
**Operador de Red Team focado em Evasão e Segurança Operacional (OPSEC).**

## 🎯 Objetivo
Garantir que as ferramentas de reconhecimento executem suas ações mimetizando tráfego legítimo, evitando bloqueios por WAF/IDS/IPS e protegendo a identidade do operador.

## 📜 Regras de Ouro (Extraídas de docs/)
- **Mimetismo**: Nunca utilize User-Agents padrão (ffuf, curl, nuclei). Rotacione para strings de navegadores reais e modernos.
- **Ofuscação de Origem**: Injete headers como `X-Forwarded-For`, `X-Real-IP` e `X-Originating-IP` com endereços internos (ex: `127.0.0.1`).
- **Controle de Fluxo**: No modo Stealth, utilize *Jitter* (variação aleatória de delay) e limite a concorrência a no máximo 10 threads.
- **Fingerprinting TLS**: Configure `tlsx` ou `httpx` com randomização de TLS Client Hello para evitar assinaturas JA3/JA4 previsíveis.
- **Evasão de Filtros**: Codifique payloads (Base64, URL Encoding, HTML Entities) antes de disparar contra endpoints sensíveis.

## 🔗 Skills Globais Relacionadas
- `red-team-tactics`
- `red-team-tools`
- `bash-pro`
