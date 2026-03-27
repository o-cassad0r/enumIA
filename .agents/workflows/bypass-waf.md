---
description: Workflow para contornar bloqueios de WAF ou Forbidden (403/401)
---

1. Identificar o alvo bloqueado (URL ou Endpoint).
2. Carregar o contexto de evasão em `active_exploitation/`:
   - `waf-evasion-adapter.md`
   - `tls-persona-mimic.md`
   - `dynamic-behavioral-shaper.md`
3. Configurar mimetismo tático:
   - Injetar headers `X-Forwarded-For` e `User-Agent` reais.
   - Ajustar o **Poisson Jitter** para mimetizar comportamento humano estocástico.
4. Executar o script de teste:
   - `bash modules/bypass/bypass_forbidden.sh <target_subdomain>`.
5. Analisar o resultado em `data/results/<domain>/bypass-<subdomain>/`.
6. Se o sucesso for parcial, recomendar alteração de Wordlist ou Verb Tampering via `api-endpoint-fuzzer.md`.
