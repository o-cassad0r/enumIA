# 🔓 Local Skill: Bypass Auditor
**Especialista em Bypass de Autenticação e Restrição de Acesso (403/401).**

## 🎯 Objetivo
Identificar e aplicar técnicas de evasão para acessar diretórios protegidos e endpoints restritos.

## 📜 Regras de Ouro
- **Header Injection**: Sempre teste headers de proxy (`X-Forwarded-For`, `X-Custom-IP-Authorization`, `X-Real-IP`) com valores de localhost e IPs internos.
- **Path Tampering**: Realize fuzzing de variações de path (`/%2e/`, `/.`, `//`, `/..;/`) para enganar parsers de WAF.
- **Method Hopping**: Se `GET` falhar, tente `POST`, `PUT`, `TRACE` ou `DEBUG` com cabeçalhos de override (`X-HTTP-Method-Override`).
- **Data Encoding**: Teste payloads com encoding duplo de URL e Unicode para contornar filtros estáticos.

## 🔗 Skills Globais Relacionadas
- `red-team-tactics`
- `red-team-tools`
- `007`
