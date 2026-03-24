# Refatoração [reporter.py](file:///e:/NIS%20Ti/Dev/Antigravity/Recon/Enum/reporter.py) — 3 Sessões

Refatora o reporter de 172 linhas sync/sem tipagem para um módulo async tipado, mantendo a interface de chamada `python3 reporter.py <dom> <workdir>` inalterada.

## Resumo do estado atual

| Aspecto | Hoje |
|---|---|
| I/O | `open()` síncrono, bloqueante |
| Tipagem | Nenhuma (só `list[str]` inline) |
| Modelo de dados | variáveis soltas em [main()](file:///e:/NIS%20Ti/Dev/Antigravity/Recon/Enum/subtakeouver.sh#49-87) |
| Template | `.replace()` em loop — risco de colisão de placeholder |
| Dependências | stdlib puro |

---

## Sessão A — Estrutura de Dados (`dataclasses` + `Path`)

### Objetivo
Substituir variáveis soltas por um modelo de dados explícito e usar `pathlib.Path` em todo o código.

### [MODIFY] [reporter.py](file:///e:/NIS%20Ti/Dev/Antigravity/Recon/Enum/reporter.py)

- Adicionar `from pathlib import Path` e `from dataclasses import dataclass, field`
- Criar `@dataclass class ReconPaths` — encapsula todos os `Path` usados
- Criar `@dataclass class ReconReport` — holds todos os valores coletados (dom, scan_time, threat_level, contadores, HTML parciais etc.)
- Substituir todos os `os.path.join(workdir, "...")` por `paths.<campo>`
- [get_file_content](file:///e:/NIS%20Ti/Dev/Antigravity/Recon/Enum/reporter.py#6-15) passa a aceitar `Path` em vez de `str`

```python
@dataclass
class ReconPaths:
    workdir: Path
    ips:     Path = field(init=False)
    whois:   Path = field(init=False)
    # … todos os campos

    def __post_init__(self):
        self.ips   = self.workdir / "ips_unicos.txt"
        self.whois = self.workdir / "whois_raw.txt"
        # …

@dataclass
class ReconReport:
    dom:         str
    scan_time:   str
    main_ip:     str
    threat_level: str = "LOW"
    v_crit: int = 0
    v_high: int = 0
    # …
```

### Verificação A
- `python3 reporter.py example.com /tmp/fake` não trava (paths inexistentes → defaults)
- Sem dependências novas além de stdlib

---

## Sessão B — Leitura Async (`aiofiles` + `asyncio.gather`)

### Objetivo
Paralelizar todas as leituras de arquivo com `asyncio.gather`, eliminando bloqueio sequencial de I/O.

> [!IMPORTANT]
> Requer `pip install aiofiles`. Adicionar ao comentário de cabeçalho do script e ao `README`.

### [MODIFY] [reporter.py](file:///e:/NIS%20Ti/Dev/Antigravity/Recon/Enum/reporter.py)

- [get_file_content](file:///e:/NIS%20Ti/Dev/Antigravity/Recon/Enum/reporter.py#6-15) → `async def async_read(path: Path, default: str) -> str` usando `aiofiles.open`
- Criar `async def collect_data(paths, dom) -> ReconReport` que dispara todas as leituras em paralelo com `asyncio.gather`
- [main()](file:///e:/NIS%20Ti/Dev/Antigravity/Recon/Enum/subtakeouver.sh#49-87) vira `async def main()` com `asyncio.run(main())`
- Funções de análise ([get_recommendations](file:///e:/NIS%20Ti/Dev/Antigravity/Recon/Enum/reporter.py#16-39), [get_nmap_cves](file:///e:/NIS%20Ti/Dev/Antigravity/Recon/Enum/reporter.py#40-68)) permanecem sync mas recebem o conteúdo já lido (não releem do disco)

```python
async def async_read(path: Path, default: str = "Nenhum dado encontrado.") -> str:
    if path.exists() and path.stat().st_size > 0:
        async with aiofiles.open(path, errors="ignore") as f:
            return (await f.read()).strip()
    return default

async def collect_data(paths: ReconPaths, dom: str) -> ReconReport:
    ips, whois, nuclei, rdns, cloud, asn, takeover, params = await asyncio.gather(
        async_read(paths.ips, "N/A"),
        async_read(paths.whois, "Sem dados de WHOIS."),
        async_read(paths.nuclei_log, ""),
        async_read(paths.reverse_dns, ""),
        async_read(paths.cloud_assets, ""),
        async_read(paths.asn_info, ""),
        async_read(paths.takeover, ""),
        async_read(paths.params, ""),
    )
    # … montar ReconReport e retornar
```

### Verificação B
- `time python3 reporter.py <dom> <workdir>` com 10+ arquivos deve ser ≥20% mais rápido que versão sync
- Sem race conditions (todas leituras são read-only)

---

## Sessão C — Geração HTML (`string.Template` seguro)

### Objetivo
Substituir o loop `.replace()` por `string.Template` com delimitador customizado, eliminando risco de colisão entre placeholders e conteúdo HTML real.

### [MODIFY] [reporter.py](file:///e:/NIS%20Ti/Dev/Antigravity/Recon/Enum/reporter.py)
### [MODIFY] [template.html](file:///e:/NIS%20Ti/Dev/Antigravity/Recon/Enum/template.html)

- Criar subclasse `class ReconTemplate(string.Template): delimiter = "@@"` para usar `@@{PLACEHOLDER}` em vez de `{{PLACEHOLDER}}`
- Trocar todos os `{{KEY}}` no [template.html](file:///e:/NIS%20Ti/Dev/Antigravity/Recon/Enum/template.html) por `@@{KEY}`
- Substituir o loop `for key, value in replacements.items(): html = html.replace(key, value)` por `ReconTemplate(html).safe_substitute(replacements_dict)`
- `safe_substitute` deixa placeholders não encontrados intactos (não levanta exceção)

```python
import string

class ReconTemplate(string.Template):
    delimiter = "@@"
    # Aceita: @@{DOM}, @@{THREAT_LEVEL}, etc.

# Uso:
html_out = ReconTemplate(template_text).safe_substitute(
    DOM=report.dom,
    SCAN_TIME=report.scan_time,
    # …
)
```

> [!WARNING]
> O [template.html](file:///e:/NIS%20Ti/Dev/Antigravity/Recon/Enum/template.html) precisa ter TODOS os `{{X}}` trocados por `@@{X}`. Verificar com `grep -n '{{' template.html` após a migração — resultado deve ser vazio.

### Verificação C
- `grep -n '{{' report.html` → sem resultados (nenhum placeholder não resolvido)
- Conteúdo HTML com `{` ou `}` legítimos (JSON inline, CSS) não é corrompido pelo `safe_substitute`

---

## Verificação Final (após as 3 sessões)

```bash
# Instalar aiofiles se necessário
pip install aiofiles

# Smoke test com workdir real
python3 reporter.py example.com ./recon_results/example.com

# Checagem de placeholders residuais
grep -n '@@{' report.html   # deve ser vazio
grep -n '{{' report.html    # deve ser vazio

# Lint
python3 -m py_compile reporter.py && echo "✅ Sem erros de sintaxe"
```
