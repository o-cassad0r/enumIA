# Proposta de Modernização: Recon/Enum Toolset

Com base na arquitetura atual do projeto (Bash + Python + ProjectDiscovery), aqui está a análise para elevar o nível das ferramentas ao estado da arte em Red Team e Bug Bounty.

## 1. Aperfeiçoamento das Técnicas Atuais
- **Subdomain Permutation (Alterações Dinâmicas):** O recon passivo/ativo atinge um limite. O uso de permutações estruturadas baseadas nos subdomínios encontrados (ex: `dev-api`, `api-v1`) descobre infraestruturas ocultas.
- **Substituição Parcial do Nmap:** Para Web, o Nmap é lento. Usar `Naabu` para port scanning inicial de grandes scopes web é ordens de grandeza mais rápido, reservando o Nmap apenas para portas não-HTTP específicas.
- **Crawling Avançado com Headless Browser:** A coleta de endpoints via `gau` está limitada a arquivos mortos. Em SPAs (Single Page Applications) modernas, é necessário um crawler headless para interagir com o DOM e extrair URLs dinâmicas.

## 2. Inserção de Novas Ferramentas Ofensivas (Stack ProjectDiscovery/Modern)
| Ferramenta | Objetivo / Capacidade Nova |
|------------|---------------------------|
| `katana`   | Crawler/spider moderno (substitui/amplia o gau). Navega em SPAs via CLI headless, extraindo endpoints e parâmetros reais do client-side. |
| `naabu`    | Port scanner ultrarrápido focado em recon web. Executa a Fase 3 antes do httpx de forma muito mais silenciosa e rápida que o Nmap. |
| `alterx`   | Gera dicionários dinâmicos de subdomínios permutando os resultados da Fase 1, alimentando novamente o dnsx. |
| `tlsx`     | Analisa certificados SSL/TLS para expansão lateral do escopo (Subject Alternative Names). |
| `dalfox`   | Scanner super focado e rápido de XSS parametrizado (integra perfeitamente com a saída do seu Paramspider atual). |
| `crlfuzz`  | Varredura passiva/ativa para CRLF injection, altamente automatizável em bulk. |

## 3. Novas Skills para Manter e Evoluir o Código
Além do `python-pro` e `bash-pro`, as seguintes skills baseadas no ecossistema do seu agente garantirão que a automação seja inteligente, mantível e ofusque sua assinatura:
- `red-team-tools`: Fornecerá integração nativa de táticas avançadas (MITRE ATT&CK) e bypass de heurísticas defensivas.
- `scanning-tools`: Refinamento superior em parâmetros de WAF evasion e configuração de tunning para Naabu e Katana.
- `vulnerability-scanner`: Especializada em refinar templates do Nuclei e focar em CVEs de alto impacto recém-descobertas (CISA KEV), reduzindo falsos positivos.
- `api-fuzzing-bug-bounty`: Focada na manipulação de APIs REST/GraphQL descobertas durante o fuzzing.

---

## 4. Roadmap de Execução (Prompts Prontos)
Para não gastar tokens desnecessários e focar estritamente na execução técnica de código, dividimos as atualizações em **Fases Isoladas**. Copie e cole os prompts a seguir, um por vez, em novas sessões ou turnos.

---

### Etapa 1: Port Scanning Fast & Permutation (Naabu + Alterx)
*(Substituir lentidão de nmap global e exaurir subdomínios via permutação DNS)*

**Prompt:**
> Refatore a Fase 1 e 3 do [fuzzdirectory.sh](file:///e:/NIS%20Ti/Dev/Antigravity/Recon/enum/fuzzdirectory.sh) (skills: bash-pro, scanning-tools). 
> 1) Adicione `alterx` após a coleta de subdomínios passivos (fase1) para gerar permutações em memória e jogue para o `dnsx`. 
> 2) Na Fase 3 (Port Scanning), troque o loop de IP/Nmap inicial por `naabu` lendo a lista de hosts vivos para descobrir portas web atípicas de forma rápida. Gere o código corrigido.

### Etapa 2: Advanced Crawling & Parameter Mining (Katana + Dalfox)
*(Extração real do client-side e automação de injeção XSS)*

**Prompt:**
> Expanda a Fase de Inteligência do [fuzzdirectory.sh](file:///e:/NIS%20Ti/Dev/Antigravity/Recon/enum/fuzzdirectory.sh) (skills: red-team-tools, api-fuzzing-bug-bounty). 
> 1) Substitua o `gau` passivo pelo `katana` (modo crawling ativo) na extração de URLs. 
> 2) Configure pipe da extração do katana e paramspider para o `dalfox` (blind XSS param scanner).
> 3) Salve o output do Dalfox em um arquivo separado na estrutura de workdir.

### Etapa 3: SSL Lateral Movement & Misconfigs (Tlsx + Crlfuzz)
*(Expansão de escopo via SNI e exploração de cabeçalhos de borda)*

**Prompt:**
> Crie uma nova Fase 2.5 no [fuzzdirectory.sh](file:///e:/NIS%20Ti/Dev/Antigravity/Recon/enum/fuzzdirectory.sh) para Edge/TLS Recon (skills: vulnerability-scanner).
> 1) Use `tlsx` nos `$WORKDIR/hosts_vivos.txt` para extrair SANs (Subject Alternative Names) e reverter para a pipeline DNS.
> 2) Execute `crlfuzz` apontando para a mesma lista para detectar CRLF Injection passivamente.
> 3) Emita as views de logs apropriadas usando [progress_bar](file:///e:/NIS%20Ti/Dev/Antigravity/Recon/enum/fuzzdirectory.sh#60-72) e [spinner](file:///e:/NIS%20Ti/Dev/Antigravity/Recon/enum/fuzzdirectory.sh#40-57).

### Etapa 4: Integração de Dashboard Python
*(Atualizar a UI HTML para comportar as novas ferramentas)*

**Prompt:**
> Atualize o [reporter.py](file:///e:/NIS%20Ti/Dev/Antigravity/Recon/enum/reporter.py) e [template.html](file:///e:/NIS%20Ti/Dev/Antigravity/Recon/enum/template.html) (skills: python-pro, ui-ux-pro-max).
> 1) Adicione parseamento assíncrono para os novos arquivos do `naabu`, `dalfox`, `tlsx` e `crlfuzz`.
> 2) Crie uma nova aba no Dashboard chamada "Advanced Attack Surface" exibindo essas saídas em terminais mockados (`.terminal-wrapper`).
> 3) Retorne apenas os arquivos modificados.
