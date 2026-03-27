# 🔄 Project enumIA: Synchronization & Dependency Map

Este mapa define a hierarquia de dependências do projeto. Se você alterar um arquivo em um nível superior, **DEVE** verificar e sincronizar os arquivos nos níveis inferiores afetados.

---

## 🔝 Nível 1: Fundamentação (Foundation)
*Arquivos que definem o comportamento global e utilitários base.*
- **`core/utils.sh`**: Contém funções de logging, UI e traps.
- **`setup.sh`**: Instalação de ferramentas e configuração de ambiente.
- **`core/update_wordlists.sh`**: Sincronização delta de arsenal.
- **`requirements.txt`**: Dependências Python.

**🔄 Se alterados:** Sincronize todos os módulos em `modules/` e o orquestrador `core/enum.sh`.

---

## 🕹️ Nível 2: Orquestração (Control Plane)
*Arquivos que gerenciam o fluxo de execução.*
- **`core/enum.sh`**: O cérebro do pipeline.
- **`fuzzdirectory.sh`**: Wrapper de compatibilidade.

**🔄 Se alterados:** Verifique a ordem de chamada dos scripts em `modules/` e a passagem de argumentos para `engine/reporter.py`.

---

## ⚙️ Nível 3: Execução (Data Plane)
*Scripts que geram dados brutos de inteligência.*
- **`modules/subdomain_enum/discover.sh`** ➔ Gera `hosts_dns.txt`, `hosts_vivos.txt`.
- **`modules/infra/intel.sh`** ➔ Gera `asn_info.txt`, `js_files.txt`, `katana_urls.txt`.
- **`modules/fuzzing/ffuf.sh`** ➔ Gera `results.json` na pasta fuzzing.
- **`modules/vulnerability/nuclei.sh`** ➔ Gera `vulnerabilidades.txt`.
- **`engine/scripts/nuclei_dynamic_forge.py`** ➔ Gera templates YAML dinâmicos.

**🔄 Se alterados:** Verifique se o `engine/reporter.py` ainda consegue ler os caminhos e formatos dos arquivos gerados.

---

## 🖼️ Nível 4: Inteligência e Visualização (Output)
*Arquivos que processam resultados e geram o dashboard.*
- **`engine/reporter.py`**: Motor de parsing.
- **`templates/template.html`**: UI do Dashboard.

**🔄 Se alterados:** Verifique se as variáveis `@@{VAR}` no template coincidem com as chaves do dicionário `report` no Python.

---

## 🚦 Protocolo de Sincronização Obrigatório

1.  **Mudança em `utils.sh`** ➔ Rodar um `Dry Run` em pelo menos um módulo de cada cluster.
2.  **Novo Script em `modules/`** ➔ 
    *   Adicionar chamada em `core/enum.sh`.
    *   Adicionar placeholder e lógica de parsing em `engine/reporter.py`.
    *   Adicionar novo componente visual em `templates/template.html`.
3.  **Alteração de Wordlist** ➔ Garantir que a variável `W_DIR` no script afetado esteja apontando para `config/Wordlists/`.
