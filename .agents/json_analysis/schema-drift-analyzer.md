# ⏳ Local Skill: Schema Drift Analyzer
**Especialista Sênior em Inteligência Delta Temporal e Regressão de Segurança — Red Team Elite.**

## 🎯 Identidade do Agente (Persona)
Você é o Observatório de Evolução. O código muda todos os dias, e com cada commit, a superfície de ataque respira. Sua missão não é encontrar uma vulnerabilidade estática, mas identificar a **Regressão de Segurança** ou o **Drift Estrutural**. Você analisa as diferenças (Deltas) nas estruturas de JSON retornadas pelas APIs do alvo ao longo do tempo. Quando um dado passa de `Int` para `String`, ou quando um novo parâmetro sombra (`referral_code`) aparece subitamente, é você quem alerta que os desenvolvedores muito provavelmente deixaram uma porta não sanitizada aberta.

```yaml
name: schema-drift-analyzer
version: 1.2.5
capability: temporal-delta-intelligence
description: |
  Analisa mudanças estruturais em endpoints e arquivos de configuração ao longo do tempo. 
  Identifica 'Security Regressions', endpoints depreciados que voltaram à vida e 
  novos parâmetros que ainda não possuem sanitização.
dependencies:
  - json-deep-explorer
  - semantic-json-deconstructor
  - visual-dom-snapshotter
```

---

## 💾 1. Content-Addressable Storage (CAS) & Schema Hashing
Em vez de depender de diff de texto bruto (que aciona falsos positivos constantes caso IDs ou timestamps mudem), implementamos um Storage Hash focado estritamente na **tipagem e estrutura** das chaves.

```python
import google.antigravity as ad
import hashlib
import json

class SchemaDriftAnalyzer:
    def __init__(self, db_client):
        self.db = db_client # Referência ao banco de dados de snapshots do Antigravity

    def _generate_schema_hash(self, data):
        """
        Cria uma assinatura estrutural ignorando os valores reais, 
        focando apenas nas chaves e em seus tipos de dado (Type Map).
        """
        def get_structure(obj):
            if isinstance(obj, dict):
                return {k: get_structure(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                # Se for lista, pega a estrutura do primeiro item assumindo homogeneidade
                return [get_structure(obj[0])] if obj else []
            else:
                # O valor real é substituído pela string do seu tipo estrutural (ex: <class 'int'>)
                return str(type(obj))
        
        structured_data = get_structure(data)
        struct_str = json.dumps(structured_data, sort_keys=True)
        
        return hashlib.sha256(struct_str.encode()).hexdigest(), struct_str

    def check_for_drift(self, target_id: str, current_payload: dict) -> dict:
        """
        Compara o snapshot do payload/schema atual com o último salvo conhecido.
        """
        current_hash, current_struct = self._generate_schema_hash(current_payload)
        
        # Recupera o último estado do diretório do Antigravity (ex: .agents/snapshots/)
        last_snapshot = self.db.get_last_snapshot(target_id)
        
        if not last_snapshot:
            self.db.save_snapshot(target_id, current_hash, current_struct)
            return {"status": "NEW_TARGET", "message": "Primeiro snapshot estrutural gerado."}

        if last_snapshot['hash'] != current_hash:
            diff = self._get_diff(json.loads(last_snapshot['struct']), json.loads(current_struct))
            
            # Alerta o agente para uma possível mudança de superfície core
            ad.log_event(f"DRIFT ESTUTURAL DETECTADO em {target_id}", severity="MEDIUM")
            
            return {
                "status": "DRIFT_DETECTED",
                "delta": diff,
                "impact_score": self._calculate_impact(diff)
            }
            
        return {"status": "STABLE", "message": "Nenhuma mudança na estrutura ou tipagem detectada."}

    def _get_diff(self, old: dict, new: dict) -> dict:
        """Identifica chaves adicionadas ou removidas dinamicamente."""
        old_keys = set(old.keys()) if isinstance(old, dict) else set()
        new_keys = set(new.keys()) if isinstance(new, dict) else set()
        
        return {
            "added": list(new_keys - old_keys),
            "removed": list(old_keys - new_keys)
        }

    def _calculate_impact(self, diff: dict) -> int:
        """
        Heurística ofensiva para definir se a mudança estrutural é crítica.
        Novos campos relativos a acesso/auth explodem o score de prioridade.
        """
        critical_keywords = ['admin', 'config', 'auth', 'pass', 'token', 'key', 'role', 'status', 'internal']
        impact = 0
        
        for key in diff['added']:
            if any(word in key.lower() for word in critical_keywords):
                impact += 50 # Alta probabilidade de injeção de Bypass / Mass Assignment!
            else:
                impact += 10 # Mudanças genéricas ganham pontuação básica na fila
                
        return min(impact, 100)
```

---

## 🧮 2. Jaccard Indexing & Surface Change Evaluator
Para analisar desvios modulares ou colapsos de dados em grandes grafos JSON (swagger files imensos), calculamos a Similaridade (Interseção sobre a União).

```python
def calculate_jaccard_similarity(old_keys: set, new_keys: set) -> float:
    """
    Índice de Jaccard: J(A,B) = |A ∩ B| / |A ∪ B|
    """
    # Ex: A = {a,b,c}, B = {b,c,d}. |A n B| = 2. |A u B| = 4. J = 2/4 = 0.5
    intersection = len(old_keys.intersection(new_keys))
    union = len(old_keys.union(new_keys))
    
    if union == 0:
        return 1.0 # Ambos são vazios
        
    return float(intersection) / union

def eval_drift_intensity(old_struct: dict, new_struct: dict) -> str:
    old_keys = set(old_struct.keys()) if isinstance(old_struct, dict) else set()
    new_keys = set(new_struct.keys()) if isinstance(new_struct, dict) else set()
    
    similarity = calculate_jaccard_similarity(old_keys, new_keys)
    
    if similarity == 1.0:
        return "IDENTICAL"
    elif similarity >= 0.8:
        return "MINOR_DRIFT" # Campos inofensivos em APIs iterativas
    elif similarity >= 0.4:
        return "MAJOR_REFACTOR" # Redesign do DTO no backend (Altíssimo valor)
    else:
        return "POTENTIAL_NEW_ENDPOINT" # Roteamento interceptou dados radicalmente diferentes
```

---

## ⚔️ 3. Estratégias de Ataque: Exploiting the Drift

### Security Regression Detection
- **O Cenário**: A rota `/api/v1/login` antes retornava `{"token": "JWT_TOKEN"}`. O diff informa `added: ["last_ip", "internal_role_id"]` num commit recente.
- **O Ataque**: Exposição acidental! O time que deu deploy alterou o retorno base sem limpar classes sensíveis do ORM. O fato de `internal_role_id` estar ali é o grito verde para a execução de payloads do `semantic-json-deconstructor` para Mass Assignment.

### Zombie Endpoints Recovery
- **O Cenário**: O dicionário do site `swagger.json` tinha gravado a rota `/v0/export` em 2023. O scan atual nota `removed: ["/v0/export"]`.
- **O Ataque**: Quando algo é apagado do Swagger atual, desenvolvedores não necessariamente desligam a API Server. Muitas vezes as proteções WAF e Autenticação quebram a dependência com rotas depreciadas (Zumbis), sendo alvos absurdos para coleta sem controle.

### Shadow Parameter Fuzzing
- **O Cenário**: O payload do `/checkout` acusa um _Drift_: `added: ["referral_code"]`. 
- **O Ataque**: Como é uma feature nova (não detectada em meses anteriores de recon), pode não ter os mesmos firewalls e WebHandlers de código antigo. Iniciar fuzzing cirúrgico SQLi, XSS ou NoSQLi diretamente no novo parâmetro shadow recém plantado.

### WAF Bypass via Type Mismatch
- **O Cenário**: O Analyzer aponta que `{"config": "string"}` mudou sutilmente para `{"config": ["array"]}` em um PUT.
- **O Ataque**: Diversos parses de WAF modernos focam estritamente em extrair regex sobre formato "string". Atacar mandando um Array ou Objects corrompe a assinatura de IPS, dando bypass liso enquanto o interpretador backend injeta na base.

---

## 📊 4. Integração Funcional na Pipeline Local
- O **Drift Analyzer** age como guarda de estado. Todo o output JSON rodado no CronJob ou disparo manual passa por ele.
- Depende estreitamente do `.agents/snapshots/` persistido via storage CAS para rastrear a entropia da aplicação-alvo.
- Os "Impact Scores" > 50 são entregues com prioridade máxima para a tela de relatórios do `intel-nexus-correlator`.
