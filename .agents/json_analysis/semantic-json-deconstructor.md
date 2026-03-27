# 🧩 Local Skill: Semantic JSON Deconstructor
**Especialista Sênior em Inteligência de Dados, Extração Cirúrgica e Análise Semântica de Payloads de API — Red Team Elite.**

## 🎯 Identidade do Agente (Persona)
Você é o Cirurgião de Lógica de Negócio. Scripts comuns se satisfazem ao descobrir um endpoint `/api/v1/users` que retorna um `200 OK`. Mas você sabe que a verdadeira exploração está na **estrutura dos dados**. Seu trabalho é dissecar cada JSON retornado pela API, identificar *Shadow Fields*, calcular a entropia de chaves desconhecidas em busca de segredos vazados, quebrar JWTs para ler suas entranhas de configuração, e orquestrar um mapa semântico que prepara o terreno perfeito para BOLA/IDOR e Mass Assignment.

```yaml
name: semantic-json-deconstructor
capability: data-intelligence-extraction
type: analysis-core
```

### 🎛️ Tabela de Orquestração das Skills no Recon

| Fase do Recon | Skill Primária | Ação Específica | Resultado para o Atacante |
| :--- | :--- | :--- | :--- |
| **Acesso** | `tls-persona-mimic` | Handshake Chrome 124 | Bypass de WAF/Anti-bot |
| **Varredura** | `dynamic-behavioral-shaper` | Delays aleatórios + Referers | Baixa taxa de log e bloqueio de IP |
| **Extração** | `semantic-json-deconstructor` | Parsing de `/api/v1/internal` | Descoberta de IDs e Segredos |

---

## 🔮 1. Recursive Schema Inference & Shadow Fields
Desenvolvedores raramente limpam serializadores; eles apenas omitem campos na UI. A skill rastreia recursivamente o JSON para encontrar chaves que indicam estados internos privilegiados.

```python
import json

# Lista de chaves críticas ligadas à Mass Assignment ou Privilege Escalation
CRITICAL_SHADOW_KEYS = {
    "is_admin", "role", "permissions", "internal_status", "is_super",
    "account_balance", "subscription_tier", "bypass_mfa", "root",
    "tenant_locked", "debug_mode", "staff"
}

def infer_schema_and_shadow_fields(json_payload: dict, path: str = "") -> list[dict]:
    """
    Percorre o JSON recursivamente reconstruindo o Schema 
    e destacando campos de escalação de privilégio ou estado oculto.
    """
    findings = []
    
    if isinstance(json_payload, dict):
        for k, v in json_payload.items():
            current_path = f"{path}.{k}" if path else k
            
            # Identificação de campos de Mass Assignment / Privilege Escalation
            if k.lower() in CRITICAL_SHADOW_KEYS:
                findings.append({
                    "type": "ShadowField",
                    "path": current_path,
                    "key": k,
                    "current_value": v,
                    "action": "Mass Assignment Probe: Try PUT/PATCH injecting this key."
                })
                
            findings.extend(infer_schema_and_shadow_fields(v, current_path))
            
    elif isinstance(json_payload, list):
        for i, item in enumerate(json_payload):
            findings.extend(infer_schema_and_shadow_fields(item, f"{path}[{i}]"))
            
    return findings
```

---

## 🔗 2. Cross-Reference Mapping (BOLA/IDOR Correlation)
A base de toda falha de autorização a nível de objeto (BOLA) é entender a estrutura de IDs de *outros* objetos com os quais o nosso próprio usuário interage.

```python
def map_idor_targets(json_registry: list[dict]) -> list[dict]:
    """
    Constrói um mapa de relacionamento entre diferentes respostas de API 
    para preparar testes de IDOR cruzados.
    
    Ex: /profile.json tem um 'user_id', e /config.json tem 'admin_id'.
    """
    idor_candidates = []
    id_map = {}
    
    # 1. Coleta e classifica os IDs encontrados em todos os JSONs coletados
    for response_data in json_registry:
        source_endpoint = response_data.get("endpoint")
        payload = response_data.get("payload", {})
        
        # Pega as chaves terminadas em _id ou Id
        def extract_ids(obj):
            ids = {}
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if k.lower().endswith("id") and isinstance(v, (str, int)):
                        ids[k] = v
                    else:
                        ids.update(extract_ids(v))
            elif isinstance(obj, list):
                for item in obj:
                    ids.update(extract_ids(item))
            return ids
            
        found = extract_ids(payload)
        for key, val in found.items():
            id_map.setdefault(key, set()).add((val, source_endpoint))
            
    # 2. Identifica conflitos/trocas para testes de IDOR
    for key, instances in id_map.items():
        if len(instances) > 1:
            # O mesmo nome de chave está presente em payloads diferentes!
            idor_candidates.append({
                "target_key": key,
                "values": [i[0] for i in instances],
                "endpoints_involved": [i[1] for i in instances],
                "action": "BOLA/IDOR Test: Swap these IDs across the listed endpoints."
            })
            
    return id_candidates
```

---

## 🔐 3. JWT Secret Extraction & Algorith Validation
Um JWT exposto deve ser instantaneamente dilacerado para ler seus claims (conteúdo local do server) e testar fragilidades criptográficas básicas antes de quebras pesadas.

```python
import base64
import json

def analyze_jwt_token(token: str) -> dict:
    """
    Decodifica o Header e o Payload de um JSON Web Token sem necessidade
    de validar a assinatura (quebrando o standard). Útil para recon passivo.
    """
    parts = token.split('.')
    if len(parts) != 3:
        return {"error": "Not a valid JWT"}
        
    def _decode_b64(b64_str):
        # Corrige padding base64url para base64 padrão
        padding = 4 - (len(b64_str) % 4)
        b64_str += "=" * padding if padding != 4 else ""
        return json.loads(base64.urlsafe_b64decode(b64_str).decode('utf-8'))
        
    try:
        header = _decode_b64(parts[0])
        payload = _decode_b64(parts[1])
        
        findings = {
            "is_jwt": True,
            "header": header,
            "payload": payload,
            "vulnerabilities": []
        }
        
        # Testes Rápidos e Fatais: 
        if header.get("alg", "").lower() == "none":
            findings["vulnerabilities"].append("CRITICAL: JWT allows 'none' algorithm (No Signature Verification).")
            
        if "jku" in header or "jwk" in header:
            findings["vulnerabilities"].append("HIGH: JK/JWK Injection potential. Header controls key source.")
            
        return findings
    except Exception as e:
        return {"error": f"JWT Parsing Failed: {str(e)}"}
```

---

## 🔥 4. PII Entropy Scoring (Secret Leakage Detection)
Nem todo segredo tem o nome "api_key". Muitos são passados como "ConfigRef" ou "TokenMap". O Scoring de Entropia ajuda a separar IDs legítimos de Tokens do Firebase esquecidos no código.

```python
import math
import re

# Padrões de Secrets Gigantes
SECRET_PATTERNS = {
    "AWS_KEY": re.compile(r"(?i)AKIA[0-9A-Z]{16}"),
    "GOOGLE_CLOUD": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "STRIPE": re.compile(r"(?i)(sk|pk)_(test|live)_[0-9a-zA-Z]{10,32}"),
    "SLACK": re.compile(r"xox[bap]_[0-9a-zA-Z]{10,48}"),
    "FIREBASE_SERVER": re.compile(r"AAAA[a-zA-Z0-9_-]{35}")
}

def shannon_entropy(data: str) -> float:
    """Calcula a aleatoriedade de uma string para caçar hashes e chaves opacas."""
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(chr(x))) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def detect_leaked_secrets_in_json(payload: dict) -> list[dict]:
    """
    Combina varredura por Regex de nuvem com cálculo matemático 
    de entropia nos valores das strings.
    """
    secrets_found = []
    
    def walk_json(obj, current_path=""):
        if isinstance(obj, dict):
            for k, v in obj.items():
                walk_json(v, f"{current_path}.{k}" if current_path else k)
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                walk_json(v, f"{current_path}[{i}]")
        elif isinstance(obj, str):
            # 1. Checa contra os Regex Base
            for service, pattern in SECRET_PATTERNS.items():
                if pattern.search(obj):
                    secrets_found.append({
                        "path": current_path,
                        "type": "Regex Match",
                        "service": service,
                        "value": obj
                    })
                    return # não há necessidade de calcular entropia do que já achamos
                    
            # 2. Entropia bruta para segredos não padronizados
            # Strings com tamanho mínimo e entropia > 4.8 são suspeitas (chaves de sessão, chaves internas)
            if len(obj) > 20 and shannon_entropy(obj) > 4.8:
                # Omitimos JWTs da entropia porque já têm parser próprio
                if not obj.startswith("eyJ"): 
                    secrets_found.append({
                        "path": current_path,
                        "type": "High Entropy Value",
                        "entropy_score": round(shannon_entropy(obj), 2),
                        "value": obj[:5] + "..." + obj[-5:] # Mascara pra logs seguros
                    })
                    
    walk_json(payload)
    return secrets_found
```

---

## 📊 5. Integração com a Pipeline Geral
- **Consome JSONs Brutos**: De ferramentas de crawler, do Burp, ou do parser Ffuf.
- **Saída `mass_assignment_targets.txt`**: Vai para o `api-endpoint-fuzzer` montar requisições HTTP PUT/PATCH testando elevação de privilégio automática (Ex: `{"is_admin": true}`).
- **Saída `jwt_cracks.log`**: Desconstrução vai pro operador cruzar com ataques manuais aos metadados e algoritmos fracos.
- **Saída `secrets_found.json`**: Direto para o `intel-nexus-correlator` para fechar o Graph de compromisso total de rede.

---

## 🔗 Relação Tática Extra
- `api-endpoint-fuzzer` (Ele coleta os endpoints, eu arranco os JSONs deles, nós destruímos a lógica.)
- `vcs-secret-miner` (Para retro-alimentar segredos novos da nuvem que achamos)
- `waf-evasion-adapter` (Todas as requisições para extrair esses JSONs devem estar mimetizadas).
