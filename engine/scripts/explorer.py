import json
import re
import math
import argparse

class JSONDeepExplorer:
    def __init__(self):
        # Padrões de Segredos (Regex avançado prático)
        self.signatures = {
            "AWS_Key": r"AKIA[0-9A-Z]{16}",
            "JWT_Token": r"eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*",
            "Google_API": r"AIza[0-9A-Za-z-_]{35}",
            "Private_IP": r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}",
            "PII_CPF": r"\d{3}\.\d{3}\.\d{3}-\d{2}", # Alvo BR
            "Cloud_Metadata": r"169\.254\.169\.254"
        }
        
        # Palavras-chave Mass Assignment / Escalonamento
        self.risk_keys = ["admin", "role", "permission", "internal", "debug", "state", "config"]

    def _calculate_entropy(self, data):
        if not data or not isinstance(data, str): return 0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(chr(x))) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log2(p_x)
        return entropy

    def _analyze_value(self, key, value, path):
        findings = []
        val_str = str(value)

        # 1. RegEx Fixos
        for name, pattern in self.signatures.items():
            if re.search(pattern, val_str):
                findings.append({
                    "type": f"CRITICAL_SIGNATURE_{name}",
                    "path": path,
                    "confidence": "HIGH"
                })

        # 2. Entropia
        if len(val_str) > 12 and self._calculate_entropy(val_str) > 3.8:
            if not val_str.startswith("http") and "-" not in val_str:
                findings.append({
                    "type": "HIGH_ENTROPY_SECRET",
                    "path": path,
                    "entropy": round(self._calculate_entropy(val_str), 2)
                })

        # 3. Mass Assignment Keys
        if any(risk in key.lower() for risk in self.risk_keys):
            findings.append({
                "type": "MASS_ASSIGNMENT_CANDIDATE",
                "path": path,
                "hint": "Tente injetar este campo em POST/PUT (Escalação)."
            })

        return findings

    def explore(self, payload):
        try:
            data = json.loads(payload) if isinstance(payload, str) else payload
            results = self._recursive_dive(data)
            category = self._categorize_json(data)
            
            return {
                "category": category,
                "findings": results,
                "stats": {"total_keys": len(results)}
            }
        except Exception as e:
            return {"error": f"Failed to parse JSON: {str(e)}"}

    def _recursive_dive(self, data, path="root"):
        results = []
        if isinstance(data, dict):
            for k, v in data.items():
                current_path = f"{path}.{k}"
                results.extend(self._analyze_value(k, v, current_path))
                results.extend(self._recursive_dive(v, current_path))
        elif isinstance(data, list):
            for i, item in enumerate(data):
                results.extend(self._recursive_dive(item, f"{path}[{i}]"))
        return results

    def _categorize_json(self, data):
        keys = str(data.keys()) if isinstance(data, dict) else ""
        if "version" in keys and "dependencies" in keys: return "MANIFEST_FILE"
        if "host" in keys or "port" in keys or "db" in keys: return "CONFIG_FILE"
        if "data" in keys or "items" in keys: return "API_RESPONSE"
        return "GENERIC_DATA"

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", required=True)
    args = parser.parse_args()

    with open(args.file, "r", encoding="utf-8") as f:
        payload = f.read()

    explorer = JSONDeepExplorer()
    report = explorer.explore(payload)
    
    # Imprime resultados consolidados
    print(json.dumps(report, indent=2, ensure_ascii=False))
