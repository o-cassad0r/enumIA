#!/usr/bin/env python3
"""
nuclei_dynamic_forge.py — Gear Level 4: Cognitive Feedback Loop
Transforms JSON intelligence into active Nuclei templates.
"""
import json
import os
import sys
from pathlib import Path

def forge_template(type, data, output_dir):
    """Gera um arquivo YAML do Nuclei baseado no tipo de inteligência."""
    template_id = f"dynamic-{type}-{os.urandom(2).hex()}"
    template_path = output_dir / f"{template_id}.yaml"
    
    content = ""
    if type == "idor":
        target_path = data.get("path", "/api/v1/user")
        content = f"""
id: {template_id}
info:
  name: Dynamic IDOR Forge from JSON Intel
  author: enumIA-AI
  severity: medium

http:
  - method: GET
    path:
      - "{{{{BaseURL}}}}{target_path}/{{{{ids}}}}"
    payloads:
      ids:
        - "1"
        - "0"
        - "-1"
        - "9999"
    matchers:
      - type: status
        status:
          - 200
"""
    
    if content:
        with open(template_path, "w") as f:
            f.write(content.strip())
        return template_path
    return None

def main():
    if len(sys.argv) < 3:
        print("Uso: python3 nuclei_dynamic_forge.py <json_dir> <output_dir>")
        sys.exit(1)

    json_dir = Path(sys.argv[1])
    out_dir = Path(sys.argv[2])
    out_dir.mkdir(parents=True, exist_ok=True)

    drift_file = json_dir / "drift_delta.json"
    if not drift_file.exists():
        print("[-] Nenhum drift detectado para forjar.")
        return

    with open(drift_file, "r") as f:
        changes = json.load(f)

    templates_created = 0
    for file, diffs in changes.items():
        for d in diffs:
            if "uuid" in d.lower() or "user_id" in d.lower():
                if forge_template("idor", {"path": "/api"}, out_dir):
                    templates_created += 1

    print(f"[+] Forja Concluída: {templates_created} templates dinâmicos gerados em {out_dir}")

if __name__ == "__main__":
    main()
