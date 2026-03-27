#!/usr/bin/env python3
"""
agent_brain.py — Phase 3: The Strategic Brain
Interfaces with local Ollama to provide agentic guidance for the pipeline.
"""
import json
import sys
import requests
from pathlib import Path

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "llama3:8b"

def ask_brain(prompt, system_context="Você é um estrategista sênior de Red Team."):
    """Consulta o LLM local via Ollama."""
    try:
        payload = {
            "model": MODEL,
            "prompt": prompt,
            "system": system_context,
            "stream": False
        }
        response = requests.post(OLLAMA_URL, json=payload, timeout=30)
        if response.status_code == 200:
            return response.json().get("response", "Erro: Resposta vazia.")
        return f"Erro: Servidor Ollama retornou {response.status_code}"
    except Exception as e:
        return f"Erro: Não foi possível conectar ao Ollama. ({e})"

def analyze_target(workdir):
    """Lê o estado atual do alvo e gera um resumo para o cérebro."""
    path = Path(workdir)
    findings = {
        "ports": [],
        "vulns": 0,
        "subs": 0
    }
    
    # Simple data gathering
    ports_file = path / "naabu_ports.txt"
    if ports_file.exists():
        findings["ports"] = ports_file.read_text().splitlines()
        
    log_file = path / "nuclei" / "vulnerabilidades.txt"
    if log_file.exists():
        findings["vulns"] = len(log_file.read_text().splitlines())

    prompt = f"""
    ESTADO ATUAL DO RECON:
    - Subdomínios: {findings['subs']}
    - Portas Abertas: {findings['ports']}
    - Vulnerabilidades detectadas: {findings['vulns']}
    
    Com base nisso, qual deve ser o próximo passo tático mais agressivo? 
    Responda de forma curta e técnica.
    """
    
    return ask_brain(prompt)

def main():
    if len(sys.argv) < 2:
        print("Uso: agent_brain.py <workdir> [query]")
        sys.exit(1)

    workdir = sys.argv[1]
    
    if len(sys.argv) > 2:
        # Modo interativo/query direta
        query = " ".join(sys.argv[2:])
        print(f"\n🧠 [CÉREBRO]: {ask_brain(query)}")
    else:
        # Modo análise automática
        print(f"\n🧠 [ANÁLISE ESTRATÉGICA]:\n{analyze_target(workdir)}")

if __name__ == "__main__":
    main()
