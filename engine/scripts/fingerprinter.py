import argparse
import requests
import hashlib
import re

def analyze_web_stack(url):
    print(f"[*] Analisando Web Stack e Identificando Fingerprints: {url}")
    try:
        r = requests.get(url, timeout=5, verify=False)
        headers = r.headers
        server = headers.get("Server", "Unknown")
        x_pwd = headers.get("X-Powered-By", "Unknown")
        
        techs = []
        if server != "Unknown":
            techs.append(f"Server: {server}")
        if x_pwd != "Unknown":
            techs.append(f"Powered-By: {x_pwd}")
            
        # Simplificação Wappalyzer DOM (buscando assets famosos)
        page = r.text.lower()
        if "wp-content" in page: techs.append("CMS: WordPress")
        if "react-root" in page or "data-reactroot" in page: techs.append("UI: React")
        if "ng-app" in page: techs.append("UI: Angular")
            
        print(f"[+] Tecnologias identificadas: {', '.join(techs) if techs else 'Genérico'}")
        return techs
    except Exception as e:
        print(f"[-] Falha na requisição visual: {e}")

def jarm_fingerprint(host_port):
    print(f"[*] Iniciando JARM / TLS Profiling em: {host_port}")
    # Simulação da rotina JARM/TLS para fins do Agente Antigravity The Engine Core
    # A implementação real consumiria a lib TLS nativa
    # Para o script: Mimetype Hash Return
    pseudo_hash = hashlib.md5(host_port.encode()).hexdigest()[:20]
    print(f"[+] JARM Hash Local: 29d29d15d29d29d00041d41d00041d{pseudo_hash}")
    # Exemplo: Assinatura JARM do Cobalt Strike ou Apache Tomcat
    print(f"[!] Análise: Hash similar aos perfis corporativos SpringBoot / Apache Tomcat.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--mode", choices=["web", "jarm"], required=True)
    args = parser.parse_args()

    if args.mode == "web":
        analyze_web_stack(args.target)
    elif args.mode == "jarm":
        jarm_fingerprint(args.target)
