import requests
import json
import os

from dotenv import load_dotenv

load_dotenv()
API_KEY = os.getenv("TRIAGE_API_KEY")
HASH_ALVO = "1d10d8f5a420d0e4683b4cb40bcf0c984d1e7ea1f3b4442a00a525584632ac11"

headers = {
    "Authorization": f"Bearer {API_KEY}",
    "Accept": "application/json"
}

def extrair_dados_triage(sha256_hash):
    # 1. Pesquisar a amostra no Triage pelo SHA256 para obter o Sample ID
    search_url = "https://tria.ge/api/v0/search"
    params = {"query": f"sha256:{sha256_hash}"}
    
    response = requests.get(search_url, headers=headers, params=params)
    
    if response.status_code != 200:
        print(f"[-] Erro na pesquisa: {response.status_code} - {response.text}")
        return None
        
    search_results = response.json().get("data", [])
    if not search_results:
        print("[-] Nenhuma amostra encontrada no Triage para este hash.")
        return None

    # Seleciona o ID da análise mais recente correspondente
    sample_id = search_results[0]["id"]
    print(f"[+] Amostra localizada! Sample ID: {sample_id}")

    # 2. Obter o relatório resumido (overview)
    overview_url = f"https://tria.ge/api/v0/samples/{sample_id}/overview.json"
    overview_resp = requests.get(overview_url, headers=headers)

    
    if overview_resp.status_code != 200:
        print(f"[-] Erro ao obter overview: {overview_resp.status_code}")
        return None

    overview_data = overview_resp.json()

    return overview_data

if __name__ == "__main__":
    dados = extrair_dados_triage(HASH_ALVO)
    if dados:
        print("\n=== CONTEXTO ESTRUTURADO PRONTO PARA PASSAR AO LLM ===")
        print(json.dumps(dados, indent=4, ensure_ascii=False))