>import argparse
import os
import requests
from dotenv import load_dotenv

load_dotenv()

def check_virustotal(ip_address):
    api_key = os.getenv("VT_API_KEY")
    if not api_key or api_key == "TWOJ_KLUCZ":
        print("[-] Błąd: Brak poprawnego klucza API w pliku .env")
        return

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }

    print(f"[*] Łączę się z API VirusTotal dla adresu: {ip_address}...")
    
    try:
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            country = data['data']['attributes'].get('country', 'Brak danych')
            as_owner = data['data']['attributes'].get('as_owner', 'Brak danych')
            
            print("\n**Raport IoC: Analiza adresu IP**")
            print("| Wskaźnik | Złośliwe | Podejrzane | Kraj | Właściciel (ASN) |")
            print("|:---:|:---:|:---:|:---:|:---:|")
            print(f"| `{ip_address}` | **{malicious}** | **{suspicious}** | {country} | {as_owner} |\n")
        else:
            print(f"[-] Błąd API. Kod HTTP: {response.status_code}")
    except Exception as e:
        print(f"[-] Błąd połączenia: {e}")

def check_hash(file_hash):
    api_key = os.getenv("VT_API_KEY")
    if not api_key or api_key == "TWOJ_KLUCZ":
        print("[-] Błąd: Brak poprawnego klucza API w pliku .env")
        return

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }

    print(f"[*] Łączę się z API VirusTotal dla hasza: {file_hash}...")
    
    try:
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            names = data['data']['attributes'].get('names', [])
            file_name = names[0] if names else "Brak znanej nazwy"
            
            print("\n**Raport IoC: Analiza pliku (Hash)**")
            print("| Hash (skrócony) | Złośliwe | Podejrzane | Najpopularniejsza nazwa |")
            print("|:---:|:---:|:---:|:---:|")
            print(f"| `{file_hash[:10]}...` | **{malicious}** | **{suspicious}** | {file_name} |\n")
            
        elif response.status_code == 404:
            print("[-] Baza VirusTotal nie zna tego pliku. Może to być unikalne zagrożenie (Zero-Day) lub bezpieczny, wewnętrzny plik.")
        else:
            print(f"[-] Błąd API. Kod HTTP: {response.status_code}")
    except Exception as e:
        print(f"[-] Błąd połączenia: {e}")

def main():
    parser = argparse.ArgumentParser(description="Narzędzie SOC: IoC Auto-Enricher")
    parser.add_argument("-i", "--ip", help="Adres IP do sprawdzenia")
    parser.add_argument("-H", "--hash", help="Hash pliku (MD5/SHA1/SHA256) do sprawdzenia")
    args = parser.parse_args()

    if args.ip:
        check_virustotal(args.ip)
    elif args.hash:
        check_hash(args.hash)
    else:
        print("[-] Błąd: Użyj flagi -i (IP) lub -H (Hash).")

if __name__ == "__main__":
    main()
