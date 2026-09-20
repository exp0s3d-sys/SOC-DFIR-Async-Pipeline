import urllib.request
import json
import datetime

# --- CONFIGURATION CTI (Multi-Sources) ---
VT_API_KEY = ""  # add your VirusTotal API key here
OTX_API_KEY = "" # add your AlienVault OTX API key here

def interroger_virustotal(hash_value):
    print(f"[*] [CTI] Interrogation de VirusTotal pour le Hash : {hash_value}...")
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    req = urllib.request.Request(url)
    req.add_header("x-apikey", VT_API_KEY)
    
    try:
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read().decode())
            stats = data['data']['attributes']['last_analysis_stats']
            malicious = stats['malicious']
            undetected = stats['undetected']
            print(f"[+] [CTI] VT Résultat - Malveillant: {malicious}")
            return malicious, undetected
    except Exception as e:
        print(f"[-] [CTI] Erreur VirusTotal : {e}")
        return None, None

def interroger_alienvault(hash_value):
    print(f"[*] [CTI] Interrogation d'AlienVault OTX pour le Hash : {hash_value}...")
    url = f"https://otx.alienvault.com/api/v1/indicators/file/{hash_value}/general"
    req = urllib.request.Request(url)
    req.add_header("X-OTX-API-KEY", OTX_API_KEY)
    
    try:
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read().decode())
            pulse_count = data.get('pulse_info', {}).get('count', 0)
            print(f"[+] [CTI] OTX Résultat - Présent dans {pulse_count} Pulses")
            return pulse_count
    except urllib.error.HTTPError as e:
        if e.code == 404:
            print("[-] [CTI] OTX : Hash inconnu (Clean).")
            return 0
        else:
            print(f"[-] [CTI] Erreur AlienVault : {e}")
            return None
    except Exception as e:
         print(f"[-] [CTI] Erreur AlienVault : {e}")
         return None

def generer_rapport_txt(ioc_data, vt_malicious, vt_undetected, otx_pulses):
    nom_fichier = "Rapport_DFIR_Dernier.txt"
    contenu = f"""
=====================================================
    RAPPORT D'INVESTIGATION AUTOMATISÉ (PFA)
=====================================================
Date               : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Hôte / Source      : {ioc_data.get('host', 'Inconnue')}
Type d'IoC         : {ioc_data.get('IoC_Type', 'Suspicious Activity')}
Valeur analysée    : {ioc_data.get('Value', 'N/A')}
Hash analysé       : {ioc_data.get('Hash', 'Aucun Hash fourni')}
=====================================================
    ENRICHISSEMENT CTI MULTI-SOURCES
=====================================================
[1] VIRUSTOTAL :
- Antivirus détectant comme Malveillant : {vt_malicious if vt_malicious is not None else 'N/A'}
- Antivirus ne détectant rien (Sain)    : {vt_undetected if vt_undetected is not None else 'N/A'}

[2] ALIENVAULT OTX :
- Présent dans des Pulses (Menaces)   : {otx_pulses if otx_pulses is not None else 'N/A'}

=====================================================
    CONCLUSION DE LA CROISÉE DES SOURCES
=====================================================
"""
    is_mal_vt = vt_malicious is not None and vt_malicious > 0
    is_mal_otx = otx_pulses is not None and otx_pulses > 0

    if is_mal_vt and is_mal_otx:
        contenu += "CRITIQUE - Multiples sources CTI confirment un Malware actif (VT + OTX)."
    elif is_mal_vt or is_mal_otx:
        contenu += "SUSPECT - Une seule source CTI a levé une alerte. Investigation humaine requise."
    else:
        contenu += "CLEAN - Fichier non reconnu comme malveillant par l'ensemble des sources."
        
    with open(nom_fichier, 'w') as f:
        f.write(contenu)
    
    print(f"[+] [Reporting] Rapport consolidé généré : {nom_fichier}")