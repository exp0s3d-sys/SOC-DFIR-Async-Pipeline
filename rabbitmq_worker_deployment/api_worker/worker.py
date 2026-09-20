import pika
import time
import json
import threading
import base64
from datetime import datetime
import cti_enrichment 
from flask import Flask, request

app = Flask(__name__)

# ==========================================
# 1. WEBHOOK RECEIVER (SPLUNK -> RABBITMQ)
# ==========================================
@app.route('/webhook', methods=['POST'])
def splunk_webhook():
    try:
        payload = request.json
        ioc_data = payload.get('result', payload)
        
        connection = pika.BlockingConnection(pika.ConnectionParameters(host='rabbitmq'))
        channel = connection.channel()
        channel.queue_declare(queue='alertes_splunk')
        channel.basic_publish(exchange='', routing_key='alertes_splunk', body=json.dumps(ioc_data))
        connection.close()
        return "Alert sent to RabbitMQ", 200
    except Exception as e:
        return str(e), 500

# ==========================================
# 2. GENERATION DU RAPPORT COMPLET SOC N3
# ==========================================
def generer_rapport_soc_complet(ioc_data, vt_malicious, otx_pulses):
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    incident_id = f"INC-0xESec-{datetime.now().strftime('%Y%m%d%H%M')}"
    report_path = f"/evidence/Rapport_SOC_FullDetails_{timestamp}.txt"
    
    hash_val = ioc_data.get('Hash', 'Non fourni')
    image_path = ioc_data.get('Image', 'Non fourni')
    process_name = image_path.split('\\')[-1] if '\\' in image_path else image_path
    parent_image = ioc_data.get('ParentImage', 'Non fourni')
    command_line = ioc_data.get('CommandLine', 'Non fourni')
    user = ioc_data.get('User', 'Système/Non fourni')
    event_code = ioc_data.get('EventCode', 'Inconnu')
    target_filename = ioc_data.get('TargetFilename', 'Non applicable')
    
    # --- DECODAGE BASE64 POWERSHELL ---
    decoded_script = "Aucune commande encodée détectée."
    if command_line and "-EncodedCommand" in command_line:
        try:
            b64_str = command_line.split("-EncodedCommand")[1].strip().split()[0]
            decoded_bytes = base64.b64decode(b64_str)
            decoded_script = decoded_bytes.decode('utf-16-le')
        except Exception as e:
            decoded_script = f"Erreur de décodage: {str(e)}"
    
    # --- MOTEUR D'ANALYSE D'IMPACT ET MITRE ATT&CK ---
    severity = "MOYENNE"
    mitre_tactics = []
    impact_analysis = ""
    
    process_lower = process_name.lower() if process_name else ""
    cmd_lower = command_line.lower() if command_line else ""
    target_lower = target_filename.lower() if target_filename != 'Non applicable' else ""
    
    if "powershell" in process_lower or "cmd" in process_lower:
        mitre_tactics.append("TA0002 - Execution (T1059 Command and Scripting Interpreter)")
        if "-enc" in cmd_lower or "hidden" in cmd_lower:
            severity = "CRITIQUE"
            mitre_tactics.append("TA0005 - Defense Evasion (T1027 Obfuscated Files or Information)")
            impact_analysis = "MECANISME D'EVASION DETECTE: Le processus utilise des arguments furtifs (Hidden) et/ou un encodage Base64 pour contourner les mécanismes de détection en clair (Antivirus/EDR). Cela indique une tentative d'exécution d'un script malveillant (payload) directement en mémoire."
        else:
            impact_analysis = "EXÉCUTION DE SCRIPT: Un interpréteur de commandes système a été lancé. Vérifiez la commande exacte pour identifier s'il s'agit d'une activité légitime ou d'un LOLBin."
            
    elif str(event_code) == "11" or "temp" in cmd_lower or "appdata" in cmd_lower or "temp" in process_lower or "appdata" in target_lower:
        severity = "HAUTE"
        mitre_tactics.append("TA0002 - Execution (T1204 User Execution)")
        mitre_tactics.append("TA0005 - Defense Evasion (T1036 Masquerading)")
        impact_analysis = f"COMPORTEMENT DE DROPPER/STAGER: Création ou exécution d'un fichier suspect ({target_filename if target_filename != 'Non applicable' else image_path}). C'est une signature classique d'infection initiale où un fichier parent télécharge ou extrait un malware dans un dossier utilisateur."

    elif str(event_code) == "3" or "curl" in cmd_lower or "wget" in cmd_lower:
        mitre_tactics.append("TA0011 - Command and Control (T1105 Ingress Tool Transfer)")
        impact_analysis = "ACTIVITÉ RÉSEAU ANORMALE: Le processus a initié une connexion sortante ou un transfert de fichiers. L'attaquant télécharge probablement des outils secondaires (mouvement latéral, exfiltration) ou communique avec un serveur Command & Control (C2)."
        
    else:
        impact_analysis = "COMPORTEMENT SUSPECT IDENTIFIÉ: Le processus a généré une alerte basée sur une anomalie comportementale. Une analyse forensique de la mémoire et du registre est requise."

    if not mitre_tactics:
        mitre_tactics.append("TA0040 - Impact (Technique générique ou non cartographiée)")
        
    mitre_str = "\n".join([f"  -> {t}" for t in mitre_tactics])

    # --- HINTS DFIR ---
    hint_ram = ""
    hint_disk = ""
    if severity == "CRITIQUE" or "powershell" in process_lower:
        hint_ram = f"Utilisez Volatility ('windows.cmdline' et 'windows.envars') sur le PID cible pour extraire les scripts décodés et les variables d'environnement injectées."
        hint_disk = f"Extrayez 'ConsoleHost_history.txt' (%APPDATA%\\Microsoft\\Windows\\PowerShell\\PSReadLine\\) pour voir l'historique des commandes tapées."
    elif severity == "HAUTE":
        hint_ram = f"Utilisez 'windows.malfind' et 'windows.ldrmodules' pour identifier du code injecté (VAD tags PAGE_EXECUTE_READWRITE) par '{process_name}'."
        hint_disk = f"Le binaire a touché le disque. Analysez la Master File Table (MFT) et le journal USN pour dater précisément le moment de la création et du dépôt du malware."
    else:
        hint_ram = f"Utilisez 'windows.pstree' et 'windows.netscan' pour dresser l'arbre généalogique complet et les connexions réseau actives."
        hint_disk = f"Vérifiez les ruches NTUSER.DAT et SOFTWARE pour des modifications de clés 'Run' ou 'RunOnce' (Persistance)."

    # --- ECRITURE DU RAPPORT ---
    with open(report_path, "w", encoding='utf-8') as f:
        f.write("*" * 85 + "\n")
        f.write(f"  RAPPORT D'ANALYSE D'INCIDENT SOC (TIER 3) - {incident_id}  \n")
        f.write("*" * 85 + "\n\n")
        
        f.write(f"DATE ET HEURE      : {timestamp}\n")
        f.write(f"NIVEAU DE GRAVITE  : [{severity}]\n")
        f.write(f"MACHINE / UTILISATEUR : {user}\n\n")
        
        f.write("=====================================================================================\n")
        f.write("[1] RESUME EXECUTIF DE L'INCIDENT\n")
        f.write("=====================================================================================\n")
        f.write(f"Le système d'alerte (Sysmon/Splunk) a intercepté un événement suspect.\n")
        f.write("L'analyse automatisée démontre que des techniques potentiellement malveillantes ont été employées.\n\n")

        f.write("=====================================================================================\n")
        f.write("[2] CARTOGRAPHIE MITRE ATT&CK\n")
        f.write("=====================================================================================\n")
        f.write(f"{mitre_str}\n\n")

        f.write("=====================================================================================\n")
        f.write("[3] GENEALOGIE ET CONTEXTE TECHNIQUE\n")
        f.write("=====================================================================================\n")
        f.write(f"Processus Suspect    : {image_path}\n")
        f.write(f"Processus Parent     : {parent_image}\n")
        f.write(f"Ligne de commande    : {command_line}\n")
        f.write(f"Event ID Déclenché   : {event_code}\n")
        if target_filename != 'Non applicable':
            f.write(f"Fichier Cible (Créé) : {target_filename}\n")
        f.write("\n")

        f.write("=====================================================================================\n")
        f.write("[4] ANALYSE D'IMPACT DETAILLEE (CE QUI S'EST REELLEMENT PASSE)\n")
        f.write("=====================================================================================\n")
        f.write(f"{impact_analysis}\n\n")
        
        if decoded_script != "Aucune commande encodée détectée.":
            f.write(f"[*] DE-OBFUSCATION REUSSIE (Base64) :\n")
            f.write(f"Le script caché tentait d'exécuter :\n{decoded_script}\n\n")

        f.write("=====================================================================================\n")
        f.write("[5] INTELLIGENCE SUR LES MENACES (INDICATEURS DE COMPROMISSION)\n")
        f.write("=====================================================================================\n")
        f.write(f"Hash Associé (SHA256/MD5) : {hash_val}\n")
        f.write(f"[-] VirusTotal Score      : {vt_malicious}/72\n")
        f.write(f"[-] AlienVault OTX Pulses : {otx_pulses}\n\n")

        f.write("=====================================================================================\n")
        f.write("[6] DIRECTIVES D'INVESTIGATION FORENSIQUE (DFIR)\n")
        f.write("=====================================================================================\n")
        f.write("Le conteneur DFIR automatisé ou l'analyste N3 doit exécuter les actions suivantes :\n\n")
        f.write(f"[*] SUR LA MEMOIRE VIVE (RAM) :\n    -> {hint_ram}\n\n")
        f.write(f"[*] SUR LE DISQUE DUR (Artifacts) :\n    -> {hint_disk}\n\n")
        
        f.write("=====================================================================================\n")
        f.write("[7] ACTIONS DE CONFINEMENT IMMEDIATES\n")
        f.write("=====================================================================================\n")
        
        poste_isole = user.split('\\')[0] if '\\' in user else user
        
        f.write(f"1. Isoler le poste '{poste_isole}' du réseau local.\n")
        f.write(f"2. Terminer l'arborescence du processus '{process_name}' via la console de l'EDR.\n")
        f.write(f"3. Réaliser une capture complète de la RAM (.raw/.mem) et l'envoyer dans le dossier /evidence.\n")
        f.write(f"4. Bloquer le hash '{hash_val}' sur l'ensemble du parc informatique.\n")
            
    print(f"[+] Rapport SOC Full Details généré avec succès f: {report_path}")

# ==========================================
# 3. WORKER CTI (RABBITMQ -> RAPPORT COMPLET)
# ==========================================
def start_worker():
    print("[*] Démarrage de l'API SOC Asynchrone (Filtrage Actif: Hash + Comportement)...")
    def connect_to_rabbitmq():
        retries = 5
        while retries > 0:
            try:
                return pika.BlockingConnection(pika.ConnectionParameters(host='rabbitmq'))
            except:
                retries -= 1
                time.sleep(5)
        raise Exception("Impossible de se connecter.")

    try:
        connection = connect_to_rabbitmq()
        channel = connection.channel()
        channel.queue_declare(queue='alertes_splunk')

        def callback(ch, method, properties, body):
            try:
                alerte = body.decode()
                ioc_data = json.loads(alerte)
                
                # Récupération sécurisée des variables
                hash_candidat = ioc_data.get("Hash", "")
                cmd_line = str(ioc_data.get("CommandLine", "")).lower()
                image_path = str(ioc_data.get("Image", "")).lower()
                target_file = str(ioc_data.get("TargetFilename", "")).lower()
                
                vt_malicious = 0
                otx_pulses = "0 (Bypass temporaire)"
                
                # 1. Analyse CTI (Si Sysmon a fourni un Hash)
                if hash_candidat and hash_candidat != "Non fourni":
                    resultat_vt = cti_enrichment.interroger_virustotal(hash_candidat)
                    # Sécurisation contre le "None" de l'erreur 429
                    if resultat_vt and resultat_vt[0] is not None:
                        vt_malicious = int(resultat_vt[0])
                    else:
                        vt_malicious = 0
                        print(f"[-] Limite API VirusTotal atteinte ou Hash introuvable. Score forcé à 0.")
                
                # 2. Analyse Comportementale Locale (Le cerveau de l'API)
                comportement_suspect = False
                
                # Détection d'évasion (LOLBins)
                if "-enc" in cmd_line or "hidden" in cmd_line or "bypass" in cmd_line:
                    comportement_suspect = True
                
                # Détection de Dropper/Stager (Écriture dans des dossiers sensibles)
                if "appdata" in image_path or "temp" in image_path or "appdata" in target_file or "temp" in target_file:
                    comportement_suspect = True
                    
                # 3. Décision Finale (Hybride)
                if int(vt_malicious) > 0 or comportement_suspect:
                    print(f"\n[!] Menace détectée ! (Score VT: {vt_malicious}/72 | Comportement suspect: {comportement_suspect})")
                    generer_rapport_soc_complet(ioc_data, vt_malicious, otx_pulses)
                else:
                    print(f"[-] Fichier propre (Score VT: {vt_malicious}) et comportement normal. Ignoré.")
                    
            except Exception as e:
                print(f"[-] Erreur Worker : {e}")

        channel.basic_consume(queue='alertes_splunk', on_message_callback=callback, auto_ack=True)
        channel.start_consuming()
    except Exception as e:
        pass

if __name__ == '__main__':
    worker_thread = threading.Thread(target=start_worker, daemon=True)
    worker_thread.start()
    app.run(host='0.0.0.0', port=5000)