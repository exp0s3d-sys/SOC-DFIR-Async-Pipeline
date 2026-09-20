import sys
import json
import urllib.request

# 1. Splunk kay-sift l'smiya dyal l'Alerte f'l'Argument ra9em 4
alert_name = sys.argv[4] if len(sys.argv) > 4 else "Menace_Inconnue"

# 2. L'Payload li ghadi n-siftou l'l'API dyalna (DFIR Triage)
ioc_data = {
    "source": "Splunk_SIEM",
    "alerte": alert_name,
    "action": "Lancer_Triage_Memoire",
    "status": "Critique"
}

# 3. L'Format l'me9boul 3nd l'API HTTP dyal RabbitMQ
rabbitmq_payload = {
    "properties": {},
    "routing_key": "alertes_splunk",
    "payload": json.dumps(ioc_data),
    "payload_encoding": "string"
}

# 4. Connexion m3a RabbitMQ (host.docker.internal kat-kheli Splunk y-chouf RabbitMQ)
url = "http://192.168.1.18:15672/api/exchanges/%2f/amq.default/publish"
req = urllib.request.Request(url)
req.add_header("Content-Type", "application/json")
req.add_header("Authorization", "Basic Z3Vlc3Q6Z3Vlc3Q=") # Hadi hiya guest:guest b'Base64

# 5. L'Envoi
try:
    urllib.request.urlopen(req, data=json.dumps(rabbitmq_payload).encode('utf-8'))
except Exception as e:
    print(f"Erreur d'envoi à RabbitMQ: {e}")