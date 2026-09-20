# Bdlna Alpine b Slim hit Alpine makatqbelsh SleuthKit w Volatility bshoula
FROM python:3.9-slim

# Définir le dossier de travail f'west l'conteneur
WORKDIR /app

# Install system dependencies w SleuthKit w git (Hado homa jdad)
RUN apt-get update && apt-get install -y \
    sleuthkit \
    git \
    && rm -rf /var/lib/apt/lists/*

# Clone Volatility 3
RUN git clone https://github.com/volatilityfoundation/volatility3.git /opt/volatility3

# Copier l'fichier des dépendances w l'installer (Lkhdma dyalek lqdima)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir yara-python pefile capstone

# Copier l'script Python dyalna
COPY . .

# Lancer l'script (le paramètre u kay-kheli l'logs y-bano f'wa9t 7a9i9i)
CMD ["python", "-u", "worker.py"]