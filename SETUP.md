# GitHub Repository Setup Anleitung

## Repository erstellen und hochladen

### 1. Neues Repository auf GitHub erstellen

1. Gehe zu https://github.com/new
2. Repository Name: `ssh-matrix`
3. Beschreibung: `SSH Matrix Server Monitoring & Terminal - A web-based SSH server management and monitoring tool`
4. Sichtbarkeit: Public (für Docker Image Build) oder Private
5. **NICHT** "Initialize this repository" auswählen
6. Klicke auf "Create repository"

### 2. Dateien hochladen (Option A: Web-Upload)

1. Entpacke die ZIP-Datei `ssh-matrix-github.zip`
2. Gehe zu deinem neuen Repository
3. Klicke auf "uploading an existing file"
4. Ziehe alle Dateien aus dem `ssh-matrix` Ordner hinein
5. Commit mit Nachricht: "Initial commit"

### 3. Dateien hochladen (Option B: Git Kommandozeile)

```bash
# Entpacke die ZIP und navigiere zum Ordner
unzip ssh-matrix-github.zip
cd ssh-matrix

# Git initialisieren
git init
git add .
git commit -m "Initial commit: SSH Matrix Server Monitoring"

# Repository verknüpfen und pushen
git remote add origin https://github.com/pjackzero1/ssh-matrix.git
git branch -M main
git push -u origin main
```

### 4. GitHub Container Registry aktivieren (für Docker Images)

Das Repository enthält einen GitHub Actions Workflow der automatisch Docker Images baut.

1. Gehe zu Repository Settings → Actions → General
2. Aktiviere "Read and write permissions" unter "Workflow permissions"
3. Speichern

Nach dem ersten Push wird automatisch ein Docker Image gebaut und unter `ghcr.io/pjackzero1/ssh-matrix:latest` verfügbar sein.

## Verwendung

### Mit Docker Compose

```bash
git clone https://github.com/pjackzero1/ssh-matrix.git
cd ssh-matrix
docker compose up -d
```

### Mit Dockge

1. Erstelle neuen Stack in Dockge
2. Name: `ssh-matrix`
3. Inhalt der `dockge-compose.yaml` einfügen:

```yaml
version: "3.8"

services:
  ssh-matrix:
    image: ghcr.io/pjackzero1/ssh-matrix:latest
    container_name: ssh-matrix
    ports:
      - "3000:3000"
    volumes:
      - ssh-matrix-data:/data
    environment:
      - NODE_ENV=production
      - PORT=3000
      - DB_DIR=/data
      - JWT_SECRET=change-this-secret-in-production-min-32-chars
    restart: unless-stopped

volumes:
  ssh-matrix-data:
```

4. Deploy klicken

### Zugriff

- URL: http://localhost:3000
- Benutzer: `admin`
- Passwort: `admin123`

**Wichtig:** Ändere das Passwort nach dem ersten Login!

## Troubleshooting

### Docker Build schlägt fehl

```bash
# Manueller Build
docker build -t ssh-matrix .

# Mit Build-Logs
docker build --progress=plain -t ssh-matrix .
```

### Container startet nicht

```bash
# Logs prüfen
docker compose logs -f

# Container neu starten
docker compose restart
```

### Datenbank zurücksetzen

```bash
# Volume löschen
docker compose down -v
docker compose up -d
```
