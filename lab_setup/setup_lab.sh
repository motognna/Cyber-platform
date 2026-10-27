#!/usr/bin/env bash
set -e

# Automation script for the Podman lab container
CONTAINER_NAME="cyber-lab"
IMAGE_NAME="cyber-lab"

case "$1" in
    start)
        echo "[+] Construire imagine Podman '$IMAGE_NAME'..."
        podman build -t "$IMAGE_NAME" -f "$(dirname "$0")/Containerfile"
        echo "[+] Pornire container '$CONTAINER_NAME'..."
        podman run -d --rm --name "$CONTAINER_NAME" -p 2222:22 -p 8080:80 "$IMAGE_NAME"
        echo "[✓] Laboratorul ruleaza!"
        echo "    - SSH: 127.0.0.1:2222 (user: victim, pass: password123)"
        echo "    - HTTP: http://127.0.0.1:8080"
        ;;
    stop)
        echo "[*] Oprire container '$CONTAINER_NAME'..."
        podman stop "$CONTAINER_NAME" 2>/dev/null || true
        echo "[✓] Laborator oprit."
        ;;
    logs)
        echo "[*] Extragere /var/log/auth.log din container catre ./vm_auth.log..."
        podman cp "$CONTAINER_NAME":/var/log/auth.log ./vm_auth.log
        echo "[✓] Log salvat la ./vm_auth.log"
        ;;
    *)
        echo "Utilizare: $0 {start|stop|logs}"
        exit 1
        ;;
esac
