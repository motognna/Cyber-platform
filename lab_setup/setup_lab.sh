#!/usr/bin/env bash
# Gestioneaza laboratorul vulnerabil (container Podman): start | stop | logs | status | reset
set -euo pipefail

CONTAINER="cyber-lab"
IMAGE="cyber-lab"
SSH_PORT="${LAB_SSH_PORT:-2222}"
WEB_PORT="${LAB_WEB_PORT:-8080}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${LAB_OUT_DIR:-.}"

need_podman() {
    command -v podman >/dev/null 2>&1 || { echo "[x] podman nu este instalat (sudo dnf install podman)"; exit 1; }
}

is_running() {
    [ "$(podman inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null || echo false)" = "true" ]
}

wait_ready() {
    # Portul publicat de podman accepta conexiuni inainte ca sshd sa porneasca: verificam procesele.
    for _ in $(seq 1 40); do
        if podman exec "$CONTAINER" sh -c \
            'for n in sshd rsyslogd nginx; do grep -qx "$n" /proc/[0-9]*/comm 2>/dev/null || exit 1; done'; then
            return 0
        fi
        sleep 1
    done
    return 1
}

case "${1:-}" in
    start)
        need_podman
        if is_running; then echo "[=] Laboratorul ruleaza deja."; exit 0; fi
        podman rm -f "$CONTAINER" >/dev/null 2>&1 || true
        echo "[+] Construire imagine '$IMAGE' (prima rulare dureaza ~1 minut)..."
        podman build -q -t "$IMAGE" -f "$HERE/Containerfile" "$HERE" >/dev/null
        echo "[+] Pornire container '$CONTAINER'..."
        podman run -d --name "$CONTAINER" -p "$SSH_PORT:22" -p "$WEB_PORT:80" "$IMAGE" >/dev/null
        wait_ready || { echo "[x] Serviciile nu au pornit. Vezi: podman logs $CONTAINER"; exit 1; }
        echo "[ok] Laborator pornit:"
        echo "     SSH  : 127.0.0.1:$SSH_PORT  (user: victim / parola: password123)"
        echo "     HTTP : http://127.0.0.1:$WEB_PORT"
        ;;
    stop)
        need_podman
        podman rm -f "$CONTAINER" >/dev/null 2>&1 && echo "[ok] Laborator oprit si sters." || echo "[=] Nu rula."
        ;;
    logs)
        need_podman
        is_running || { echo "[x] Laboratorul nu ruleaza. Porneste-l: $0 start"; exit 1; }
        mkdir -p "$OUT_DIR"
        podman cp "$CONTAINER:/var/log/auth.log" "$OUT_DIR/vm_auth.log"
        podman cp "$CONTAINER:/var/log/nginx/access.log" "$OUT_DIR/vm_access.log"
        echo "[ok] Log-uri extrase: $OUT_DIR/vm_auth.log  $OUT_DIR/vm_access.log"
        ;;
    status)
        need_podman
        if is_running; then echo "[ok] Laboratorul RULEAZA (SSH :$SSH_PORT, HTTP :$WEB_PORT)"; else echo "[=] Laboratorul este oprit."; fi
        ;;
    reset)
        "$0" stop
        "$0" start
        ;;
    *)
        echo "Utilizare: $0 {start|stop|logs|status|reset}"
        exit 1
        ;;
esac
