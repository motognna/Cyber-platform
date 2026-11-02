# AI Log Hunter & Tutor

Utilitar CLI educațional de securitate cibernetică: analizează log-uri reale (SSH `auth.log`, `access.log` Nginx/Apache), detectează atacuri cu reguli euristice, le corelează în **incidente** mapate pe **MITRE ATT&CK** și cere unui **model AI local (Ollama)** să le explice pe înțelesul unui începător. Datele nu părăsesc calculatorul tău.

Include și un laborator (container Podman) pe care îl poți ataca singur ca să generezi log-uri reale: **Red Team → log-uri → Blue Team**.

## Ce detectează

| Atac | MITRE | Sursă log |
|---|---|---|
| SSH brute force / enumerare utilizatori | T1110.001 | auth.log |
| **Login reușit după brute force (posibilă compromitere)** — severitate CRITICAL | T1078 | auth.log |
| SQL Injection (UNION, tautologii, blind/time-based, `;DROP`…) | T1190 | access.log |
| Path Traversal (`../`, `%2e%2e%2f`, dublu-encodat) — CRITICAL dacă răspunsul e 2xx | T1083 | access.log |
| Command / Code injection (shell, Log4Shell, Shellshock) | T1059 | access.log (URL + headere) |
| XSS | T1189 | access.log |
| Scannere (sqlmap, Nikto, nmap, gobuster…) | T1595.002 | access.log |
| Căutare `.env`, `.git`, backup-uri, phpMyAdmin | T1595.003 | access.log |

Alertele de la aceeași sursă se grupează într-un singur incident (nu 500 de apeluri AI pentru 500 de încercări). Traficul legitim nu declanșează alerte (acoperit de teste).

## Instalare (Fedora)

```bash
git clone <repo> && cd Cyber-platform
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

# AI local
ollama serve &            # dacă nu rulează deja ca serviciu
ollama pull llama3.2      # sau un model mai capabil, ex: qwen2.5:7b
```

## Pornire rapidă (fără laborator)

```bash
.venv/bin/python main.py --check-ollama
.venv/bin/python main.py --log sample_logs/auth_bruteforce.log
.venv/bin/python main.py --log sample_logs/auth_compromise.log --export raport.md
.venv/bin/python main.py --log sample_logs/nginx_sqli.log --model llama3.2
.venv/bin/python main.py --log sample_logs/nginx_sqli.log --skip-ai      # fără AI, instant
```

Răspunsul AI apare **live** (streaming) și respectă structura: *Tip Atac → Ce a încercat atacatorul → Explicație Tehnică → Soluție de Remediere → Provocare*. Dacă modelul nu respectă structura, se reîncearcă automat o dată.

## Laboratorul Red Team ⚔️ vs Blue Team 🛡️

Necesită `podman` (preinstalat pe Fedora). Primul `start` descarcă imaginea Ubuntu (~30 MB) și construiește containerul (~1 min).

```bash
./lab_setup/setup_lab.sh start                                   # SSH :2222, HTTP :8080
.venv/bin/python main.py --simulate ssh --port 2222 --with-valid-login   # brute force REAL (paramiko)
.venv/bin/python main.py --simulate web --port 8080              # atacuri web (SQLi, traversal, XSS...)
./lab_setup/setup_lab.sh logs                                    # -> vm_auth.log + vm_access.log
.venv/bin/python main.py --log vm_auth.log                       # Blue Team + AI Tutor
.venv/bin/python main.py --log vm_access.log
./lab_setup/setup_lab.sh stop
```

> **Siguranță:** simulatorul refuză orice țintă care nu e loopback / rețea privată (RFC 1918). Container-ul are parole slabe intenționat — **nu îl expune în rețea publică**. Rulează doar pe sisteme proprii.

Pentru o mașină virtuală completă (Ubuntu Server / Metasploitable): [lab_setup/README_VM.md](lab_setup/README_VM.md).

## Toate opțiunile

```
--log FISIER          log de analizat (autodetectie auth/web; forțează cu --type auth|web)
--model MODEL         model Ollama (implicit llama3.2 sau $LOGHUNTER_MODEL)
--skip-ai             doar detecție
--ai-top N            explică prin AI doar primele N incidente (implicit 5; 0 = toate)
--threshold N         nr. minim de eșecuri SSH pentru brute force (implicit 3)
--export RAPORT.md    salvează raport Markdown (sumar + dovezi + analiză AI)
--simulate ssh|web    generează trafic de atac către o țintă de laborator (--target, --port)
--generate-mock FILE  log sintetic offline (--type auth|web, --compromise)
--check-ollama        verifică Ollama și listează modelele
```

Coduri de ieșire: `0` ok, `1` eroare (fișier lipsă / fără permisiuni / format nerecunoscut / țintă nepermisă), `130` Ctrl-C.

Erori tratate: Ollama oprit (analiza continuă fără AI), model neinstalat (mesaj cu `ollama pull`), timeout, răspuns gol, fișier lipsă/director/fără permisiuni, fișiere goale sau binare.

Pe Fedora nu există `/var/log/auth.log`: loghează în journald / `/var/log/secure`. Exportă cu `sudo journalctl -u sshd --no-pager -o short > sshd.log` (format syslog compatibil) sau citește `/var/log/secure` cu `sudo`.

## Arhitectură

```
blue_team/  catalog.py (MITRE + măsuri defensive) · parser.py · detector.py · aggregator.py · ai_tutor.py
red_team/   traffic_simulator.py (SSH real + HTTP, doar ținte private) · mock_logs.py
lab_setup/  Containerfile · entrypoint.sh · setup_lab.sh · README_VM.md
ui/         terminal.py (Rich: tabele, streaming live, raport .md)
tests/      test_parser.py · test_integration.py (server Ollama fals, CLI cap-coadă)
sample_logs/ auth_bruteforce.log · auth_compromise.log · nginx_sqli.log
```

**Securitatea prompt-ului:** liniile de log sunt controlate de atacator, deci sunt trunchiate, sanitizate și trimise ca date nefiabile (cu instrucțiune explicită în system prompt de a nu urma comenzi din ele) — protecție împotriva *prompt injection* prin log-uri.

## Teste

```bash
.venv/bin/python -m unittest discover tests -v      # 46 teste
```

## Idei de continuare

Urmărire în timp real (`tail -f`) · parser pentru journald/Windows Event Log · bază SQLite de incidente · blocare automată IP (fail2ban/firewalld) · mod chat cu tutorul + evaluarea răspunsurilor tale · dashboard web.