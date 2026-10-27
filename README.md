# 🛡️ AI Log Hunter & Tutor 🔍

> **Ecosistem educațional complet pentru securitate cibernetică (Red & Blue Team)** cu analiză euristică de telemetrie, corelare de incidente, cartografiere MITRE ATT&CK și mentor AI local (via Ollama).

---

## 📖 Despre Proiect

**AI Log Hunter & Tutor** este creat special pentru începătorii și pasionații de securitate cibernetică care doresc experiență practică (*hands-on*) în:
1. **Red Team (Atacul & Generarea de Telemetrie)**: Înțelegerea modului în care funcționează atacurile reale (SSH Brute Force, injecții SQL, Directory Traversal) și cum generează acestea urme în jurnalele de sistem (log-uri).
2. **Blue Team (Detectarea & Apărarea)**: Parsarea log-urilor reale, aplicarea de reguli euristice/RegEx, corelarea alertelor în incidente și cartografierea lor pe cadrul industrial **MITRE ATT&CK**.
3. **AI Mentor Local (Triage & Învățare)**: Trimiterea incidentelor corelate către un model LLM local (ex: `llama3.2`, `llama3`), care acționează ca un instructor de securitate senior: explică intenția atacatorului, detaliile tehnice ale protocolului și măsurile concrete de remediere (*hardening*), păstrând datele 100% private.

---

## 🏗️ Arhitectura Proiectului

```
Cyber-platform/
├── blue_team/                 # Modulul de analiză, detecție și apărare (Blue Team)
│   ├── parser.py              # Parsare log-uri: Linux auth.log și Web (Nginx/Apache)
│   ├── detector.py            # Reguli euristice + mapare MITRE ATT&CK
│   ├── aggregator.py          # Corelarea alertelor brute în incidente unice
│   └── ai_tutor.py            # Integrare Ollama cu prompt educațional structurat
├── red_team/                  # Modulul de simulare și generare trafic (Red Team)
│   ├── traffic_simulator.py   # Generator sigur de conexiuni de test (SSH & Web)
│   └── mock_logs.py           # Generator de log-uri sintetice pentru laborator offline
├── lab_setup/                 # Configurarea laboratorului vulnerabil de testare
│   ├── README_VM.md           # Ghid pas cu pas pentru mașină virtuală (Ubuntu / Metasploitable)
│   ├── Containerfile          # Container vulnerabil Podman/Docker gata în 15 secunde
│   └── setup_lab.sh           # Script de automatizare laborator containerizat
├── sample_logs/               # Log-uri reale pre-înregistrate pentru testare imediată
│   ├── auth_bruteforce.log    # Campanie SSH Brute Force & valid admin login
│   └── nginx_sqli.log         # Atacuri Web: SQL Injection, Path Traversal, Scannere
├── ui/
│   └── terminal.py            # Interfață consolă Rich (tabele, insigne, panouri, Markdown)
├── tests/
│   └── test_parser.py         # Teste automate unitare
├── main.py                    # Punctul central de intrare în linie de comandă (CLI)
├── requirements.txt           # Dependențe Python (rich, requests)
└── README.md                  # Documentație completă a proiectului
```

---

## 🚀 Pornire Rapidă (Quickstart)

### 1. Clonare și configurare mediu Python
```bash
git clone https://github.com/motognna/Cyber-platform.git
cd Cyber-platform

# Creare mediu virtual și instalare dependențe
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Verificare Ollama (AI Local)
Asigură-te că serviciul Ollama rulează pe mașina ta și că ai modelul descărcat:
```bash
# Verifică din utilitar
python main.py --check-ollama

# Dacă nu ai modelul descărcat:
ollama pull llama3.2
```

---

## 🎯 Exemple de Utilizare

### 1. Analiza unui atac SSH Brute Force cu AI Tutor
```bash
python main.py --log sample_logs/auth_bruteforce.log --model llama3.2
```
*Ce se întâmplă*: Utilitarul parsează log-ul, identifică 9 încercări de autentificare eșuate de la același IP, le grupează într-un singur incident critic, iar Ollama generează o lecție completă de securitate și comenzi de hardening.

### 2. Analiza unui log de server Web (SQL Injection & Path Traversal)
```bash
python main.py --log sample_logs/nginx_sqli.log --model llama3.2
```

### 3. Analiză rapidă fără AI (doar euristici & tabele)
```bash
python main.py --log sample_logs/auth_bruteforce.log --skip-ai
```

### 4. Salvare raport complet în format Markdown
```bash
python main.py --log sample_logs/auth_bruteforce.log --export raport_securitate.md
```

### 5. Generare log-uri sintetice de test
```bash
python main.py --generate-mock test_ssh.log --type auth
```

---

## 🧪 Laboratorul de Testare (Hands-on Lab)

Pentru a testa fluxul complet atac-apărare:

### Opțiunea A: Laborator rapid cu Podman (Recomandat)
1. **Pornește laboratorul**:
   ```bash
   ./lab_setup/setup_lab.sh start
   ```
2. **Lansează atacul simulat de test**:
   ```bash
   python main.py --simulate ssh --target 127.0.0.1 --port 2222
   ```
3. **Extrage log-ul generat din laborator**:
   ```bash
   ./lab_setup/setup_lab.sh logs
   ```
4. **Triage și analiză AI**:
   ```bash
   python main.py --log vm_auth.log --model llama3.2
   ```
5. **Oprește laboratorul**:
   ```bash
   ./lab_setup/setup_lab.sh stop
   ```

### Opțiunea B: Mașină Virtuală Completă (VM)
Urmărește instrucțiunile detaliate din [`lab_setup/README_VM.md`](lab_setup/README_VM.md) pentru configurarea unei mașini virtuale Ubuntu Server sau Metasploitable prin VirtualBox sau KVM/virt-manager.

---

## 🧠 Structura Răspunsului AI Tutor

Pentru fiecare incident, mentorul AI este instruit să răspundă conform unui șablon didactic strict:
1. **🏷️ 1. Clasificare și Cadrul MITRE ATT&CK**: Numele atacului, ID-ul oficial MITRE și severitatea.
2. **🎯 2. Ce a încercat atacatorul să facă?**: Explicație intuitivă pe înțelesul unui analist junior.
3. **⚙️ 3. Mecanismul Tehnic**: Ce s-a întâmplat la nivel de protocol (handshake SSH, query SQL, etc.) și de ce a apărut acea linie în log.
4. **🛡️ 4. Soluții de Remediere (Hardening)**: Comenzi practice de configurare (`sshd_config`, `fail2ban`, `firewalld`, Prepared Statements).
5. **💡 5. Provocare Practică**: O întrebare de reflecție sau gândire critică pentru student.

---

## 🧪 Rularea Testelor Automate

Proiectul include o suită completă de teste unitare:
```bash
python -m unittest discover tests
```

---

## 📄 Licență
Open-source sub licența MIT. Creat în scopuri educaționale pentru formarea viitorilor specialiști în securitate cibernetică.