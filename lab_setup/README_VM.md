# Ghid de Configurare a Mediului de Laborator (VM & Podman)

Acest document explică pas cu pas cum să configurezi un mediu de testare sigur și controlat pentru generarea și colectarea log-urilor de securitate.

---

## Opțiunea 1: Laborator Rapid cu Podman (Recomandat pe Fedora - 1 minut)

Fedora vine cu `podman` preinstalat. Nu este nevoie să descarci imagini ISO de 4 GB pentru o mașină virtuală.

### 1. Construiește imaginea de container
Din rădăcina proiectului:
```bash
podman build -t cyber-lab -f lab_setup/Containerfile
```

### 2. Pornește containerul de laborator
Containerul expune serviciul SSH pe portul `2222` și un mini-server web pe portul `8080`:
```bash
podman run -d --name cyber-lab -p 2222:22 -p 8080:80 cyber-lab
```

### 3. Testează cu simulatorul integrat Red Team
Din sistemul gazdă:
```bash
.venv/bin/python main.py --simulate ssh --target 127.0.0.1 --port 2222
```

### 4. Extrage log-ul generat din container
```bash
podman cp cyber-lab:/var/log/auth.log ./vm_auth.log
```

### 5. Analizează log-ul cu Blue Team & Ollama
```bash
.venv/bin/python main.py --log vm_auth.log --model llama3.2
```

---

## Opțiunea 2: Mașină Virtuală Completă (Ubuntu Server sau Metasploitable)

Dacă dorești o experiență clasică de hypervisor (VirtualBox, virt-manager / KVM, VMware):

### 1. Descărcare și Instalare
- Descarcă **Ubuntu Server 24.04 / 22.04 LTS** (sau **Metasploitable 2** pentru un mediu intenționat vulnerabil).
- În setările de rețea ale VM-ului, alege **Host-Only Adapter** (sau **Bridge Adapter**) pentru ca VM-ul să aibă o adresă IP privată din aceeași rețea cu gazda Fedora (ex: `192.168.56.101`).
- *Atenție*: Evită modul NAT simplu dacă dorești să inițiezi conexiuni directe de la gazdă către VM fără port forwarding.

### 2. Instalare și Activare SSH pe VM
Conectează-te la consola VM-ului și rulează:
```bash
sudo apt update
sudo apt install -y openssh-server rsyslog
sudo systemctl enable --now ssh
sudo systemctl enable --now rsyslog
```

### 3. Aflarea Adresei IP a VM-ului
Pe VM:
```bash
ip addr show
# Notam IP-ul interfetei de retea (ex: 192.168.56.101)
```

### 4. Generarea Traficului de Test către VM
De pe mașina gazdă (Fedora):
```bash
# Simulează autentificări eșuate către VM
.venv/bin/python main.py --simulate ssh --target 192.168.56.101 --port 22
```

### 5. Preluarea Log-ului din VM pe Fedora
Ai două variante simple:

#### Varianta A: Copiere directă prin SCP
```bash
scp user_vm@192.168.56.101:/var/log/auth.log ./vm_auth.log
```

#### Varianta B: Syslog Forwarding (Timp Real - Avansat)
Pe VM, adaugă în `/etc/rsyslog.conf`:
```
*.*  @192.168.56.1:514
```
(Unde `192.168.56.1` este adresa IP a interfeței Host-Only de pe Fedora).

---

## Opțiunea 3: Testare Imediată cu Log-uri Mock (Offline)

Dacă dorești să testezi doar motorul Blue Team și explicațiile AI fără a porni niciun container sau VM:
```bash
# Folosește log-urile demonstrative incluse
.venv/bin/python main.py --log sample_logs/auth_bruteforce.log
.venv/bin/python main.py --log sample_logs/nginx_sqli.log

# Sau generează propriile tale log-uri sintetice
.venv/bin/python main.py --generate-mock test_custom.log --type auth
```
