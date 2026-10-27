"""Ollama AI Tutor integration: Enforces educational, structured cybersecurity explanations."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional
import requests

from blue_team.aggregator import SecurityIncident


DEFAULT_OLLAMA_URL = "http://localhost:11434"
DEFAULT_MODEL = "llama3.2"

SYSTEM_PROMPT = """Ești un Senior Cybersecurity Instructor și Threat Hunting Mentor (expert Red & Blue Team).
Misiunea ta este să instruiești un analist de securitate aflat la început de drum, analizând log-urile și incidentele identificate de sistem.

Răspunde ÎNTOTDEAUNA în limba română, păstrând o structură clară, didactică și direct aplicabilă, folosind exact următoarele secțiuni Markdown:

### 🏷️ 1. Clasificare și Cadrul MITRE ATT&CK
- **Nume Atac**: [Numele complet]
- **Cod MITRE**: [Tehnica și Tactica, ex: T1110.001 - Password Guessing]
- **Nivel de Risc**: [Scăzut / Mediu / Ridicat / Critic]

### 🎯 2. Ce a încercat atacatorul să facă?
[Explică pe scurt, într-un limbaj simplu și intuitiv, ce intenții a avut atacatorul și ce urmărea să obțină.]

### ⚙️ 3. Mecanismul Tehnic (De ce arată așa în log?)
[Explică mecanismul tehnic precis al protocolului sau vulnerabilității (de exemplu: handshake SSH, conexiuni pe portul 22, injectare de token-uri SQL, coduri HTTP de stare). Explică ce înseamnă cuvintele cheie din liniile de log furnizate.]

### 🛡️ 4. Cum securizăm sistemul? (Hardening & Blue Team Defense)
[Oferă măsuri concrete, inclusiv comenzi Linux sau reguli de configurare gata de aplicat, de exemplu:
- Reguli de firewall / Fail2ban
- Configurări sigure în /etc/ssh/sshd_config (ex: dezactivare login root, doar chei SSH)
- Practici de codare securizată (ex: Prepared Statements pentru SQLi)]

### 💡 5. Provocare pentru tine (Întrebare de verificare)
[Formulează o scurtă întrebare sau un scenariu practic de gândire critică pentru student, legat de acest incident.]
"""


class OllamaClient:
    """Client for local Ollama API server with health-checking and educational prompting."""

    def __init__(self, base_url: str = DEFAULT_OLLAMA_URL, model: str = DEFAULT_MODEL):
        self.base_url = base_url.rstrip("/")
        self.model = model

    def check_connection(self) -> Dict[str, Any]:
        """Verify that Ollama daemon is reachable and retrieve list of available models."""
        try:
            resp = requests.get(f"{self.base_url}/api/tags", timeout=3)
            if resp.status_code == 200:
                data = resp.json()
                models = [m.get("name") for m in data.get("models", [])]
                return {
                    "online": True,
                    "models": models,
                    "error": None
                }
            return {
                "online": False,
                "models": [],
                "error": f"Ollama a raspuns cu codul HTTP {resp.status_code}"
            }
        except requests.exceptions.ConnectionError:
            return {
                "online": False,
                "models": [],
                "error": (
                    "Nu s-a putut realiza conexiunea la Ollama (http://localhost:11434).\n"
                    "Verifica daca serviciul ruleaza folosind comanda: 'ollama serve' sau 'systemctl start ollama'."
                )
            }
        except Exception as exc:
            return {
                "online": False,
                "models": [],
                "error": f"Eroare neasteptata la verificarea Ollama: {exc}"
            }

    def resolve_model(self, requested_model: Optional[str] = None) -> str:
        """Resolve a suitable model name, falling back to installed models if necessary."""
        health = self.check_connection()
        if not health["online"]:
            return requested_model or self.model

        available = health["models"]
        if not available:
            return requested_model or self.model

        target = requested_model or self.model

        # 1. Exact match
        if target in available:
            return target

        # 2. Match without tag (e.g. 'llama3.2' -> 'llama3.2:latest')
        for m in available:
            if m.startswith(f"{target}:"):
                return m

        # 3. Match base family (e.g. 'llama3' -> 'llama3.2:latest')
        for m in available:
            if target.split(":")[0] in m:
                return m

        # 4. Fallback to first available installed model
        return available[0]

    def explain_incident(self, incident: SecurityIncident, model: Optional[str] = None) -> str:
        """Send incident context to Ollama and obtain a structured educational breakdown."""
        resolved_model = self.resolve_model(model)
        incident_context = incident.to_llm_context()

        user_prompt = (
            f"Analizeaza urmatorul incident de securitate si instruieste analistul conform instructiunilor din system prompt:\n\n"
            f"{incident_context}"
        )

        payload = {
            "model": resolved_model,
            "prompt": user_prompt,
            "system": SYSTEM_PROMPT,
            "stream": False,
            "options": {
                "temperature": 0.3,  # Keep responses technical, deterministic, and accurate
            }
        }

        try:
            resp = requests.post(
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=120  # generous timeout for local models on larger context
            )
            if resp.status_code == 200:
                data = resp.json()
                return data.get("response", "Niciun raspuns generat de model.")
            else:
                return f"[Eroare Ollama HTTP {resp.status_code}]: {resp.text}"
        except requests.exceptions.Timeout:
            return "[Eroare]: Interogarea catre Ollama a expirat (timeout). Modelul local ruleaza prea incet sau incarca resurse mari."
        except requests.exceptions.ConnectionError:
            return "[Eroare]: Conexiunea catre Ollama a fost intrerupta in timpul generarii raspunsului."
        except Exception as exc:
            return f"[Eroare neasteptata]: {exc}"
