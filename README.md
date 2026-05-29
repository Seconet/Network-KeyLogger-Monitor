# 🔍 Network-KeyLogger-Monitor
Un tool di sicurezza per enumerare le connessioni attive, scapy per l'ispezione dei pacchetti e un motore di regole basato su soglie comportamentali.
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Windows](https://img.shields.io/badge/Windows-10%2011-0078D6?logo=windows)](https://microsoft.com)

<img src="https://seconet.it/wp-content/uploads/2026/05/networkmonitor-1024x734.webp" alt="Network Monitor Interface" width="800">

## 📌 Introduzione

**Network KeyLogger Monitor** è un tool di sicurezza open source progettato per rilevare keylogger e malware attraverso l'analisi del traffico di rete in uscita.

A differenza degli antivirus tradizionali che si concentrano sulle firme dei file, questo monitor si basa su un principio semplice ma efficace: **un keylogger senza rete è inutile, un keylogger che invia dati è rilevabile**.

## 🎯 Cosa rileva

| Minaccia | Metodo di rilevamento |
|----------|----------------------|
| Keylogger via FTP | 🔴 Porta 21 + processo in AppData/Temp |
| Exfiltration via HTTP/HTTPS | 🟠 IP sconosciuti + pattern periodici |
| DNS Tunneling | 🟡 Query anomale (TLD insoliti, lunghezza record) |
| Processi mascherati | 🟡 Nome legit ma percorso sospetto |

## 🛠️ Funzionalità

- 🔍 **Enumerazione connessioni attive** (psutil)
- 📦 **Ispezione pacchetti** (scapy)
- 🧠 **Motore di regole** basato su soglie comportamentali
- 🚨 **Alert in tempo reale** con colori (terminal)
- 📊 **Report finale** delle minacce rilevate
- ⚙️ **Whitelist configurabile** per falsi positivi

## 📊 Come funziona

```python
# Il monitor analizza:
1. Processo → da dove parte? (AppData/Temp? → SOSPETTO)
2. Porta → è una porta C2 nota? (21, 4444, 1337? → CRITICO)
3. Destinazione → IP in whitelist? (no → SOSPETTO)
4. Comportamento → pattern periodico di connessioni? (sì → ATTACCO)

## 🚀 Installazione
Prerequisiti
- Python 3.8+
- Windows 10/11 (Linux compatibile, ma ottimizzato per Windows)

## Installazione rapida
1. Clona o scarica lo zip dal repository
2. Installa le dipendenze
pip install -r requirements.txt
3. Esegui come amministratore (consigliato)
python network_monitor.py

## 📁 Struttura del progetto
Network-KeyLogger-Monitor/
├── network_monitor.py      # Main script
├── requirements.txt        # Dipendenze
├── README.md              # Documentazione
└── LICENSE                # MIT License

## 🤝 Contribuire

| Passo | Comando |
|-------|---------|
| 🍴 Fork | Clicca su "Fork" in alto a destra |
| 🔧 Branch | `git checkout -b feature/AmazingFeature` |
| 💾 Commit | `git commit -m 'Add AmazingFeature'` |
| 📤 Push | `git push origin feature/AmazingFeature` |
| 🔃 Pull Request | Apri PR su GitHub |

> 💡 **Nota**: Sostituisci `AmazingFeature` con il nome della tua modifica.

## 📝 Changelog
v1.0.0 (Maggio 2026)
✨ Rilascio iniziale

🔍 Enumerazione connessioni attive

🚨 Alert colorati in console

📊 Report finale delle minacce

## ⚖️ Licenza
Distribuito sotto licenza MIT. Vedere LICENSE per maggiori informazioni.

## ⚠️ Disclaimer legale
Questo strumento è fornito esclusivamente per scopi educativi e di difesa.
Il monitoraggio di dispositivi senza esplicita autorizzazione viola le leggi sulla privacy (GDPR, art. 615-ter c.p. e normative equivalenti). Utilizza questo tool solo su:

✅ Sistemi di tua proprietà
✅ Dispositivi per cui hai ricevuto autorizzazione scritta
✅ Ambienti di laboratorio controllati

L'autore non è responsabile per usi impropri o illegali di questo software.

## 📧 Contatti
🔗 Sito: seconet.it

🐛 Issue: GitHub Issues

## ⭐ Supporta il progetto

Se trovi utile questo tool:

⭐ Metti una stella sul repository

🐦 Condividi sui social

🔗 Linka il progetto sul tuo sito

