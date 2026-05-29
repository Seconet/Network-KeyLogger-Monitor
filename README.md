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
