import psutil
import time
import datetime
import socket
import os
from dataclasses import dataclass
from typing import List

@dataclass
class SuspiciousConnection:
    timestamp: datetime.datetime
    process_name: str
    process_pid: int
    process_path: str
    dest_ip: str
    dest_port: int
    bytes_sent: int
    risk: str
    reason: str


class SimpleNetworkMonitor:
    def __init__(self):
        self.suspicious_connections: List[SuspiciousConnection] = []
        self.alerted_connections = set()
        
        # Porte altamente sospette per keylogger C2
        self.critical_ports = [21, 25, 465, 587, 4444, 1337, 6667, 31337, 54321]
        
        # Porte da monitorare con attenzione
        self.suspicious_ports = [8080, 8443, 9001, 9999, 12345]
        
        # IP locali (ignorati)
        self.local_ips = ['127.0.0.1', 'localhost', '::1', '192.168.', '10.', '172.16.']
        
        # Whitelist processi legittimi
        self.whitelist_processes = [
            'svchost.exe', 'System', 'Registry', 'services.exe',
            'lsass.exe', 'wininit.exe', 'csrss.exe', 'winlogon.exe',
            'explorer.exe', 'chrome.exe', 'firefox.exe', 'msedge.exe',
            'Spotify.exe', 'Discord.exe', 'Code.exe', 'python.exe'
        ]
    
    def is_whitelisted_ip(self, ip: str) -> bool:
        for local in self.local_ips:
            if ip.startswith(local):
                return True
        return False
    
    def is_whitelisted_process(self, process_name: str) -> bool:
        return process_name.lower() in [p.lower() for p in self.whitelist_processes]
    
    def get_process_info(self, pid: int):
        try:
            proc = psutil.Process(pid)
            return {
                'name': proc.name(),
                'path': proc.exe(),
                'cwd': proc.cwd(),
                'create_time': proc.create_time()
            }
        except:
            return None
    
    def calculate_risk(self, dest_port: int, process_path: str) -> tuple:
        # CRITICAL: porte note per C2
        if dest_port in self.critical_ports:
            return "CRITICAL", f"Porta {dest_port} (tipica C2 keylogger)"
        
        # HIGH: processi da cartelle utente
        if process_path:
            path_lower = process_path.lower()
            if 'appdata' in path_lower:
                return "HIGH", "Processo in AppData"
            if 'temp' in path_lower:
                return "HIGH", "Processo in Temp"
            if 'downloads' in path_lower:
                return "HIGH", "Processo in Downloads"
        
        # MEDIUM: porte sospette
        if dest_port in self.suspicious_ports:
            return "MEDIUM", f"Porta {dest_port} (non standard)"
        
        return "LOW", "Monitoraggio normale"
    
    def scan_connections(self):
        alerts = []
        
        try:
            connections = psutil.net_connections(kind='inet')
            
            for conn in connections:
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    dest_ip = conn.raddr.ip
                    dest_port = conn.raddr.port
                    pid = conn.pid
                    
                    if self.is_whitelisted_ip(dest_ip):
                        continue
                    
                    proc_info = self.get_process_info(pid)
                    if not proc_info:
                        continue
                    
                    process_name = proc_info['name']
                    process_path = proc_info['path']
                    
                    if self.is_whitelisted_process(process_name):
                        continue
                    
                    alert_key = f"{pid}_{dest_ip}_{dest_port}"
                    if alert_key in self.alerted_connections:
                        continue
                    
                    risk, reason = self.calculate_risk(dest_port, process_path)
                    
                    if risk in ["CRITICAL", "HIGH", "MEDIUM"]:
                        alert = SuspiciousConnection(
                            timestamp=datetime.datetime.now(),
                            process_name=process_name,
                            process_pid=pid,
                            process_path=process_path[:100] if process_path else "N/A",
                            dest_ip=dest_ip,
                            dest_port=dest_port,
                            bytes_sent=0,
                            risk=risk,
                            reason=reason
                        )
                        alerts.append(alert)
                        self.alerted_connections.add(alert_key)
                        
        except Exception as e:
            pass
        
        return alerts
    
    def run(self, interval_seconds: int = 2):
        print("=" * 70)
        print("🔍 NETWORK MONITOR - Rilevazione Keylogger")
        print("=" * 70)
        print(f"📡 Monitoraggio attivo (scan ogni {interval_seconds} secondi)")
        print("🔴 CRITICAL = Porte C2 note")
        print("🟠 HIGH = Processo da cartella utente")
        print("🟡 MEDIUM = Porta non standard")
        print("✅ CTRL+C per fermare\n")
        
        try:
            while True:
                alerts = self.scan_connections()
                for alert in alerts:
                    self.print_alert(alert)
                time.sleep(interval_seconds)
                
        except KeyboardInterrupt:
            print("\n\n" + "=" * 70)
            print("📊 REPORT FINALE")
            print("=" * 70)
            print(f"Totale connessioni sospette rilevate: {len(self.suspicious_connections)}")
            
            if self.suspicious_connections:
                print("\n⚠️ TROVATE POSSIBILI MINACCE:")
                for conn in self.suspicious_connections:
                    print(f"   • {conn.process_name} (PID:{conn.process_pid}) → {conn.dest_ip}:{conn.dest_port} [{conn.risk}]")
            else:
                print("✅ Nessuna minaccia rilevata durante il monitoraggio")
    
    def print_alert(self, alert: SuspiciousConnection):
        self.suspicious_connections.append(alert)
        
        if alert.risk == "CRITICAL":
            color = "\033[91m"
            emoji = "🔴"
        elif alert.risk == "HIGH":
            color = "\033[93m"
            emoji = "🟠"
        else:
            color = "\033[94m"
            emoji = "🟡"
        
        reset = "\033[0m"
        
        print(f"\n{'='*70}")
        print(f"{color}{emoji} [{alert.timestamp.strftime('%H:%M:%S')}] ALLERTA: {alert.risk}{reset}")
        print(f"   📁 Processo: {alert.process_name} (PID: {alert.process_pid})")
        print(f"   📂 Path: {alert.process_path}")
        print(f"   🌐 Destinazione: {alert.dest_ip}:{alert.dest_port}")
        print(f"   📝 Motivo: {alert.reason}")
        print(f"{'='*70}")


if __name__ == "__main__":
    monitor = SimpleNetworkMonitor()
    monitor.run(interval_seconds=2)