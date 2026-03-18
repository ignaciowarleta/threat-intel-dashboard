import sys
from rich.console import Console
from rich.table import Table

from services.abuseipdb import get_abuseipdb_report
from services.virustotal import get_virustotal_report
from services.geolocation import get_geolocation
from utils.validator import is_valid_ip
from utils.scorer import calculate_risk

console = Console()

def main():
    if len(sys.argv) != 2:
        console.print("[red]Uso:[/red] python main.py <ip>")
        raise SystemExit(1)

    ip = sys.argv[1].strip()

    if not is_valid_ip(ip):
        console.print(f"[red]IP no válida:[/red] {ip}")
        raise SystemExit(1)

    geo = get_geolocation(ip)
    abuse = get_abuseipdb_report(ip)
    vt = get_virustotal_report(ip)

    abuse_score = abuse.get("abuseConfidenceScore") if "error" not in abuse else None
    vt_malicious = vt.get("malicious") if "error" not in vt else None
    risk_score, risk_label = calculate_risk(abuse_score, vt_malicious)

    table = Table(title="Threat Intelligence Report")
    table.add_column("Campo", style="cyan")
    table.add_column("Valor", style="white")

    table.add_row("IP", ip)
    table.add_row("País", str(geo.get("country", "N/D")))
    table.add_row("Ciudad", str(geo.get("city", "N/D")))
    table.add_row("ISP", str(geo.get("isp", "N/D")))
    table.add_row("Abuse Score", str(abuse.get("abuseConfidenceScore", "N/D")))
    table.add_row("Total Reports", str(abuse.get("totalReports", "N/D")))
    table.add_row("VT Reputation", str(vt.get("reputation", "N/D")))
    table.add_row("VT Malicious", str(vt.get("malicious", "N/D")))
    table.add_row("VT Suspicious", str(vt.get("suspicious", "N/D")))
    table.add_row("Riesgo", f"{risk_label} ({risk_score}/100)")

    console.print(table)

    if "error" in abuse:
        console.print(f"[yellow]AbuseIPDB:[/yellow] {abuse['error']}")
    if "error" in vt:
        console.print(f"[yellow]VirusTotal:[/yellow] {vt['error']}")

if __name__ == "__main__":
    main()