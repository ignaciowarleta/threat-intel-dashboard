from services.abuseipdb import get_abuseipdb_report
from services.virustotal import get_virustotal_report
from services.geolocation import get_geolocation
from utils.validator import classify_ip
from utils.scorer import calculate_risk


def analyze_ip(ip: str) -> dict:
    ip_info = classify_ip(ip)

    if not ip_info["is_global"]:
        return {
            "ip": ip,
            "type": "local",
            "country": "N/D",
            "isp": "N/D",
            "abuse_score": None,
            "vt_malicious": None,
            "risk_score": 0,
            "risk_label": "No aplicable",
            "details": ip_info,
        }

    geo = get_geolocation(ip)
    abuse = get_abuseipdb_report(ip)
    vt = get_virustotal_report(ip)

    abuse_score = abuse.get("abuseConfidenceScore") if "error" not in abuse else None
    vt_malicious = vt.get("malicious") if "error" not in vt else None
    risk_score, risk_label = calculate_risk(abuse_score, vt_malicious)

    return {
        "ip": ip,
        "type": "public",
        "country": geo.get("country", "N/D"),
        "isp": geo.get("isp", "N/D"),
        "abuse_score": abuse_score,
        "vt_malicious": vt_malicious,
        "risk_score": risk_score,
        "risk_label": risk_label,
        "geo": geo,
        "abuse": abuse,
        "vt": vt,
    }