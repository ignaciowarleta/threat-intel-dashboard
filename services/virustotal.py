import os
import requests
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("VT_API_KEY")

def get_virustotal_report(ip: str) -> dict:
    if not API_KEY:
        return {"error": "Falta VT_API_KEY en .env"}

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {
        "accept": "application/json",
        "x-apikey": API_KEY,
    }

    response = requests.get(url, headers=headers, timeout=15)
    response.raise_for_status()
    data = response.json().get("data", {})
    attrs = data.get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})

    return {
        "reputation": attrs.get("reputation"),
        "malicious": stats.get("malicious"),
        "suspicious": stats.get("suspicious"),
        "harmless": stats.get("harmless"),
        "undetected": stats.get("undetected"),
        "country": attrs.get("country"),
        "as_owner": attrs.get("as_owner"),
    }