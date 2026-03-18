import os
import requests
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("ABUSEIPDB_API_KEY")

def get_abuseipdb_report(ip: str) -> dict:
    if not API_KEY:
        return {"error": "Falta ABUSEIPDB_API_KEY en .env"}

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Accept": "application/json",
        "Key": API_KEY,
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90,
        "verbose": "",
    }

    response = requests.get(url, headers=headers, params=params, timeout=15)
    response.raise_for_status()
    payload = response.json().get("data", {})

    return {
        "abuseConfidenceScore": payload.get("abuseConfidenceScore"),
        "countryCode": payload.get("countryCode"),
        "usageType": payload.get("usageType"),
        "isp": payload.get("isp"),
        "domain": payload.get("domain"),
        "totalReports": payload.get("totalReports"),
        "lastReportedAt": payload.get("lastReportedAt"),
    }