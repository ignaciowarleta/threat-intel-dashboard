import requests

def get_geolocation(ip: str) -> dict:
    url = f"http://ip-api.com/json/{ip}"
    response = requests.get(url, timeout=10)
    response.raise_for_status()
    data = response.json()

    if data.get("status") != "success":
        return {"error": data.get("message", "No se pudo resolver la geolocalización")}

    return {
        "country": data.get("country"),
        "regionName": data.get("regionName"),
        "city": data.get("city"),
        "isp": data.get("isp"),
        "org": data.get("org"),
        "as": data.get("as"),
    }