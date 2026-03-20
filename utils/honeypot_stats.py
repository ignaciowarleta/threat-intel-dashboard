import json
from collections import Counter, defaultdict


def summarize_honeypot_events(file_content: str) -> dict:
    summary = defaultdict(lambda: {
        "events": 0,
        "event_types": Counter(),
        "paths": Counter(),
        "user_agents": Counter(),
    })

    for line in file_content.splitlines():
        line = line.strip()
        if not line:
            continue

        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue

        ip = event.get("ip")
        if not ip:
            continue

        event_type = event.get("event_type", "unknown")
        path = event.get("path", "unknown")
        user_agent = event.get("user_agent", "unknown")

        summary[ip]["events"] += 1
        summary[ip]["event_types"][event_type] += 1
        summary[ip]["paths"][path] += 1
        summary[ip]["user_agents"][user_agent] += 1

    return summary


def get_primary_activity(event_types: Counter) -> str:
    if event_types.get("credential_attempt", 0) > 0:
        return "Credential attempts"
    if event_types.get("suspicious_request", 0) > 0:
        return "Suspicious scanning"
    if event_types.get("request", 0) > 0:
        return "General requests"
    return "Unknown"


def calculate_priority(risk_score: int, events: int, event_types: Counter) -> tuple[int, str]:
    activity_score = 0

    if events >= 20:
        activity_score += 30
    elif events >= 10:
        activity_score += 20
    elif events >= 5:
        activity_score += 10
    elif events >= 1:
        activity_score += 5

    activity_score += event_types.get("credential_attempt", 0) * 8
    activity_score += event_types.get("suspicious_request", 0) * 4
    activity_score += event_types.get("request", 0) * 1

    final_score = min(risk_score + activity_score, 100)

    if final_score >= 75:
        label = "Crítica"
    elif final_score >= 50:
        label = "Alta"
    elif final_score >= 25:
        label = "Media"
    else:
        label = "Baja"

    return final_score, label