import json
import ipaddress
import csv
from io import StringIO


def normalize_ip(value: str) -> str | None:
    value = value.strip()
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def load_ips_from_txt(file_content: str) -> list[str]:
    ips = []
    for line in file_content.splitlines():
        ip = normalize_ip(line)
        if ip:
            ips.append(ip)
    return sorted(set(ips))


def load_ips_from_csv(file_content: str) -> list[str]:
    ips = []
    reader = csv.reader(StringIO(file_content))
    for row in reader:
        for cell in row:
            ip = normalize_ip(cell)
            if ip:
                ips.append(ip)
    return sorted(set(ips))


def load_ips_from_honeypot_jsonl(file_content: str) -> list[str]:
    ips = []
    for line in file_content.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
            ip = normalize_ip(str(event.get("ip", "")))
            if ip:
                ips.append(ip)
        except json.JSONDecodeError:
            continue
    return sorted(set(ips))