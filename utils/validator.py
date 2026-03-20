import ipaddress

def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

def classify_ip(value: str) -> dict:
    ip = ipaddress.ip_address(value)

    return {
        "is_private": ip.is_private,
        "is_loopback": ip.is_loopback,
        "is_multicast": ip.is_multicast,
        "is_reserved": ip.is_reserved,
        "is_global": ip.is_global,
        "version": ip.version,
    }