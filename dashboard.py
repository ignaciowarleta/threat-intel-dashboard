import streamlit as st

from services.abuseipdb import get_abuseipdb_report
from services.virustotal import get_virustotal_report
from services.geolocation import get_geolocation
from utils.validator import is_valid_ip
from utils.scorer import calculate_risk


st.set_page_config(page_title="Threat Intel Dashboard", layout="wide")

st.title("Threat Intelligence Dashboard")
st.write("Análisis de reputación, geolocalización y riesgo de una IP.")


def risk_color(label: str) -> str:
    if label == "Alto":
        return "🔴"
    if label == "Medio":
        return "🟠"
    return "🟢"


ip = st.text_input("Introduce una dirección IP", value="8.8.8.8")

if st.button("Analizar IP"):
    if not is_valid_ip(ip):
        st.error("La IP introducida no es válida.")
        st.stop()

    with st.spinner("Consultando fuentes de threat intelligence..."):
        geo = get_geolocation(ip)
        abuse = get_abuseipdb_report(ip)
        vt = get_virustotal_report(ip)

    abuse_score = abuse.get("abuseConfidenceScore") if "error" not in abuse else None
    vt_malicious = vt.get("malicious") if "error" not in vt else None
    risk_score, risk_label = calculate_risk(abuse_score, vt_malicious)

    st.subheader("Resumen")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("IP", ip)
    c2.metric("País", str(geo.get("country", "N/D")))
    c3.metric("ISP", str(geo.get("isp", "N/D")))
    c4.metric("Riesgo", f"{risk_color(risk_label)} {risk_label} ({risk_score}/100)")

    st.subheader("Geolocalización")
    g1, g2, g3 = st.columns(3)
    g1.write(f"**País:** {geo.get('country', 'N/D')}")
    g1.write(f"**Región:** {geo.get('regionName', 'N/D')}")
    g2.write(f"**Ciudad:** {geo.get('city', 'N/D')}")
    g2.write(f"**ISP:** {geo.get('isp', 'N/D')}")
    g3.write(f"**Organización:** {geo.get('org', 'N/D')}")
    g3.write(f"**AS:** {geo.get('as', 'N/D')}")

    st.subheader("AbuseIPDB")
    if "error" in abuse:
        st.warning(f"AbuseIPDB: {abuse['error']}")
    else:
        a1, a2, a3 = st.columns(3)
        a1.metric("Abuse Score", str(abuse.get("abuseConfidenceScore", "N/D")))
        a2.metric("Total Reports", str(abuse.get("totalReports", "N/D")))
        a3.metric("Último reporte", str(abuse.get("lastReportedAt", "N/D")))
        st.write(f"**Tipo de uso:** {abuse.get('usageType', 'N/D')}")
        st.write(f"**Dominio:** {abuse.get('domain', 'N/D')}")
        st.write(f"**ISP:** {abuse.get('isp', 'N/D')}")

    st.subheader("VirusTotal")
    if "error" in vt:
        st.warning(f"VirusTotal: {vt['error']}")
    else:
        v1, v2, v3, v4 = st.columns(4)
        v1.metric("Reputation", str(vt.get("reputation", "N/D")))
        v2.metric("Malicious", str(vt.get("malicious", "N/D")))
        v3.metric("Suspicious", str(vt.get("suspicious", "N/D")))
        v4.metric("Harmless", str(vt.get("harmless", "N/D")))
        st.write(f"**Undetected:** {vt.get('undetected', 'N/D')}")
        st.write(f"**Country:** {vt.get('country', 'N/D')}")
        st.write(f"**AS Owner:** {vt.get('as_owner', 'N/D')}")

    st.subheader("Datos crudos")
    with st.expander("Ver geolocalización"):
        st.json(geo)

    with st.expander("Ver respuesta normalizada de AbuseIPDB"):
        st.json(abuse)

    with st.expander("Ver respuesta normalizada de VirusTotal"):
        st.json(vt)