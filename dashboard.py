import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
from utils.validator import is_valid_ip, classify_ip
from utils.scorer import calculate_risk
from utils.analyzer import analyze_ip
from utils.loaders import (
    load_ips_from_txt,
    load_ips_from_csv,
    load_ips_from_honeypot_jsonl,
)
from utils.honeypot_stats import (
    summarize_honeypot_events,
    get_primary_activity,
    calculate_priority,
)

st.set_page_config(page_title="Threat Intel Dashboard", layout="wide")

st.title("Threat Intelligence Dashboard")
st.write("Análisis de reputación, geolocalización y riesgo de una IP o de múltiples IPs.")


def risk_color(label: str) -> str:
    if label == "Alto":
        return "🔴"
    if label == "Medio":
        return "🟠"
    if label == "Bajo":
        return "🟢"
    return "⚪"


def get_ip_scope(ip_info: dict) -> tuple[str, str]:
    if ip_info["is_loopback"]:
        return "Loopback", "Dirección usada por el propio sistema para comunicaciones internas."
    if ip_info["is_private"]:
        return "Red privada", "Dirección reservada para uso interno en redes locales."
    if ip_info["is_multicast"]:
        return "Multicast", "Dirección utilizada para tráfico multicast."
    if ip_info["is_reserved"]:
        return "Reservada", "Dirección reservada para usos especiales."
    if ip_info["is_global"]:
        return "Pública", "Dirección enrutable en internet."
    return "Especial", "Dirección no clasificada como pública estándar."


def show_single_result(result: dict):
    if result["type"] == "local":
        ip_info = result["details"]
        scope, description = get_ip_scope(ip_info)

        st.warning("La IP introducida no es pública. No puede enriquecerse con fuentes públicas de threat intelligence.")

        st.subheader("Resumen")
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("IP", result["ip"])
        c2.metric("Tipo", scope)
        c3.metric("Versión", f"IPv{ip_info['version']}")
        c4.metric("Threat Intel", "No disponible")

        st.subheader("Información de red")
        g1, g2 = st.columns(2)
        g1.write(f"**Clasificación:** {scope}")
        g1.write(f"**Descripción:** {description}")
        g1.write(f"**IP privada:** {'Sí' if ip_info['is_private'] else 'No'}")
        g2.write(f"**Loopback:** {'Sí' if ip_info['is_loopback'] else 'No'}")
        g2.write(f"**Multicast:** {'Sí' if ip_info['is_multicast'] else 'No'}")
        g2.write(f"**Reservada:** {'Sí' if ip_info['is_reserved'] else 'No'}")

        with st.expander("Ver detalles técnicos de la IP"):
            st.json(ip_info)
        return

    st.subheader("Resumen")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("IP", result["ip"])
    c2.metric("País", str(result.get("country", "N/D")))
    c3.metric("ISP", str(result.get("isp", "N/D")))
    c4.metric("Riesgo", f"{risk_color(result['risk_label'])} {result['risk_label']} ({result['risk_score']}/100)")

    st.subheader("Geolocalización")
    geo = result.get("geo", {})
    g1, g2, g3 = st.columns(3)
    g1.write(f"**País:** {geo.get('country', 'N/D')}")
    g1.write(f"**Región:** {geo.get('regionName', 'N/D')}")
    g2.write(f"**Ciudad:** {geo.get('city', 'N/D')}")
    g2.write(f"**ISP:** {geo.get('isp', 'N/D')}")
    g3.write(f"**Organización:** {geo.get('org', 'N/D')}")
    g3.write(f"**AS:** {geo.get('as', 'N/D')}")

    st.subheader("AbuseIPDB")
    abuse = result.get("abuse", {})
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
    vt = result.get("vt", {})
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
        st.json(result.get("geo", {}))
    with st.expander("Ver respuesta normalizada de AbuseIPDB"):
        st.json(result.get("abuse", {}))
    with st.expander("Ver respuesta normalizada de VirusTotal"):
        st.json(result.get("vt", {}))


def results_to_dataframe(results: list[dict]) -> pd.DataFrame:
    rows = []
    for r in results:
        rows.append({
            "IP": r.get("ip"),
            "Tipo": r.get("type"),
            "País": r.get("country", "N/D"),
            "ISP": r.get("isp", "N/D"),
            "Abuse Score": r.get("abuse_score"),
            "VT Malicious": r.get("vt_malicious"),
            "Risk Score": r.get("risk_score"),
            "Risk Label": r.get("risk_label"),
        })

    df = pd.DataFrame(rows)
    if not df.empty:
        df = df.sort_values(by=["Risk Score", "Abuse Score"], ascending=False, na_position="last")
    return df

def show_honeypot_kpis(df: pd.DataFrame):
    if df.empty:
        return

    total_ips = len(df)
    critical_ips = int((df["Priority Label"] == "Crítica").sum())
    high_ips = int((df["Priority Label"] == "Alta").sum())
    credential_ips = int((df["Actividad principal"] == "Credential attempts").sum())

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("IPs analizadas", total_ips)
    c2.metric("IPs críticas", critical_ips)
    c3.metric("IPs altas", high_ips)
    c4.metric("IPs con credenciales", credential_ips)


def show_priority_chart(df: pd.DataFrame):
    if df.empty:
        return

    counts = (
        df["Priority Label"]
        .value_counts()
        .reindex(["Crítica", "Alta", "Media", "Baja"], fill_value=0)
    )

    fig, ax = plt.subplots(figsize=(5, 3))
    ax.bar(counts.index, counts.values)
    ax.set_title("Distribución de prioridades")
    ax.set_xlabel("Nivel de prioridad")
    ax.set_ylabel("Número de IPs")

    plt.tight_layout()

    col1, col2, col3 = st.columns([1,2,1])
    with col2:
        st.pyplot(fig)

mode = st.sidebar.radio(
    "Modo de análisis",
    ["IP individual", "Lote TXT/CSV", "Logs del honeypot"]
)

if mode == "IP individual":
    ip = st.text_input("Introduce una dirección IP", value="8.8.8.8")

    if st.button("Analizar IP"):
        if not is_valid_ip(ip):
            st.error("La IP introducida no es válida.")
            st.stop()

        result = analyze_ip(ip)
        show_single_result(result)

elif mode == "Lote TXT/CSV":
    uploaded_file = st.file_uploader("Sube un archivo .txt o .csv con IPs", type=["txt", "csv"])

    if uploaded_file is not None:
        content = uploaded_file.read().decode("utf-8", errors="ignore")

        if uploaded_file.name.endswith(".txt"):
            ips = load_ips_from_txt(content)
        else:
            ips = load_ips_from_csv(content)

        st.write(f"IPs únicas detectadas: {len(ips)}")

        if st.button("Analizar lote"):
            results = []
            progress = st.progress(0)

            for i, ip in enumerate(ips):
                results.append(analyze_ip(ip))
                progress.progress((i + 1) / len(ips))

            df = results_to_dataframe(results)
            st.subheader("Resultados")
            st.dataframe(df, use_container_width=True)

            csv_data = df.to_csv(index=False).encode("utf-8")
            st.download_button(
                "Descargar resultados CSV",
                data=csv_data,
                file_name="threat_intel_results.csv",
                mime="text/csv",
            )

elif mode == "Logs del honeypot":
    uploaded_file = st.file_uploader("Sube el archivo events.jsonl del honeypot", type=["jsonl", "txt"])

    if uploaded_file is not None:
        content = uploaded_file.read().decode("utf-8", errors="ignore")
        ips = load_ips_from_honeypot_jsonl(content)
        honeypot_summary = summarize_honeypot_events(content)

        st.write(f"IPs únicas extraídas del honeypot: {len(ips)}")

        if st.button("Analizar IPs del honeypot"):
            results = []
            progress = st.progress(0)

            for i, ip in enumerate(ips):
                result = analyze_ip(ip)

                stats = honeypot_summary.get(ip, {})
                events = stats.get("events", 0)
                event_types = stats.get("event_types", {})
                paths = stats.get("paths", {})

                primary_activity = get_primary_activity(event_types)
                priority_score, priority_label = calculate_priority(
                    result.get("risk_score", 0),
                    events,
                    event_types,
                )

                result["events"] = events
                result["primary_activity"] = primary_activity
                result["top_path"] = paths.most_common(1)[0][0] if paths else "N/D"
                result["priority_score"] = priority_score
                result["priority_label"] = priority_label

                results.append(result)
                progress.progress((i + 1) / len(ips))

            rows = []
            for r in results:
                rows.append({
                    "IP": r.get("ip"),
                    "Tipo": r.get("type"),
                    "País": r.get("country", "N/D"),
                    "ISP": r.get("isp", "N/D"),
                    "Eventos": r.get("events", 0),
                    "Actividad principal": r.get("primary_activity", "N/D"),
                    "Ruta más atacada": r.get("top_path", "N/D"),
                    "Risk Score": r.get("risk_score", 0),
                    "Risk Label": r.get("risk_label", "N/D"),
                    "Priority Score": r.get("priority_score", 0),
                    "Priority Label": r.get("priority_label", "N/D"),
                })

            df = pd.DataFrame(rows)

            if not df.empty:
                df = df.sort_values(
                    by=["Priority Score", "Eventos", "Risk Score"],
                    ascending=False,
                    na_position="last",
                )

            st.subheader("KPIs")
            show_honeypot_kpis(df)

            st.subheader("Distribución de prioridades")
            show_priority_chart(df)

            st.subheader("Resultados priorizados")
            st.dataframe(df, use_container_width=True)

            st.subheader("IPs prioritarias")
            priority_df = df[df["Priority Label"].isin(["Crítica", "Alta", "Media"])] if not df.empty else df
            st.dataframe(priority_df, use_container_width=True)

            csv_data = df.to_csv(index=False).encode("utf-8")
            st.download_button(
                "Descargar resultados CSV",
                data=csv_data,
                file_name="honeypot_prioritized_results.csv",
                mime="text/csv",
            )