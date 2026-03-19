# Threat Intelligence Dashboard

Herramienta en Python para enriquecimiento de direcciones IP mediante fuentes de *threat intelligence*, combinando reputación, geolocalización y scoring básico de riesgo.

El proyecto incluye tanto una **CLI** como un **dashboard interactivo** para analizar actividad sospechosa de forma sencilla.

---

## Características

- Consulta de reputación de IPs mediante APIs públicas  
- Geolocalización (país, ciudad, ISP, ASN)  
- Detección básica de actividad maliciosa  
- Scoring de riesgo personalizado  
- Interfaz CLI  
- Dashboard interactivo con Streamlit
- Análisis por lote (TXT/CSV)
- Integración con logs de honeypot (JSONL)
- Exportación de resultados a CSV  

## Estructura del proyecto

    threat-intel-dashboard/
    ├── main.py
    ├── dashboard.py
    ├── services/
    │   ├── abuseipdb.py
    │   ├── virustotal.py
    │   └── geolocation.py
    ├── utils/
    │   ├── analyzer.py
    │   ├── loaders.py
    │   ├── scorer.py
    │   └── validator.py
    ├── .env.example
    ├── requirements.txt
    └── README.md


## Instalación

1.  Clonar el entorno
    ```bash
    git clone https://github.com/tu-usuario/threat-intel-dashboard.git
    cd threat-intel-dashboard

2.	Crear y activar entorno virtual

	Ejecuta en la terminal:
    ```bash
    
    python3 -m venv .venv
    source .venv/bin/activate

3.	Instalar dependencias
    ```bash
    pip install -r requirements.txt

4.	Configurar variables de entorno

	Crear archivo .env a partir del ejemplo. Luego abre el archivo .env y añade tus API keys:
    ```bash
	
    cp .env.example .env
    
    ABUSEIPDB_API_KEY=tu_api_key
    VT_API_KEY=tu_api_key

5.	Ejecutar la aplicación (CLI)
    ```bash
    python main.py 8.8.8.8

6.	Ejecutar el dashboard
    ```bash
    streamlit run dashboard.py

## Uso

Analizar una IP desde terminal:
    ```bash
    
    python main.py 8.8.8.8

Mediante Dashboard
    ```bash
    
    streamlit run dashboard.py

## Funcionalidades del dashboard

### IP Individual

- Análisis completo de una IP
- Clasificación automática (privada/pública)
- Visualización de riesgo

### Análisis por lote

- Carga de archivos .txt o .csv
- Procesamiento de múltiples IPs
- Tabla ordenada por riesgo
- Exportación a CSV

### Logs del honeypot

- Carga de events.jsonl
- Extracción automática de IPs
- Eliminación de duplicados
- Priorización por riesgo

## Ejemplo de salida:
 
IP: 8.8.8.8
País: United States
ISP: Google LLC
Abuse Score: 0
VT Reputation: 0
Riesgo: Bajo


<img width="1093" height="837" alt="Captura de pantalla 2026-03-18 a las 19 25 52" src="https://github.com/user-attachments/assets/72d5dd42-6039-4edd-83c3-f81190f660b0" />

## Integración con Honeypot

Este proyecto está diseñado para integrarse con el repositorio: [Python HTTP Honeypot](https://github.com/ignaciowarleta/honeypot-http)

Flujo de uso:

1.	El honeypot captura actividad y genera events.jsonl
2.	El dashboard carga ese fichero
3.	Se extraen IPs únicas
4.	Se enriquecen con fuentes de threat intelligence
5.	Se priorizan según riesgo

