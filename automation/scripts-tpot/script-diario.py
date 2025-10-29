import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from datetime import datetime, timedelta, timezone
from elasticsearch import Elasticsearch, ConnectionError, TransportError
import json
import os
import urllib3

# Deshabilitar advertencias de 'verify_certs=False'
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- CONFIGURACIÓN ELASTICSEARCH ---
ELASTIC_HOST = "localhost"
ELASTIC_PORT = 64298
ELASTIC_SCHEME = "http"
ELASTIC_USER = "elastic"
ELASTIC_PASSWORD = os.getenv("ELASTIC_PASSWORD")

# --- Configuración de Correo Electrónico ---
SENDER_EMAIL = "adrianchvzfox7@gmail.com"
SENDER_PASSWORD = "shyc yyoy rrny knpx"
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587

# Lista de destinatarios
RECEIVER_EMAILS = ["adrian.chavez@tecsup.edu.pe", "anthony.lopez@tecsup.edu.pe"]

ALL_HONEYPOT_TYPES = "Cowrie Dionaea H0neytr4p Honeytrap"

# Modifica aquí el rango. "7d" para semanal, "1d" para diario.
REPORT_TIME_RANGE = "1d"

# --- Conexión a Elasticsearch ---
def get_es_client():
    try:
        es = Elasticsearch(
            hosts=[f"{ELASTIC_SCHEME}://{ELASTIC_HOST}:{ELASTIC_PORT}"],
            basic_auth=(ELASTIC_USER, ELASTIC_PASSWORD),
            verify_certs=False,
            request_timeout=30
        )
        if not es.ping():
            raise ValueError("Conexión a Elasticsearch fallida.")
        print(f"[{datetime.now()}] Conexión a Elasticsearch exitosa.")
        return es
    except ConnectionError as e:
        print(f"[{datetime.now()}] Error de conexión a Elasticsearch: {e}")
        return None
    except Exception as e:
        print(f"[{datetime.now()}] Error inesperado al conectar a Elasticsearch: {e}")
        return None


# --- Consultas ---
def get_honeypot_attack_counts(es_client, time_range):
    days = int(time_range.replace("d", ""))
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(days=days)
    
    query_body = { "bool": { "filter": [ {"bool": {"should": [{"match": {"type": ALL_HONEYPOT_TYPES}}], "minimum_should_match": 1}}, {"range": {"@timestamp": {"format": "strict_date_optional_time", "gte": start_time.isoformat(timespec='milliseconds') + 'Z', "lte": end_time.isoformat(timespec='milliseconds') + 'Z'}}} ] } }
    try:
        res = es_client.search( index="logstash-*", query=query_body, aggs={ "honeypot_types": { "terms": {"field": "type.keyword", "order": {"_count": "desc"}, "size": 50} } }, size=0 )
        honeypot_counts = [ {"honeypot_type": b['key'], "count": b['doc_count']} for b in res["aggregations"]["honeypot_types"]["buckets"] ]
        return honeypot_counts, start_time, end_time
    except Exception as e:
        print(f"[{datetime.now()}] Error en get_honeypot_attack_counts: {e}")
        return [], None, None


def get_port_attack_counts(es_client, time_range):
    days = int(time_range.replace("d", ""))
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(days=days)
    
    query_body = { "bool": { "filter": [ {"bool": {"should": [{"match": {"type": ALL_HONEYPOT_TYPES}}], "minimum_should_match": 1}}, {"range": {"@timestamp": {"format": "strict_date_optional_time", "gte": start_time.isoformat(timespec='milliseconds') + 'Z', "lte": end_time.isoformat(timespec='milliseconds') + 'Z'}}} ] } }
    try:
        res = es_client.search( index="logstash-*", query=query_body, aggs={ "top_dest_ports": { "terms": {"field": "dest_port", "order": {"_count": "desc"}, "size": 10, "shard_size": 1000} } }, size=0 )
        port_counts = [ {"port": b['key'], "count": b['doc_count']} for b in res["aggregations"]["top_dest_ports"]["buckets"] ]
        return port_counts
    except Exception as e:
        print(f"[{datetime.now()}] Error en get_port_attack_counts: {e}")
        return []


def get_top_attacker_ips(es_client, time_range):
    days = int(time_range.replace("d", ""))
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(days=days)
    
    query_body = { "bool": { "filter": [ {"bool": {"should": [{"match": {"type": ALL_HONEYPOT_TYPES}}], "minimum_should_match": 1}}, {"range": {"@timestamp": {"format": "strict_date_optional_time", "gte": start_time.isoformat(timespec='milliseconds') + 'Z', "lte": end_time.isoformat(timespec='milliseconds') + 'Z'}}} ] } }
    try:
        res = es_client.search( index="logstash-*", query=query_body, aggs={ "top_attacker_ips": { "terms": {"field": "src_ip.keyword", "order": {"_count": "desc"}, "size": 10, "shard_size": 1000} } }, size=0 )
        ip_counts = [ {"ip": b['key'], "count": b['doc_count']} for b in res["aggregations"]["top_attacker_ips"]["buckets"] ]
        return ip_counts
    except Exception as e:
        print(f"[{datetime.now()}] Error en get_top_attacker_ips: {e}")
        return []


def get_attacks_by_country(es_client, time_range):
    days = int(time_range.replace("d", ""))
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(days=days)
    
    query_body = { "bool": { "filter": [ {"range": {"@timestamp": {"format": "strict_date_optional_time", "gte": start_time.isoformat(timespec='milliseconds') + 'Z', "lte": end_time.isoformat(timespec='milliseconds') + 'Z'}}} ] } }
    try:
        res = es_client.search( index="logstash-*", query=query_body, aggs={ "countries": { "terms": {"field": "geoip.country_name.keyword", "order": {"_count": "desc"}, "size": 10} } }, size=0 )
        country_counts = [ {"country": b['key'], "count": b['doc_count']} for b in res["aggregations"]["countries"]["buckets"] ]
        return country_counts
    except Exception as e:
        print(f"[{datetime.now()}] Error en get_attacks_by_country: {e}")
        return []


# --- PROCESAMIENTO Y ENVÍO ---

def build_table_rows(data, headers):
    """Construye las filas <tr> para las tablas."""
    if not data:
        return '<tr><td colspan="2" class="no-data">No hay datos disponibles.</td></tr>'
    rows = []
    for item in data:
        row = "<tr>"
        row += f"<td>{item.get(headers[0], 'N/A')}</td>"
        row += f"<td>{item.get(headers[1], 'N/A')}</td>"
        row += "</tr>"
        rows.append(row)
    return '\n'.join(rows)


# --- ¡FUNCIÓN HTML MODIFICADA! ---
def process_data_to_html(honeypot_data, port_data, ip_data, country_data, start_date_utc, end_date_utc):
    """
    Genera el reporte HTML usando la nueva plantilla proporcionada.
    """
    report_filename = f"tpot_honeypot_report_{start_date_utc.strftime('%Y-%m-%d')}_to_{end_date_utc.strftime('%Y-%m-%d')}.html"
    total_attacks = sum(item['count'] for item in honeypot_data)

    # Timestamps dinámicos para el header
    generation_time_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S (Hora del Servidor)')
    start_time_str = start_date_utc.strftime('%Y-%m-%d %H:%M:%S UTC')
    end_time_str = end_date_utc.strftime('%Y-%m-%d %H:%M:%S UTC')

    # Construir filas dinámicas para cada tabla
    honeypot_rows = build_table_rows(honeypot_data, ['honeypot_type', 'count'])
    port_rows = build_table_rows(port_data, ['port', 'count'])
    ip_rows = build_table_rows(ip_data, ['ip', 'count'])
    country_rows = build_table_rows(country_data, ['country', 'count'])


    # --- INICIO DE TU PLANTILLA HTML ---
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Reporte de Ataques TPOT</title>
        <meta charset='utf-8'>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; background-color: #eef2f7; color: #333; }}
            .header {{ background-color: #2c3e50; color: white; padding: 20px 40px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
            .header h1 {{ margin: 0; font-size: 2.2em; }}
            .header p {{ margin-top: 5px; font-size: 1em; opacity: 0.9; }}
            .report-container {{ display: flex; flex-wrap: wrap; justify-content: center; gap: 20px; padding: 30px; max-width: 1200px; margin: 20px auto; }}
            .card {{ background-color: white; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); padding: 25px; flex: 1 1 48%; box-sizing: border-box; transition: transform 0.2s; }}
            .card:hover {{ transform: translateY(-5px); }}
            .card h2 {{ color: #2980b9; margin-top: 0; border-bottom: 2px solid #ecf0f1; padding-bottom: 10px; margin-bottom: 20px; font-size: 1.6em; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
            th, td {{ padding: 12px 15px; border: 1px solid #e0e6ed; text-align: left; font-size: 0.95em; }}
            th {{ background-color: #3498db; color: white; font-weight: 600; }}
            tr:nth-child(even) {{ background-color: #f8fbfd; }}
            tr:hover {{ background-color: #eaf4fa; }}
            .no-data {{ text-align: center; color: #888; font-style: italic; padding: 20px; }}
            .table-scroll {{ max-height: 400px; overflow-y: auto; border: 1px solid #e0e6ed; border-radius: 8px; }}
            .total-row {{ font-weight: bold; background-color: #e0e6ed; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Reporte de Ataques TPOT</h1>
            <p>Reporte generado el {generation_time_str}</p>
            <p><strong>Período del reporte:</strong> {start_time_str} a {end_time_str}</p>
        </div>

        <div class="report-container">
            <div class="card">
                <h2>Conteo de Ataques por Tipo de Honeypot</h2>
                <div class="table-scroll">
                    <table>
                        <thead>
                            <tr><th>Tipo de Honeypot</th><th>Conteo</th></tr>
                        </thead>
                        <tbody>
                            {honeypot_rows}
                            <tr class="total-row">
                                <td>TOTAL GLOBAL</td>
                                <td>{total_attacks}</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <div class="card">
                <h2>Conteo de Ataques por Puerto Destino</h2>
                <div class="table-scroll" style="max-height: 250px;">
                    <table>
                        <thead>
                            <tr><th>Puerto</th><th>Conteo</th></tr>
                        </thead>
                        <tbody>
                            {port_rows}
                        </tbody>
                    </table>
                </div>
            </div>

            <div class="card">
                <h2>Top 10 IPs Atacantes</h2>
                <div class="table-scroll" style="max-height: 250px;">
                    <table>
                        <thead>
                            <tr><th>IP Atacante</th><th>Conteo</th></tr>
                        </thead>
                        <tbody>
                            {ip_rows}
                        </tbody>
                    </table>
                </div>
            </div>

            <div class="card">
                <h2>Ataques por País</h2>
                <div class="table-scroll" style="max-height: 250px;">
                    <table>
                        <thead>
                            <tr><th>País</th><th>Conteo</th></tr>
                        </thead>
                        <tbody>
                            {country_rows}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </body>
    </html>
    """
    # --- FIN DE TU PLANTILLA HTML ---

    # Guardar el archivo HTML
    try:
        with open(report_filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        print(f"[{datetime.now()}] Reporte HTML '{report_filename}' generado exitosamente.")
    except Exception as e:
        print(f"[{datetime.now()}] Error al escribir el archivo HTML: {e}")
        return None, None
    return report_filename, html_content


# --- FUNCIÓN DE ENVÍO (CON LA ÚLTIMA CORRECCIÓN) ---
def send_email_with_attachment(report_filepath, subject, html_body):
    msg = MIMEMultipart()
    msg['From'] = SENDER_EMAIL
    msg['Subject'] = subject
    
    # --- CORRECCIÓN FINAL ---
    # Convierte la lista en un string para la cabecera 'To'
    msg['To'] = ", ".join(RECEIVER_EMAILS)
    
    msg.attach(MIMEText(html_body, 'html'))

    try:
        with open(report_filepath, "rb") as attachment:
            part = MIMEBase("application", "octet-stream")
            part.set_payload(attachment.read())
        encoders.encode_base64(part)
        part.add_header("Content-Disposition", f"attachment; filename= {os.path.basename(report_filepath)}")
        msg.attach(part)
    except Exception as e:
        print(f"[{datetime.now()}] Error al adjuntar el archivo: {e}")
        return

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            
            # 'server.sendmail' SÍ acepta la lista de destinatarios
            server.sendmail(SENDER_EMAIL, RECEIVER_EMAILS, msg.as_string())
            
            print(f"[{datetime.now()}] Correo enviado exitosamente a {', '.join(RECEIVER_EMAILS)}")
    except Exception as e:
        print(f"[{datetime.now()}] Error al enviar el correo: {e}")


# --- MAIN ---
if __name__ == "__main__":
    es_client = get_es_client()
    if es_client:
        honeypot_counts, start_time, end_time = get_honeypot_attack_counts(es_client, REPORT_TIME_RANGE)
        
        if honeypot_counts is not None and start_time and end_time:
            port_counts = get_port_attack_counts(es_client, REPORT_TIME_RANGE)
            ip_counts = get_top_attacker_ips(es_client, REPORT_TIME_RANGE)
            country_counts = get_attacks_by_country(es_client, REPORT_TIME_RANGE)

            report_file, html_content = process_data_to_html(honeypot_counts, port_counts, ip_counts, country_counts, start_time, end_time)
            
            if report_file and html_content:
                today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                email_subject = f"Reporte Diario de Ataques Honeypot TPOT - {today_str}"
                send_email_with_attachment(report_file, email_subject, html_content)
                
                try:
                    os.remove(report_file)
                    print(f"[{datetime.now()}] Archivo de reporte '{report_file}' eliminado.")
                except Exception as e:
                    print(f"[{datetime.now()}] Error al eliminar el archivo de reporte: {e}")
        else:
            print(f"[{datetime.now()}] No se pudieron obtener los datos de Elasticsearch. No se generará el reporte.")
    else:
        print(f"[{datetime.now()}] No se pudo establecer conexión con Elasticsearch. No se generará el reporte.")
