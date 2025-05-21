import re
import json
import requests
from collections import defaultdict

regex = re.compile(
    r'^(\d{1,3}(?:\.\d{1,3}){3}) - - \[(\d{2}/\w{3}/\d{4}):(\d{2}:\d{2}:\d{2}) [+-]\d{4}\] "(GET|POST|PUT|DELETE|HEAD) (.*?) HTTP/[\d.]+" (\d{3})'
)

def obtener_pais(ip):
    try:
        datos_geolocalizacion = requests.get(f"http://ip-api.com/json/{ip}", timeout=2).json()
        return datos_geolocalizacion.get("country", "Desconocido")
    except:
        return "Desconocido"

def procesar_archivo(ruta, ips_procesadas):
    ataques = []
    with open(ruta, encoding="utf-8", errors="ignore") as f:
        for linea in f:
            match = regex.match(linea)
            if match:
                ip, fecha, hora, metodo, ruta_peticion, codigo = match.groups()
                if ip not in ips_procesadas:
                    pais = obtener_pais(ip)
                    ips_procesadas.add(ip)
                    ataques.append({
                        "ip": ip,
                        "date": fecha,
                        "time": hora,
                        "method": metodo,
                        "path": ruta_peticion,
                        "code": codigo,
                        "country": pais
                    })
                    print(f"Procesada IP: {ip}, País: {pais}")
    return ataques

def procesar_logs(lista_archivos):
    ataques_por_pais = defaultdict(list)
    ips_procesadas = set()
    for archivo in lista_archivos:
        print(f"Procesando archivo: {archivo}")
        ataques = procesar_archivo(archivo, ips_procesadas)
        for ataque in ataques:
            pais = ataque.pop("country")
            ataques_por_pais[pais].append(ataque)
    return ataques_por_pais

def guardar_json(datos, archivo_salida):
    with open(archivo_salida, "w", encoding="utf-8") as f:
        json.dump(datos, f, indent=4, ensure_ascii=False)

if __name__ == "__main__":
    archivos_log = [
        r"C:\Users\marlo\Downloads\SotM34\http\access_log.1",
        r"C:\Users\marlo\Downloads\SotM34\http\access_log.2",
        r"C:\Users\marlo\Downloads\SotM34\http\access_log.3"
    ]

    ataques_por_pais = procesar_logs(archivos_log)

    resultado_final = [{"country": pais, "attacks": ataques} for pais, ataques in ataques_por_pais.items()]

    guardar_json(resultado_final, "geo_logs_apache.json")

    print("Datos guardados en 'geo_logs_apache.json'")

