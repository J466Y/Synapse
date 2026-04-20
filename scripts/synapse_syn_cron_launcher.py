import requests
# Lista de módulos que quieres sincronizar
MODULES = [
	{"name": "qradar", "timerange": 30},
	{"name": "fortiedr", "timerange": 30}
    # {"name": "splunk", "timerange": 15}, # Facil de añadir en el futuro
]

TOKEN = "Your Token"

SYNAPSE_URL = "http://127.0.0.1:5000/integration/"
def run_sync():
    for module in MODULES:
        print(f"Sincronizando {module['name']}...")
        try:
            url = f"{SYNAPSE_URL}{module['name']}"
            data = {"timerange": module['timerange']}
            headers = {"Authorization": f"Bearer {TOKEN}"}
            response = requests.post(url, json=data, headers=headers)
            print(f"Resultado: {response.status_code}")
        except Exception as e:
            print(f"Error en {module['name']}: {e}")
if __name__ == "__main__":
    run_sync()
