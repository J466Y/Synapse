import os
import sys
import requests
import json
import time

# Set project root in sys.path to allow importing core modules
synapse_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if synapse_dir not in sys.path:
    sys.path.append(synapse_dir)

from core.functions import getConf

# Configuración de backoff
STATE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "backoff_state.json")
INITIAL_DELAY = 30
MAX_DELAY = 3600  # 1 hora

# Lista de módulos que quieres sincronizar
MODULES = [
    {"name": "qradar", "timerange": 30},
    {"name": "fortiedr", "timerange": 30},
    {"name": "darktrace", "timerange": 30}
]

cfg = getConf()
TOKEN = cfg.get('api', 'api_key')
SYNAPSE_URL = "http://127.0.0.1:5000/integration/"

def load_state():
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, 'r') as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_state(state):
    try:
        with open(STATE_FILE, 'w') as f:
            json.dump(state, f, indent=4)
    except Exception as e:
        print(f"Error saving state file: {e}")

def run_sync():
    state = load_state()
    current_time = time.time()
    
    for module in MODULES:
        name = module['name']
        m_state = state.get(name, {"failures": 0, "next_attempt": 0})
        
        # Verificar si el módulo está en periodo de "castigo" (backoff)
        if current_time < m_state.get('next_attempt', 0):
            wait_remaining = int(m_state['next_attempt'] - current_time)
            print(f"Saltando {name}: Servidor caído. Próximo intento en {wait_remaining} segundos.")
            continue

        print(f"Sincronizando {name}...")
        try:
            url = f"{SYNAPSE_URL}{name}"
            data = {"timerange": module['timerange']}
            headers = {"Authorization": f"Bearer {TOKEN}"}
            
            # Timeout corto para el request al proxy local
            response = requests.post(url, json=data, headers=headers, timeout=305) # 5 min + 5s buffer
            
            if response.status_code == 200:
                res_data = response.json()
                if res_data.get('success'):
                    print(f"Resultado {name}: Éxito")
                    m_state['failures'] = 0
                    m_state['next_attempt'] = 0
                elif res_data.get('reason') == 'server_down':
                    # El conector detectó que el servidor remoto no responde
                    m_state['failures'] += 1
                    delay = min(INITIAL_DELAY * (2 ** (m_state['failures'] - 1)), MAX_DELAY)
                    m_state['next_attempt'] = current_time + delay
                    print(f"Resultado {name}: Servidor remoto DOWN. Aplicando backoff de {delay}s (Fallo #{m_state['failures']})")
                else:
                    print(f"Resultado {name}: Error lógico - {res_data.get('message', 'No message')}")
            else:
                # Error de servidor (500 o similar) - también aplicamos backoff por si acaso
                m_state['failures'] += 1
                delay = min(INITIAL_DELAY * (2 ** (m_state['failures'] - 1)), MAX_DELAY)
                m_state['next_attempt'] = current_time + delay
                print(f"Resultado {name}: HTTP {response.status_code}. Aplicando backoff de {delay}s")

        except Exception as e:
            # Error de conexión local o timeout severo
            m_state['failures'] += 1
            delay = min(INITIAL_DELAY * (2 ** (m_state['failures'] - 1)), MAX_DELAY)
            m_state['next_attempt'] = current_time + delay
            print(f"Error en {name}: {e}. Aplicando backoff de {delay}s")

        state[name] = m_state

    save_state(state)

if __name__ == "__main__":
    run_sync()
