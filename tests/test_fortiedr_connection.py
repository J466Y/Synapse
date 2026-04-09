import sys
import os
import logging
from datetime import datetime

# Add Synapse to sys.path
synapse_dir = "/opt/Synapse"
sys.path.append(synapse_dir)

from core.functions import getConf
from modules.FortiEDR.connector import FortiEDRConnector

# Configure logging to see what's happening
logging.basicConfig(level=logging.DEBUG)

def test_connection():
    try:
        print("[*] Loading configuration...")
        cfg = getConf()
        
        print("[*] Initializing FortiEDR Connector...")
        connector = FortiEDRConnector(cfg)
        
        print("[*] Testing authentication...")
        auth_result = connector.authenticate()
        if auth_result['status']:
            print("[+] Authentication SUCCESSFUL")
        else:
            print(f"[-] Authentication FAILED: {auth_result['data']}")
            return

        print("[*] Testing list_events (last 120 minutes)...")
        events_result = connector.list_events(120)
        if events_result['status']:
            events = events_result['data']
            print(f"[+] Successfully fetched {len(events)} events")
            if events:
                print(f"[+] First event ID: {events[0].get('id')}")
        else:
            print(f"[-] Failed to fetch events: {events_result['data']}")

        print("[*] Testing list_collectors...")
        collectors_result = connector.list_collectors()
        if collectors_result['status']:
            collectors = collectors_result['data']
            print(f"[+] Successfully fetched {len(collectors)} collectors")
        else:
            print(f"[-] Failed to fetch collectors: {collectors_result['data']}")

    except Exception as e:
        print(f"[!] Unexpected error during test: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_connection()
