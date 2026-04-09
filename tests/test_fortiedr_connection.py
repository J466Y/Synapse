import sys
import os
import logging
from datetime import datetime
import platform

# Add Synapse to sys.path
synapse_dir = "localpathtosynapse"

if platform.system() == "Windows":
    if not os.path.exists(synapse_dir):
        print("There is no local Synapse Path! ERROR!!")
        exit(1)
else:
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

        print("[*] Testing list_events...")
        minutes = 300
        events_result = connector.list_events(minutes)
        if events_result['status']:
            events = events_result['data']
            print(f"[+] Successfully fetched {len(events)} events")
            if events:
                event = events[0]
                # Extracting as in integration.py
                event_id = event.get('eventId')
                collectors = event.get('collectors', [])
                process = event.get('process', 'N/A')
                device = collectors[0].get('device', 'Unknown') if collectors else 'Unknown'
                device_ip = collectors[0].get('ip', 'N/A') if collectors else 'N/A'
                rules = event.get('rules', [])
                rule = rules[0] if rules else 'N/A'
                
                
                print(f"[+] Verified Event ID: {event_id}")
                print(f"[+] Verified Device: {device}")
                print(f"[+] Verified IP: {device_ip}")
                print(f"[+] Verified Process: {process}")
                print(f"[+] Verified Rule: {rule}")
                print(f"[+] Verified Last Seen: {event.get('lastSeen')}")
            else:
                print(f"[-] No events found in {minutes} minutes.")
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
