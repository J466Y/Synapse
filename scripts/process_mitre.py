#!/usr/bin/env python3
# -*- coding: utf8 -*-

import json
import os

def process_mitre(input_path, output_path):
    if not os.path.exists(input_path):
        print(f"Error: Input file {input_path} not found.")
        return

    print(f"Reading {input_path}...")
    with open(input_path, 'r') as f:
        data = json.load(f)

    processed_techniques = []

    for obj in data.get('objects', []):
        # We only want techniques (attack-pattern)
        if obj.get('type') == 'attack-pattern':
            technique = {
                "name": obj.get('name'),
                "id": obj.get('id'),
                "kill_chain_phases": obj.get('kill_chain_phases', []),
                "external_id": None
            }

            # Extract the MITRE external ID (e.g., T1059)
            external_refs = obj.get('external_references', [])
            for ref in external_refs:
                if ref.get('source_name') == 'mitre-attack':
                    technique["external_id"] = ref.get('external_id')
                    break
            
            if technique["external_id"]:
                processed_techniques.append(technique)

    print(f"Extracted {len(processed_techniques)} techniques.")

    with open(output_path, 'w') as f:
        json.dump(processed_techniques, f, indent=4)
    
    print(f"Saved processed data to {output_path}")

if __name__ == "__main__":
    base_path = "/opt/Synapse/conf/mitre_mapping"
    input_file = os.path.join(base_path, "enterprise-attack.json")
    output_file = os.path.join(base_path, "mitre_techniques.json")
    
    process_mitre(input_file, output_file)
