#!/usr/bin/env python3
# -*- coding: utf8 -*-

import json
import csv
import os
import logging

class MitreMapper:
    """
    Utility class to map events to MITRE ATT&CK TTPs.
    """
    def __init__(self, cfg):
        self.cfg = cfg
        self.logger = logging.getLogger(__name__)
        self.base_path = "/opt/Synapse/conf/mitre_mapping"
        self.techniques_path = os.path.join(self.base_path, "mitre_techniques.json")
        self.qradar_csv_path = os.path.join(self.base_path, "QRadar_Rules_To_Mitre.csv")
        
        self.techniques_by_id = {}
        self.techniques_by_name = {}
        self._load_techniques()
        
        self.qradar_mappings = {}
        self._load_qradar_mappings()

    def _load_techniques(self):
        """Load the processed MITRE techniques JSON."""
        if os.path.exists(self.techniques_path):
            try:
                with open(self.techniques_path, 'r') as f:
                    data = json.load(f)
                    for tech in data:
                        self.techniques_by_id[tech['external_id']] = tech
                        self.techniques_by_name[tech['name'].lower()] = tech
                self.logger.info(f"Loaded {len(self.techniques_by_id)} MITRE techniques.")
            except Exception as e:
                self.logger.error(f"Failed to load MITRE techniques: {e}")

    def _load_qradar_mappings(self):
        """Load the QRadar Rules to MITRE CSV."""
        if os.path.exists(self.qradar_csv_path):
            try:
                with open(self.qradar_csv_path, 'r', encoding='utf-8') as f:
                    # Some versions of this CSV might have a 'z' or BOM at the start
                    content = f.read()
                    if content.startswith('z"'):
                        content = content[1:]
                    
                    lines = content.splitlines()
                    reader = csv.DictReader(lines)
                    for row in reader:
                        rule_name = row.get('Rule name')
                        if not rule_name:
                            continue
                        
                        if rule_name not in self.qradar_mappings:
                            self.qradar_mappings[rule_name] = []
                        
                        # Use Sub-technique if available, otherwise Technique
                        tech_name = row.get('Sub-technique')
                        if not tech_name or tech_name == "None":
                            tech_name = row.get('Technique')
                        
                        if tech_name and tech_name != "None":
                            self.qradar_mappings[rule_name].append(tech_name)
                self.logger.info(f"Loaded {len(self.qradar_mappings)} QRadar rule mappings.")
            except Exception as e:
                self.logger.error(f"Failed to load QRadar MITRE mappings: {e}")

    def get_mitre_info_by_id(self, technique_id):
        """Get MITRE info (name, phases) by external ID (e.g., T1059)."""
        return self.techniques_by_id.get(technique_id)

    def get_mitre_info_by_name(self, technique_name):
        """Get MITRE info by technique name."""
        return self.techniques_by_name.get(technique_name.lower())

    def get_tags_for_technique(self, technique_info):
        """Generate tags for a technique and its associated tactics."""
        tags = set()
        if not technique_info:
            return tags
        
        # Technique ID tag
        tags.add(technique_info['external_id'])
        
        # Tactics (phase_name) tags
        for phase in technique_info.get('kill_chain_phases', []):
            if phase.get('phase_name'):
                tags.add(phase['phase_name'])
        
        return tags

    def get_qradar_mitre_tags(self, rule_names):
        """Generate tags for QRadar events based on rule names."""
        all_tags = set()
        for rule in rule_names:
            name = rule.get('name')
            if name in self.qradar_mappings:
                for tech_name in self.qradar_mappings[name]:
                    info = self.get_mitre_info_by_name(tech_name)
                    if info:
                        all_tags.update(self.get_tags_for_technique(info))
        return list(all_tags)

    def get_darktrace_mitre_tags(self, mitre_data):
        """Generate tags for Darktrace events based on MITRE data in response."""
        all_tags = set()
        techniques = mitre_data.get('techniques', [])
        for tech_id in techniques:
            info = self.get_mitre_info_by_id(tech_id)
            if info:
                all_tags.update(self.get_tags_for_technique(info))
        return list(all_tags)
