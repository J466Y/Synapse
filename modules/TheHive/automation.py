#!/usr/bin/env python3
# -*- coding: utf8 -*-

"""
TheHive Automation Module - Observable Enrichment

Automatically runs Cortex analyzers when new observables are created in cases.
This works universally for ALL cases, regardless of tags.

Supported observable types: ip, domain, fqdn, hash
"""

import logging
import ipaddress
import re

from modules.TheHive.connector import TheHiveConnector
from modules.Cortex.connector import CortexConnector

logger = logging.getLogger(__name__)

# Default analyzer mappings per dataType
DEFAULT_ENRICHMENT = {
    'ip': {
        'analyzers': [
            'AbuseIPDB_2_0',
            'Abuse_Finder_3_0',
            'Censys_2_0',
            'DShield_lookup_1_0',
            'GreyNoise_3_2',
            'IBMXForce_Lookup_1_0',
            'MISP_2_1',
            'MaxMind_GeoIP_4_0',
            'OTXQuery_2_0',
            'Pulsedive_GetIndicator_1_0',
            'Robtex_IP_Query_1_0',
            'Shodan_Host_1_0',
            'Shodan_Host_History_1_0',
            'VirusTotal_GetReport_3_1',
        ],
        'blacklist': [
            '10.0.0.0/8',
            '172.16.0.0/12',
            '192.168.0.0/16',
            '127.0.0.0/8',
            '169.254.0.0/16',
            '0.0.0.0/32',
        ]
    },
    'domain': {
        'analyzers': [
            'CyberCrime-Tracker_1_0',
            'Cyberprotect_ThreatScore_3_0',
            'DNSdumpster_report_1_0',
            'Lookyloo_Screenshot_1_0',
            'MISP_2_1',
            'OTXQuery_2_0',
            'Pulsedive_GetIndicator_1_0',
            'Robtex_Forward_PDNS_Query_1_0',
            'Robtex_Reverse_PDNS_Query_1_0',
            'Shodan_InfoDomain_1_0',
            'Shodan_ReverseDNS_1_0',
            'VirusTotal_GetReport_3_1',
        ]
    },
    'fqdn': {
        'analyzers': [
            'CyberCrime-Tracker_1_0',
            'Cyberprotect_ThreatScore_3_0',
            'DNSdumpster_report_1_0',
            'Lookyloo_Screenshot_1_0',
            'MISP_2_1',
            'OTXQuery_2_0',
            'Pulsedive_GetIndicator_1_0',
            'Robtex_Forward_PDNS_Query_1_0',
            'Robtex_Reverse_PDNS_Query_1_0',
            'Shodan_InfoDomain_1_0',
            'Shodan_ReverseDNS_1_0',
            'VirusTotal_GetReport_3_1',
        ]
    },
    'hash': {
        'analyzers': [
            'CIRCLHashlookup_1_1',
            'CIRCLVulnerabilityLookup_1_0',
            'HybridAnalysis_GetReport_1_0',
            'IBMXForce_Lookup_1_0',
            'MISP_2_1',
            'MalwareBazaar_1_0',
            'OTXQuery_2_0',
            'Pulsedive_GetIndicator_1_0',
            'VirusTotal_GetReport_3_1',
        ]
    }
}


class Automation():
    """
    TheHive automation module for universal observable enrichment.

    When a new observable (case_artifact) is created in any case,
    this module automatically launches the appropriate Cortex analyzers
    based on the observable's dataType.
    """

    def __init__(self, webhook, cfg):
        logger.info('Initiating TheHive Observable Enrichment Automation')
        self.webhook = webhook
        self.cfg = cfg
        self.TheHiveConnector = TheHiveConnector(cfg)
        self.CortexConnector = CortexConnector(cfg)
        self.report_action = 'None'

        # Load enrichment configuration from synapse.conf or use defaults
        self.cortex_instance = self.cfg.get('TheHive', 'enrichment', fallback=None)
        if self.cortex_instance and isinstance(self.cortex_instance, dict):
            self.cortex_instance = self.cortex_instance.get('cortex_instance', 'Cortex')
        else:
            self.cortex_instance = 'Cortex'

        self.enrichment_config = self._load_enrichment_config()

    def _load_enrichment_config(self):
        """
        Load enrichment configuration from synapse.conf.
        Falls back to DEFAULT_ENRICHMENT if not configured.
        """
        enrichment_cfg = self.cfg.get('TheHive', 'enrichment', fallback=None)

        if enrichment_cfg and isinstance(enrichment_cfg, dict):
            config = {}
            for datatype in ['ip', 'domain', 'fqdn', 'hash']:
                dt_cfg = enrichment_cfg.get(datatype)
                if dt_cfg and isinstance(dt_cfg, dict):
                    config[datatype] = {
                        'analyzers': dt_cfg.get('analyzers', DEFAULT_ENRICHMENT.get(datatype, {}).get('analyzers', [])),
                        'blacklist': dt_cfg.get('blacklist', DEFAULT_ENRICHMENT.get(datatype, {}).get('blacklist', []))
                    }
                elif datatype in DEFAULT_ENRICHMENT:
                    config[datatype] = DEFAULT_ENRICHMENT[datatype]
            return config
        else:
            logger.info('No enrichment configuration found in synapse.conf, using defaults')
            return DEFAULT_ENRICHMENT

    def _is_blacklisted_ip(self, ip_str, blacklist):
        """
        Check if an IP address matches any entry in the blacklist.
        Supports CIDR notation and single IPs.
        """
        try:
            observable_ip = ipaddress.ip_address(ip_str)
            for entry in blacklist:
                try:
                    if '/' in entry:
                        network = ipaddress.ip_network(entry, strict=False)
                        if observable_ip in network:
                            logger.debug('IP %s matched blacklist entry %s', ip_str, entry)
                            return True
                    else:
                        if observable_ip == ipaddress.ip_address(entry):
                            logger.debug('IP %s matched blacklist entry %s', ip_str, entry)
                            return True
                except ValueError:
                    logger.warning('Invalid blacklist entry: %s', entry)
                    continue
        except ValueError:
            logger.warning('Invalid IP address for blacklist check: %s', ip_str)
            return False
        return False

    def _extract_observables_from_text(self, text):
        """
        Extract potential observables from text using regex.
        Returns a list of artifact-like dicts.
        """
        extracted = []
        
        # Regex patterns
        patterns = {
            'ip': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            'domain': r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b',
            'hash': r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b'
        }

        for data_type, pattern in patterns.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in set(matches):  # De-duplicate
                extracted.append({
                    'dataType': data_type,
                    'data': match,
                    'id': f'extracted-{data_type}-{match}' # Synthetic ID for logging
                })
        
        return extracted

    def parse_hooks(self):
        """
        Parse incoming webhooks and trigger enrichment for new observables.

        Only acts on webhooks where:
        - objectType == 'case_artifact', 'case', or 'alert'
        - operation == 'Creation'
        """
        # List of observables to process
        observables_to_process = []

        if self.webhook.isNewArtifact():
            # It's a single artifact creation
            observables_to_process.append(self.webhook.data.get('object', {}))
        elif self.webhook.isNewCase() or self.webhook.isNewAlert():
            # It's a case or alert creation
            obj = self.webhook.data.get('object', {})
            
            # 1. Check for bundled artifacts
            if 'artifacts' in obj and isinstance(obj['artifacts'], list) and len(obj['artifacts']) > 0:
                observables_to_process.extend(obj['artifacts'])
            
            # 2. Fallback: extract from description if no artifacts are bundled
            description = obj.get('description', '')
            if description:
                logger.info('No bundled artifacts found. Attempting regex extraction from description.')
                extracted = self._extract_observables_from_text(description)
                if extracted:
                    logger.info('Extracted %d observables from description via regex.', len(extracted))
                    observables_to_process.extend(extracted)
        else:
            return False

        if not observables_to_process:
            return False

        total_success = 0
        total_fail = 0

        for observable in observables_to_process:
            data_type = observable.get('dataType', '')
            observable_id = observable.get('_id') or observable.get('id')
            observable_data = observable.get('data', '')

            # Check if this dataType has enrichment configured
            if data_type not in self.enrichment_config:
                continue

            enrichment = self.enrichment_config[data_type]
            analyzers = enrichment.get('analyzers', [])
            blacklist = enrichment.get('blacklist', [])

            if not analyzers:
                continue

            # Check IP blacklist
            if data_type == 'ip' and blacklist:
                if self._is_blacklisted_ip(observable_data, blacklist):
                    logger.info('Observable %s (%s) is blacklisted, skipping enrichment',
                               observable_data, observable_id)
                    continue

            # Run all configured analyzers
            logger.info('Starting enrichment for %s observable %s (%s) with %d analyzers',
                        data_type, observable_data, observable_id, len(analyzers))

            for analyzer in analyzers:
                try:
                    logger.info('Running analyzer %s directly via Cortex for observable %s',
                               analyzer, observable_data)
                    
                    # Using direct Cortex API as requested
                    self.CortexConnector.runAnalyzer(
                        analyzer,
                        observable_data,
                        data_type
                    )
                    total_success += 1
                except Exception as e:
                    logger.error('Failed to run analyzer %s for observable %s: %s',
                                analyzer, observable_id, e)
                    total_fail += 1

        if total_success > 0 or total_fail > 0:
            self.report_action = {
                'status': total_success > 0,
                'message': f'Enrichment completed: {total_success} analyzers launched, {total_fail} failed'
            }
            logger.info('Enrichment result: %s', self.report_action['message'])
            return self.report_action
        
        return False
