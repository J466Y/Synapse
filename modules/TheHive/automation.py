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
        Supports CIDR notation, hyphenated ranges (1.1.1.1-1.1.1.5), and single IPs.
        """
        try:
            observable_ip = ipaddress.ip_address(ip_str)
            for entry in blacklist:
                entry = entry.strip()
                if not entry:
                    continue
                try:
                    # Case 1: CIDR Notation (192.168.1.0/24)
                    if '/' in entry:
                        network = ipaddress.ip_network(entry, strict=False)
                        if observable_ip in network:
                            logger.debug('IP %s matched CIDR blacklist entry %s', ip_str, entry)
                            return True
                    
                    # Case 2: Hyphenated Range (212.55.27.130-212.55.27.135)
                    elif '-' in entry:
                        start_ip_str, end_ip_str = entry.split('-')
                        start_ip = ipaddress.ip_address(start_ip_str.strip())
                        end_ip = ipaddress.ip_address(end_ip_str.strip())
                        if start_ip <= observable_ip <= end_ip:
                            logger.debug('IP %s matched range blacklist entry %s', ip_str, entry)
                            return True
                    
                    # Case 3: Single IP
                    else:
                        if observable_ip == ipaddress.ip_address(entry):
                            logger.debug('IP %s matched single IP blacklist entry %s', ip_str, entry)
                            return True
                except ValueError:
                    logger.warning('Invalid blacklist entry: %s', entry)
                    continue
        except ValueError:
            logger.warning('Invalid IP address for blacklist check: %s', ip_str)
            return False
        return False

    def parse_hooks(self):
        """
        Parse incoming webhooks and trigger enrichment for new observables.

        Only acts on webhooks where:
        - objectType == 'case_artifact', 'case', or 'alert'
        - operation == 'Creation' OR status == 'Imported'
        """
        # List of observables to process
        observables_to_process = []

        if self.webhook.isNewArtifact():
            # It's a single artifact creation, data is already in the webhook
            logger.debug('New observable detected in webhook. Processing directly.')
            observables_to_process.append(self.webhook.data.get('object', {}))
        
        elif self.webhook.isNewCase() or self.webhook.isImportedAlert() or self.webhook.isNewAlert():
            # It's a case or alert. We fetch observables via API for efficiency and completeness.
            obj = self.webhook.data.get('object', {})
            obj_id = obj.get('id') or self.webhook.data.get('objectId', '')
            obj_type = self.webhook.data.get('objectType')
            
            logger.info('Detected %s with ID: %s. Fetching observables...', obj_type, obj_id)

            if obj_type.lower() == 'case':
                logger.info('Calling TheHive API to get observables for Case %s', obj_id)
                observables = self.TheHiveConnector.getCaseObservables(obj_id)
                if observables:
                    logger.info('Found %d observables in Case %s', len(observables), obj_id)
                    observables_to_process.extend(observables)
                else:
                    logger.warning('No observables returned by API for Case %s', obj_id)
            
            elif obj_type.lower() == 'alert':
                logger.info('Calling TheHive API to get artifacts for Alert %s', obj_id)
                artifacts = self.TheHiveConnector.getAlertArtifacts(obj_id)
                if artifacts:
                    logger.info('Found %d artifacts in Alert %s', len(artifacts), obj_id)
                    observables_to_process.extend(artifacts)
                else:
                    logger.warning('No artifacts returned by API for Alert %s', obj_id)
        else:
            return False

        # Automated IP Correlation
        try:
            self.correlateByIP()
        except Exception as e:
            logger.error(f"IP Correlation failed: {e}", exc_info=True)

        if not observables_to_process:
            logger.debug('No observables found to process for this webhook.')
            return False

        total_success = 0
        total_fail = 0

        for observable in observables_to_process:
            data_type = observable.get('dataType', '')
            observable_id = observable.get('_id') or observable.get('id')
            observable_data = observable.get('data', '')
            tags = observable.get('tags', [])

            # Skip if already enriched or has reports
            if observable.get('reports') or 'enriched' in tags:
                logger.info('Observable %s (%s) already has reports or is tagged as enriched. Skipping.', 
                            observable_data, observable_id)
                continue

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
                    logger.info('Running analyzer %s via TheHive for observable %s (%s)',
                               analyzer, observable_data, observable_id)
                    
                    # Run via TheHive API to ensure reports are linked
                    self.TheHiveConnector.runAnalyzer(
                        self.cortex_instance,
                        observable_id,
                        analyzer
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

    def correlateByIP(self):
        """
        Correlate alerts by IP address. 
        If multiple alerts share the same non-private, non-blacklisted IP, group them in a case.
        """
        logger.debug('Automation.correlateByIP starts')
        
        # Configuration
        enabled = self.cfg.getboolean('Correlation', 'enabled', fallback=False)
        if not enabled:
            return False

        blacklist = [ip.strip() for ip in self.cfg.get('Correlation', 'ip_blacklist', fallback="").split(',')]
        include_private = self.cfg.getboolean('Correlation', 'include_private', fallback=False)

        # Extraction logic depends on webhook type
        ip_to_check = None
        alert_id = None

        if self.webhook.isNewArtifact():
            if self.webhook.data['object'].get('dataType') == 'ip':
                ip_to_check = self.webhook.data['object'].get('data')
                # For an artifact, we need to know which alert it belongs to
                alert_id = self.webhook.data.get('rootId')
                if alert_id and alert_id.startswith('~'): # It's an alert ID
                    pass
                else:
                    logger.debug("Artifact does not belong to an alert (likely a case). Skipping correlation.")
                    return False
        elif self.webhook.isNewAlert():
            # For a new alert, we check all its artifacts
            artifacts = self.webhook.data['object'].get('artifacts', [])
            for artifact in artifacts:
                if artifact.get('dataType') == 'ip':
                    ip_to_check = artifact.get('data')
                    alert_id = self.webhook.data['object']['id']
                    break # We correlate by the first IP found for now
        
        if not ip_to_check or not alert_id:
            return False

        # Validate IP
        try:
            ip_obj = ipaddress.ip_address(ip_to_check)
            if not include_private and ip_obj.is_private:
                logger.info(f"Skipping correlation for private IP: {ip_to_check}")
                return False
            if self._is_blacklisted_ip(ip_to_check, blacklist):
                logger.info(f"Skipping correlation for blacklisted IP: {ip_to_check}")
                return False
        except ValueError:
            logger.warning(f"Invalid IP address format: {ip_to_check}")
            return False

        logger.info(f"Correlating alert {alert_id} by IP {ip_to_check}")

        # Search for other alerts with this IP
        matching_alerts = self.TheHiveConnector.findAlertsByObservable(ip_to_check, 'ip')
        
        # Filter out current alert
        other_alerts = [a for a in matching_alerts if a['id'] != alert_id]
        
        if not other_alerts:
            logger.debug(f"No other alerts found with IP {ip_to_check}")
            return False

        # Check if any alert (including current) is already in a case
        target_case_id = None
        
        # 1. Check if current alert has a case
        current_alert = self.TheHiveConnector.getAlert(alert_id)
        if current_alert.get('case'):
            target_case_id = current_alert['case']
        
        # 2. Check if others have a case
        if not target_case_id:
            for alert in other_alerts:
                if alert.get('case'):
                    target_case_id = alert['case']
                    break

        if target_case_id:
            logger.info(f"Found existing case {target_case_id} for correlation. Merging...")
            # If current alert is not in the case, merge it
            if current_alert.get('case') != target_case_id:
                self.TheHiveConnector.mergeAlertIntoCase(alert_id, target_case_id)
            
            # Ensure all other alerts are also in this case
            for alert in other_alerts:
                if alert.get('case') != target_case_id:
                    try:
                        self.TheHiveConnector.mergeAlertIntoCase(alert['id'], target_case_id)
                    except Exception as e:
                        logger.warning(f"Failed to merge alert {alert['id']} into case {target_case_id}: {e}")
        else:
            # No case exists, create a new one from the first alert
            logger.info(f"No existing case found. Creating new case from alert {other_alerts[0]['id']}...")
            new_case = self.TheHiveConnector.promoteAlertToCase(other_alerts[0]['id'])
            target_case_id = new_case['id']
            
            # Merge all other alerts (including current)
            all_alerts = [alert_id] + [a['id'] for a in other_alerts[1:]]
            for aid in all_alerts:
                try:
                    self.TheHiveConnector.mergeAlertIntoCase(aid, target_case_id)
                except Exception as e:
                    logger.warning(f"Failed to merge alert {aid} into new case {target_case_id}: {e}")

        return True
