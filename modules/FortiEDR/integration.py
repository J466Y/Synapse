#!/usr/bin/env python3
# -*- coding: utf8 -*-

import os
import sys
import logging
import copy
import json
import datetime
import re
from thehive4py.query import Eq, And
from core.integration import Main
from modules.FortiEDR.connector import FortiEDRConnector
from modules.TheHive.connector import TheHiveConnector

class Integration(Main):
    """FortiEDR Integration for Synapse"""

    def __init__(self):
        super().__init__()
        self.logger = logging.getLogger(__name__)
        self.fortiedrConnector = FortiEDRConnector(self.cfg)
        self.theHiveConnector = TheHiveConnector(self.cfg)
        # Verify connection to TheHive as well
        self.theHiveConnector.test_connection()

    def enrichEvent(self, event):
        """
        Enrich a FortiEDR event with observables (artifacts)
        :param event: raw event dict from FortiEDR
        :return: enriched event dict
        """
        enriched = copy.deepcopy(event)
        artifacts = []

        # Extract observables based on common FortiEDR fields
        # Device / Hostname
        collectors = event.get('collectors', [])
        if collectors and isinstance(collectors, list):
            device = collectors[0].get('device')
            if device:
                artifacts.append({'data': device, 'dataType': 'hostname', 'message': 'Endpoint Name', 'tags': ['FortiEDR']})

            # Device IP
            device_ip = collectors[0].get('ip')
            if device_ip:
                artifacts.append({'data': device_ip, 'dataType': 'ip', 'message': 'Endpoint IP', 'tags': ['FortiEDR']})

        # Process / File Name
        process = event.get('process')
        if process:
            artifacts.append({'data': process, 'dataType': 'filename', 'message': 'Process Name', 'tags': ['FortiEDR']})

        # File Hash - Not directly available in top-level keys seen in test, 
        # but leaving if it might appear in other event types or subfields.
        file_hash = event.get('fileHash')
        if file_hash:
            data_type = 'hash'
            if len(file_hash) == 32:
                data_type = 'md5'
            elif len(file_hash) == 40:
                data_type = 'sha1'
            elif len(file_hash) == 64:
                data_type = 'sha256'
            artifacts.append({'data': file_hash, 'dataType': data_type, 'message': 'Process File Hash', 'tags': ['FortiEDR']})

        # Process Path
        path = event.get('processPath')
        if path:
            # dataType changed to 'other' to prevent local FileNotFoundError
            artifacts.append({'data': path, 'dataType': 'other', 'message': 'Process Path', 'tags': ['FortiEDR']})

        # Rules and Tags
        tags = ['FortiEDR']
        rules = event.get('rules', [])
        if rules and isinstance(rules, list):
            enriched['automation_identifiers'] = rules
            for rule in rules:
                if isinstance(rule, str) and rule:
                    tags.append(rule)

        # Additional Observables from exhaustive list
        # Destinations
        destinations = event.get('destinations', [])
        if destinations and isinstance(destinations, list):
            for dest in destinations:
                artifacts.append({'data': dest, 'dataType': 'ip', 'message': 'Communication Destination', 'tags': ['FortiEDR']})

        # Logged Users
        logged_users = event.get('loggedUsers', [])
        if logged_users and isinstance(logged_users, list):
                # Fixed: Use 'user-account' instead of 'user'
                artifacts.append({'data': user, 'dataType': 'user-account', 'message': 'Logged User', 'tags': ['FortiEDR']})

        # Process Owner
        process_owner = event.get('processOwner')
            # Fixed: Use 'user-account' instead of 'user'
            artifacts.append({'data': process_owner, 'dataType': 'user-account', 'message': 'Process Owner', 'tags': ['FortiEDR']})

        # Remove observables that are to be excluded based on the configuration
        artifacts = self.checkObservableExclusionList(artifacts)

        # Match observables against the TLP list
        artifacts = self.checkObservableTLP(artifacts)

        # Craft artifacts using TheHiveConnector
        hiveArtifacts = []
        for artifact in artifacts:
            hiveArtifact = self.theHiveConnector.craftAlertArtifact(
                dataType=artifact['dataType'],
                data=artifact['data'],
                message=artifact['message'],
                tags=artifact['tags'],
                tlp=artifact.get('tlp', self.cfg.get('Automation', 'default_observable_tlp', fallback=2))
            )
            hiveArtifacts.append(hiveArtifact)

        enriched['artifacts'] = hiveArtifacts
        enriched['tags'] = tags
        return enriched

    def fortiedrEventToHiveAlert(self, event):
        """
        Convert an enriched FortiEDR event to TheHive alert format
        :param event: enriched event dict
        :return: TheHive alert dict
        """
        # Severity mapping
        severity_map = {
            'Critical': 4,
            'High': 4,
            'Medium': 3,
            'Low': 2,
            'Info': 1
        }
        severity = severity_map.get(event.get('severity'), 2)
        
        # Case Template
        case_template = self.cfg.get('FortiEDR', 'case_template', fallback='FortiEDR')
        
        # Description
        description = "### FortiEDR Security Event\n\n"
        
        # Extract device and IP from collectors list
        collectors = event.get('collectors', [])
        device = collectors[0].get('device', 'Unknown') if collectors else 'Unknown'
        device_ip = collectors[0].get('ip', 'N/A') if collectors else 'N/A'
        rules = event.get('rules', [])
        rule = rules[0] if rules else 'N/A'

        description += f"* **ID:** {event.get('eventId')}\n"
        description += f"* **Device:** {device} (Group: {collectors[0].get('collectorGroup', 'N/A') if collectors else 'N/A'})\n"
        description += f"* **IP:** {device_ip} (OS: {collectors[0].get('os', 'Unknown') if collectors else 'Unknown'})\n"
        description += f"* **Process:** {event.get('process', 'N/A')} ({event.get('processType', 'N/A')})\n"
        description += f"* **Path:** {event.get('processPath', 'N/A')}\n"
        description += f"* **Certified:** {'Yes' if event.get('certified') else 'No'}\n"
        description += f"* **Owner:** {event.get('processOwner', 'N/A')}\n"
        description += f"* **Severity:** {event.get('severity')}\n"
        description += f"* **Classification:** {event.get('classification', 'N/A')}\n"
        description += f"* **Action:** {event.get('action', 'N/A')}\n"
        description += f"* **Rule:** {rule}\n"
        
        threat_family = event.get('threatFamily') or (event.get('threatDetails', {}).get('threatFamily') if isinstance(event.get('threatDetails'), dict) else 'N/A')
        threat_type = event.get('threatType') or (event.get('threatDetails', {}).get('threatType') if isinstance(event.get('threatDetails'), dict) else 'N/A')
        threat_name = event.get('threatName') or (event.get('threatDetails', {}).get('threatName') if isinstance(event.get('threatDetails'), dict) else 'N/A')
        
        description += f"* **Threat Family:** {threat_family}\n"
        description += f"* **Threat Type:** {threat_type}\n"
        description += f"* **Threat Name:** {threat_name}\n"
        description += f"* **Last Seen:** {event.get('lastSeen', 'N/A')}\n"
        description += f"* **First Seen:** {event.get('firstSeen', 'N/A')}\n"
        description += f"* **Handled:** {'Yes' if event.get('handled') else 'No'}\n"

        last_seen_str = event.get('lastSeen')
        alert_date = int(datetime.datetime.now().timestamp() * 1000)
        if last_seen_str:
            try:
                # Format: "Fri Apr 10 00:00:00 UTC 2026"
                parts = last_seen_str.split(" ")
                if len(parts) >= 6:
                    clean_str = " ".join(parts[:4] + parts[5:])
                    parsed_date = datetime.datetime.strptime(clean_str, '%a %b %d %H:%M:%S %Y')
                    alert_date = int(parsed_date.timestamp() * 1000) # Epoch ms
            except Exception as e:
                self.logger.warning("Failed to parse lastSeen date '%s': %s", last_seen_str, e)

        # Build TheHive alert using craftAlert
        alert = self.theHiveConnector.craftAlert(
            title=f"FortiEDR: {event.get('classification', 'Security Event')} on {device}",
            description=description,
            severity=severity,
            date=alert_date,
            tags=event.get('tags', ['FortiEDR']),
            tlp=int(self.cfg.get('Automation', 'default_observable_tlp', fallback=2)),
            status='New',
            type='FortiEDR Alert',
            source='FortiEDR',
            sourceRef=str(event.get('eventId')),
            artifacts=event.get('artifacts', []),
            caseTemplate=case_template
        )
        
        return alert

    def validateRequest(self, request):
        """
        Handle incoming API requests to the FortiEDR endpoint
        """
        if request.is_json:
            content = request.get_json()
            if 'timerange' in content:
                workflowReport = self.allEvents2Alerts(content['timerange'])
                if workflowReport['success']:
                    return json.dumps(workflowReport), 200
                else:
                    return json.dumps(workflowReport), 500
            else:
                self.logger.error('Missing <timerange> key/value')
                return json.dumps({'success': False, 'message': "timerange key missing in request"}), 400
        else:
            self.logger.error('Not json request')
            return json.dumps({'success': False, 'message': "Request didn't contain valid JSON"}), 400

    def allEvents2Alerts(self, timerange_minutes=60):
        """
        Pull events and create alerts in TheHive with deduplication
        """
        self.logger.info("FortiEDR.allEvents2Alerts starts (timerange: %s min)", timerange_minutes)
        report = {'success': True, 'events': []}
        
        result = self.fortiedrConnector.list_events(timerange_minutes=timerange_minutes)
        if not result['status']:
            self.logger.error("Failed to pull events: %s", result['data'])
            report['success'] = False
            report['message'] = str(result['data'])
            return report
            
        events = result['data']
        if not isinstance(events, list):
            events = events.get('events', [])
            
        for event in events:
            event_id = event.get('eventId')
            event_report = {'event_id': event_id, 'success': True}
            
            # Deduplication: check if alert already exists
            query = dict()
            query['sourceRef'] = str(event_id)
            results = self.theHiveConnector.findAlert(query)
            
            if results is None:
                self.logger.error('Failed to search for alert with event %s, skipping', event_id)
                event_report['success'] = False
                event_report['message'] = 'findAlert returned None'
                report['success'] = False
                report['events'].append(event_report)
                continue
            
            if len(results) == 0:
                self.logger.info('Event %s not found in TheHive, creating alert', event_id)
                try:
                    enriched = self.enrichEvent(event)
                    alert = self.fortiedrEventToHiveAlert(enriched)
                    created_alert = self.theHiveConnector.createAlert(alert)
                    if created_alert:
                        event_report['raised_alert_id'] = created_alert.get('id')
                    else:
                        raise Exception("createAlert returned None, likely due to HTTP 400")
                except Exception as e:
                    self.logger.error('Failed to create alert for event %s: %s', event_id, e, exc_info=True)
                    event_report['success'] = False
                    event_report['message'] = str(e)
                    report['success'] = False
            else:
                self.logger.info('Event %s already imported as alert, skipping', event_id)
                event_report['message'] = 'Already imported'
                
            report['events'].append(event_report)
            
        return report

    # Public methods for automation rules
    def isolateDevice(self, device):
        """
        Action: Isolate device
        """
        return self.fortiedrConnector.isolate_collector(device)

    def unisolateDevice(self, device):
        """
        Action: Unisolate device
        """
        return self.fortiedrConnector.unisolate_collector(device)

    def remediateDevice(self, device, process_id=0):
        """
        Action: Remediate device
        """
        return self.fortiedrConnector.remediate_device(device, process_id)
