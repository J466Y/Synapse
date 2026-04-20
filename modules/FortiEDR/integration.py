#!/usr/bin/env python3
# -*- coding: utf8 -*-

import os
import sys
import logging
import copy
import json
import datetime
import re
from core.integration import Main
from thehive4py.query import And, Eq
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

        # Extract observables based on common FortiEDR fields (Flat or Nested structure)
        # Device / Hostname (Endpoint)
        device = event.get('device') or event.get('collectorName')
        if device:
            artifacts.append({'data': device, 'dataType': 'hostname', 'message': 'Endpoint Name', 'tags': ['FortiEDR', 'endpoint']})
        enriched['device'] = device
        
        # Device IP (Endpoint IP)
        device_ip = event.get('deviceIp') or event.get('collectorIp')
        if device_ip:
            artifacts.append({'data': device_ip, 'dataType': 'ip', 'message': 'Endpoint IP', 'tags': ['FortiEDR', 'endpoint']})
        enriched['deviceIp'] = device_ip

        # Process / File Name
        process_info = event.get('source', {}).get('process', {}) if isinstance(event.get('source'), dict) else {}
        process = event.get('process') or process_info.get('name')
        if process:
            artifacts.append({'data': process, 'dataType': 'filename', 'message': 'Process Name', 'tags': ['FortiEDR']})
        enriched['process'] = process

        # File Hash
        file_hash = event.get('fileHash') or process_info.get('fileHash')
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
        path = event.get('path') or process_info.get('path')
        if path:
            artifacts.append({'data': path, 'dataType': 'file', 'message': 'Process Path', 'tags': ['FortiEDR']})

        # Destination IPs
        dest = event.get('destinationIp') or event.get('destination', {}).get('ip')
        if dest:
            artifacts.append({'data': dest, 'dataType': 'ip', 'message': 'Destination IP', 'tags': ['FortiEDR', 'destination']})
        
        # User discovery
        user = event.get('loggedUser') or event.get('userName') or event.get('user')
        if not user and isinstance(event.get('target'), dict):
            # Try target user if it was a targeted attack
            user = event.get('target', {}).get('user', {}).get('name') or event.get('target', {}).get('name')
        if not user and isinstance(event.get('source'), dict):
            # Try source user
            user = event.get('source', {}).get('user', {}).get('name')
            
        if user:
            artifacts.append({'data': user, 'dataType': 'user', 'message': 'Involved User', 'tags': ['FortiEDR', 'user']})
        enriched['user'] = user
        # Rule Name & Tags
        tags = ['FortiEDR']
        rule = event.get('rule')
        if rule:
            enriched['automation_identifiers'] = [rule]
            automation_tags = self.getAutomationTags([rule])
            tags.extend(automation_tags)
            
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
        description += f"* **ID:** {event.get('id')}\n"
        description += f"* **Device:** {event.get('device')}\n"
        description += f"* **IP:** {event.get('deviceIp', 'N/A')}\n"
        description += f"* **Process:** {event.get('process', 'N/A')}\n"
        description += f"* **Severity:** {event.get('severity')}\n"
        description += f"* **Classification:** {event.get('classification', 'N/A')}\n"
        description += f"* **Rule:** {event.get('rule', 'N/A')}\n"
        description += f"* **First Seen:** {event.get('firstSeen', 'N/A')}\n"

        # Date handling: TheHive 4 requires epoch milliseconds
        # FortiEDR usually returns YYYY-MM-DD HH:MM:SS or similar
        event_date = event.get('firstSeen')
        if isinstance(event_date, str):
            try:
                # Try common FortiEDR formats
                dt = datetime.datetime.strptime(event_date, '%Y-%m-%d %H:%M:%S')
                epoch_ms = int(dt.timestamp() * 1000)
            except Exception:
                # Fallback to current time if parsing fails
                epoch_ms = int(datetime.datetime.now().timestamp() * 1000)
        else:
            epoch_ms = int(datetime.datetime.now().timestamp() * 1000)

        eid = event.get('id') or event.get('eventId')
        
        # Build TheHive alert using craftAlert
        alert = self.theHiveConnector.craftAlert(
            title=f"FortiEDR: {event.get('classification', 'Security Event')} on {event.get('device', 'Unknown Device')}",
            description=description,
            severity=severity,
            date=epoch_ms,
            tags=event.get('tags', ['FortiEDR']),
            tlp=int(self.cfg.get('Automation', 'default_observable_tlp', fallback=2)),
            status='New',
            type='FortiEDR Alert',
            source='Synapse',
            sourceRef=str(eid),
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
            self.logger.debug("Inspecting event: %s", json.dumps(event))
            # Temporary fix/guess: try 'eventId' if 'id' is missing
            eid = event.get('id') or event.get('eventId')
            event_report = {'event_id': eid, 'success': True}
            
            # Deduplication: check if alert already exists
            query = And(Eq('sourceRef', str(eid)), Eq('source', 'Synapse'), Eq('type', 'FortiEDR Alert'))
            results = self.theHiveConnector.findAlert(query)
            
            if len(results) == 0:
                self.logger.info('Event %s not found in TheHive, creating alert', eid)
                try:
                    enriched = self.enrichEvent(event)
                    alert = self.fortiedrEventToHiveAlert(enriched)
                    created_alert = self.theHiveConnector.createAlert(alert)
                    event_report['raised_alert_id'] = created_alert['id']
                except Exception as e:
                    self.logger.error('Failed to create alert for event %s: %s', eid, e, exc_info=True)
                    event_report['success'] = False
                    event_report['message'] = str(e)
                    report['success'] = False
            else:
                self.logger.info('Event %s already imported as alert, skipping', eid)
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
