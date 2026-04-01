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
        device = event.get('device')
        if device:
            artifacts.append({'data': device, 'dataType': 'hostname', 'message': 'Endpoint Name', 'tags': ['FortiEDR']})

        # Device IP
        device_ip = event.get('deviceIp')
        if device_ip:
            artifacts.append({'data': device_ip, 'dataType': 'ip', 'message': 'Endpoint IP', 'tags': ['FortiEDR']})

        # Process / File Name
        process = event.get('process')
        if process:
            artifacts.append({'data': process, 'dataType': 'filename', 'message': 'Process Name', 'tags': ['FortiEDR']})

        # File Hash
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
        path = event.get('path')
        if path:
            artifacts.append({'data': path, 'dataType': 'file', 'message': 'Process Path', 'tags': ['FortiEDR']})

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

        # Build TheHive alert using craftAlert
        alert = self.theHiveConnector.craftAlert(
            title=f"FortiEDR: {event.get('classification', 'Security Event')} on {event.get('device', 'Unknown Device')}",
            description=description,
            severity=severity,
            date=event.get('firstSeen', datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
            tags=event.get('tags', ['FortiEDR']),
            tlp=int(self.cfg.get('Automation', 'default_observable_tlp', fallback=2)),
            status='New',
            type='FortiEDR Alert',
            source='FortiEDR',
            sourceRef=str(event.get('id')),
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
            
            # Check for target (automation or automator)
            target = request.args.get('target')
            
            if target == 'automation':
                from modules.FortiEDR.automation import Automation
                automation = Automation()
                success, message = automation.parse_hooks(self.cfg, content)
                return json.dumps({'success': success, 'message': message}), (200 if success else 500)
            
            elif target == 'automator':
                from modules.FortiEDR.automator import Automator
                automator = Automator()
                # Determine which task to run from the request or config
                task_name = request.args.get('task')
                if hasattr(automator, str(task_name)):
                    task_func = getattr(automator, str(task_name))
                    success, message = task_func(self.cfg, content)
                    return json.dumps({'success': success, 'message': message}), (200 if success else 500)
                else:
                    return json.dumps({'success': False, 'message': f"Task {task_name} not found in Automator"}), 404

            # Default: pull events
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
            event_report = {'event_id': event.get('id'), 'success': True}
            
            # Deduplication: check if alert already exists
            query = {'sourceRef': str(event.get('id')), 'source': 'FortiEDR'}
            results = self.theHiveConnector.findAlert(query)
            
            if len(results) == 0:
                self.logger.info('Event %s not found in TheHive, creating alert', event.get('id'))
                try:
                    enriched = self.enrichEvent(event)
                    alert = self.fortiedrEventToHiveAlert(enriched)
                    created_alert = self.theHiveConnector.createAlert(alert)
                    event_report['raised_alert_id'] = created_alert['id']
                except Exception as e:
                    self.logger.error('Failed to create alert for event %s: %s', event.get('id'), e, exc_info=True)
                    event_report['success'] = False
                    event_report['message'] = str(e)
                    report['success'] = False
            else:
                self.logger.info('Event %s already imported as alert, skipping', event.get('id'))
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
