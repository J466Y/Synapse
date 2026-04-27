#!/usr/bin/env python3
# -*- coding: utf8 -*-

import os
import sys
import logging
import copy
import json
import datetime
from core.integration import Main
from thehive4py.query import And, Eq
from modules.Darktrace.connector import DarktraceConnector
from modules.TheHive.connector import TheHiveConnector

class Integration(Main):
    """Darktrace Integration for Synapse"""

    def __init__(self):
        super().__init__()
        self.logger = logging.getLogger(__name__)
        self.connector = DarktraceConnector(self.cfg)
        self.theHiveConnector = TheHiveConnector(self.cfg)
        # Verify connection to TheHive as well
        self.theHiveConnector.test_connection()

    def enrichBreach(self, breach):
        enriched = copy.deepcopy(breach)
        artifacts = []

        # Assuming breach has 'pbid' as unique identifier
        pbid = breach.get('pbid')
        enriched['id'] = pbid

        # Check 'deviceattop' vs 'device' struct
        hostname = breach.get('hostname') or breach.get('device', {}).get('hostname')
        if hostname:
            artifacts.append({'data': hostname, 'dataType': 'hostname', 'message': 'Darktrace Device Hostname', 'tags': ['Darktrace', 'endpoint']})
        
        ip = breach.get('ip') or breach.get('device', {}).get('ip')
        if ip:
            artifacts.append({'data': ip, 'dataType': 'ip', 'message': 'Darktrace Device IP', 'tags': ['Darktrace', 'endpoint']})
            
        macaddress = breach.get('macaddress') or breach.get('device', {}).get('macaddress')
        if macaddress:
            artifacts.append({'data': macaddress, 'dataType': 'mac', 'message': 'Darktrace Device MAC', 'tags': ['Darktrace', 'endpoint']})

        # Process triggered components
        components = breach.get('triggeredComponents', [])
        for c in components:
            filters = c.get('triggeredFilters', [])
            for f in filters:
                filter_type = f.get('filterType', '')
                value = f.get('trigger', {}).get('value')
                if not value or not isinstance(value, str):
                    continue
                
                # Basic mapping
                dt_type = None
                if 'hostname' in filter_type.lower() or 'domain' in filter_type.lower():
                    dt_type = 'fqdn'
                elif ' ip' in filter_type.lower() or filter_type.lower().startswith('ip '):
                    dt_type = 'ip'
                elif 'uri' in filter_type.lower() or 'url' in filter_type.lower():
                    dt_type = 'url'
                
                if dt_type:
                    # check for duplicates
                    if not any(a['data'] == value and a['dataType'] == dt_type for a in artifacts):
                        artifacts.append({'data': value, 'dataType': dt_type, 'message': f'Darktrace: {filter_type}', 'tags': ['Darktrace']})

        # Tags processing
        tags = ['Darktrace']
        model_name = breach.get('model', {}).get('name') if isinstance(breach.get('model'), dict) else breach.get('modelName')
        if model_name:
            tags.append(f"model:{model_name}")

        artifacts = self.checkObservableExclusionList(artifacts)
        artifacts = self.checkObservableTLP(artifacts)

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

    def darktraceBreachToHiveAlert(self, breach):
        # Severity mapping: Score is 0.0-1.0 from API, but we want 0-100.
        score = breach.get('score', 0)
        if isinstance(score, (int, float)):
            if score <= 1.0:
                score = int(score * 100)
            else:
                score = int(score)
        else:
            score = 0
            
        if score >= 80:
            severity = 4
        elif score >= 60:
            severity = 3
        elif score >= 40:
            severity = 2
        else:
            severity = 1
            
        case_template = self.cfg.get('Darktrace', 'case_template', fallback='Darktrace Breach')
        pbid = breach.get('pbid') or breach.get('id')

        model_obj = breach.get('model', {})
        target_model = model_obj.get('then') or model_obj.get('now') or model_obj
        model_name = target_model.get('name') or breach.get('modelName') or 'N/A'
        
        description = "### Darktrace Model Breach\n\n"
        description += f"* **Breach ID (PBID):** {pbid}\n"
        description += f"* **Score:** {score}\n"
        description += f"* **Model:** {model_name}\n"

        model_desc = target_model.get('description')
        if model_desc:
            description += f"\n**Description / Action:**\n{model_desc}\n"
            
        mitre_info = target_model.get('mitre', {})
        if mitre_info:
            tactics = ', '.join(mitre_info.get('tactics', []))
            techniques = ', '.join(mitre_info.get('techniques', []))
            if tactics or techniques:
                description += f"\n**MITRE ATT&CK:**\n"
                if tactics:
                    description += f"- Tactics: {tactics}\n"
                if techniques:
                    description += f"- Techniques: {techniques}\n"

        # Check components for additional details in description
        components = breach.get('triggeredComponents', [])
        if components:
            description += "\n**Triggered Components:**\n"
            for c in components:
                filters = c.get('triggeredFilters', [])
                for f in filters:
                    filter_type = f.get('filterType', '')
                    value = f.get('trigger', {}).get('value', 'N/A')
                    description += f"- {filter_type}: {value}\n"

        # Date handling: TheHive 4 requires epoch milliseconds
        event_time = breach.get('time')
        if isinstance(event_time, int):
            epoch_ms = event_time
        else:
            epoch_ms = int(datetime.datetime.now().timestamp() * 1000)

        alert = self.theHiveConnector.craftAlert(
            title=f"DARKTRACE: {model_name} (Score: {score})",
            description=description,
            severity=severity,
            date=epoch_ms,
            tags=breach.get('tags', ['Darktrace']),
            tlp=int(self.cfg.get('Automation', 'default_observable_tlp', fallback=2)),
            status='New',
            type='Darktrace Breach',
            source='Synapse',
            sourceRef=str(pbid),
            artifacts=breach.get('artifacts', []),
            caseTemplate=case_template
        )
        return alert

    def validateRequest(self, request):
        if request.is_json:
            content = request.get_json()
            if 'timerange' in content:
                workflowReport = self.allBreaches2Alert(content['timerange'])
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

    def allBreaches2Alert(self, timerange_minutes=60):
        self.logger.info("Darktrace.allBreaches2Alert starts (timerange: %s min)", timerange_minutes)

        if not getattr(self.connector, 'health_check', lambda: True)():
            self.logger.warning("Target server is unreachable. Aborting pull to prevent hangs.")
            return {'success': False, 'reason': 'server_down'}

        report = {'success': True, 'events': []}

        to_dt = datetime.datetime.now(datetime.timezone.utc)
        from_dt = to_dt - datetime.timedelta(minutes=int(timerange_minutes))
        starttime_ms = int(from_dt.timestamp() * 1000)
        endtime_ms = int(to_dt.timestamp() * 1000)

        breaches = self.connector.get_breaches(starttime_ms, endtime_ms)
        if not isinstance(breaches, list):
            self.logger.error("Failed to pull breaches: expected list")
            report['success'] = False
            return report

        for breach in breaches:
            pbid = breach.get('pbid')
            if not pbid:
                continue

            event_report = {'event_id': pbid, 'success': True}

            query = And(Eq('sourceRef', str(pbid)), Eq('source', 'Synapse'), Eq('type', 'Darktrace Breach'))
            results = self.theHiveConnector.findAlert(query)

            if len(results) == 0:
                self.logger.info('Breach %s not found in TheHive, creating alert', pbid)
                try:
                    enriched = self.enrichBreach(breach)
                    alert = self.darktraceBreachToHiveAlert(enriched)
                    created_alert = self.theHiveConnector.createAlert(alert)
                    event_report['raised_alert_id'] = created_alert['id']
                except Exception as e:
                    self.logger.error('Failed to create alert for breach %s: %s', pbid, e, exc_info=True)
                    event_report['success'] = False
                    event_report['message'] = str(e)
                    report['success'] = False
            else:
                self.logger.info('Breach %s already imported as alert, skipping', pbid)
                event_report['message'] = 'Already imported'

            report['events'].append(event_report)

        return report
