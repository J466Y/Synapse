import json
import requests
import time
import logging
from datetime import date

from modules.TheHive.connector import TheHiveConnector
from modules.Cortex.connector import CortexConnector
from modules.QRadar.connector import QRadarConnector

from thehive4py.models import Case, CustomFieldHelper, CaseObservable, CaseTask
from thehive4py.query import Eq

logger = logging.getLogger(__name__)

# When no condition is match, the default action is None
report_action = 'None'

class Automation():

    def __init__(self, webhook, cfg):
        logger.info('Initiating QRadarAutomation')
        self.TheHiveConnector = TheHiveConnector(cfg)
        self.QRadarConnector = QRadarConnector(cfg)
        self.webhook = webhook
        self.cfg = cfg
        self.report_action = report_action

    def checkIfInClosedCaseOrAlertMarkedAsRead(self, sourceref):
        query = Eq('sourceRef', str(sourceref))
        logger.debug('Checking if third party ticket({}) is linked to a closed case'.format(sourceref))
        alert_results = self.TheHiveConnector.findAlert(query)
        if len(alert_results) > 0:
            alert_found = alert_results[0]
            if alert_found['status'] == 'Ignored':
                logger.info(f"{sourceref} is found in alert {alert_found['id']} that has been marked as read")
                return {"resolutionStatus": "Indeterminate", "summary": "Closed by Synapse with summary: Marked as Read within The Hive"}
            elif 'case' in alert_found:
                # Check if alert is present in closed case
                case_found = self.TheHiveConnector.getCase(alert_found['case'])
                if case_found['status'] == "Resolved":
                    logger.info(f"{sourceref} was found in a closed case {case_found['id']}")
                    resolution_status = "N/A"
                    resolution_summary = "N/A"
                    # Return information required to sync with third party
                    if 'resolutionStatus' in case_found:
                        resolution_status = case_found['resolutionStatus']
                    if 'summary' in case_found:
                        resolution_summary = case_found['summary']
                    return {"resolutionStatus": resolution_status, "summary": resolution_summary}
        return False

    def parse_hooks(self):
        # 0. Handle explicit manual actions from Responders
        tags = self.webhook.data.get('object', {}).get('tags', [])
        if 'synapse:close-offense' in tags:
            obj_type = self.webhook.data.get('objectType')
            
            if obj_type == 'alert':
                self.offense_id = self.webhook.data['object'].get('sourceRef')
                if self.offense_id:
                    logger.info(f"Triggering explicit QRadar offense closure for alert offense {self.offense_id}")
                    self.QRadarConnector.closeOffense(self.offense_id)
            
            elif obj_type == 'case':
                case_id = self.webhook.data['object'].get('id', self.webhook.data.get('objectId'))
                
                # Fetch all alerts linked to this case using fromQRadar
                if self.webhook.fromQRadar(case_id):
                    # Single alert case
                    if hasattr(self.webhook, 'ext_alert_id') and self.webhook.ext_alert_id:
                        logger.info(f"Triggering explicit QRadar offense closure for case {case_id} -> offense {self.webhook.ext_alert_id}")
                        self.QRadarConnector.closeOffense(self.webhook.ext_alert_id)
                        
                    # Multiple alerts case
                    elif hasattr(self.webhook, 'ext_alert_ids') and len(self.webhook.ext_alert_ids) > 0:
                        logger.info(f"Triggering explicit QRadar bulk offense closure for case {case_id} -> offenses {self.webhook.ext_alert_ids}")
                        for offense_id in self.webhook.ext_alert_ids:
                            logger.info(f"Closing offense {offense_id} for case {case_id}")
                            self.QRadarConnector.closeOffense(offense_id)

            return 'closeOffenseExplicit'

        # 1. Update incident status to active when imported as Alert
        if self.webhook.isQRadarAlertImported():
            self.offense_id = self.webhook.data['object']['sourceRef']

            # Check if the alert is imported in a closed case
            closure_info = self.checkIfInClosedCaseOrAlertMarkedAsRead(self.offense_id)
            if closure_info:
                logger.info('Qradar offense({}) is linked to a closed case'.format(self.offense_id))
                # Close incident and continue with the next incident
                self.QRadarConnector.closeOffense(self.offense_id)

        # Close offenses in QRadar
        if self.webhook.isClosedQRadarCase() or self.webhook.isDeletedQRadarCase() or self.webhook.isQRadarAlertMarkedAsRead():
            operation = self.webhook.data.get('operation') or self.webhook.data.get('action')
            obj_type = self.webhook.data.get('objectType', '').lower()
            
            if operation in ['Delete', 'delete']:
                self.case_id = self.webhook.data.get('objectId')
                logger.info('Case {} has been deleted'.format(self.case_id))

            elif obj_type == 'alert':
                self.alert_id = self.webhook.data.get('objectId')
                logger.info('Alert {} has been marked as read'.format(self.alert_id))
                obj = self.webhook.data.get('object', {})
                if obj.get('sourceRef'):
                    self.QRadarConnector.closeOffense(obj.get('sourceRef'))

            else:
                obj = self.webhook.data.get('object', {})
                self.case_id = obj.get('id', self.webhook.data.get('objectId'))
                logger.info('Case {} has been marked as resolved'.format(self.case_id))

            if hasattr(self, 'case_id'):
                if hasattr(self.webhook, 'ext_alert_id'):
                    logger.info("Closing offense {} for case {}".format(self.webhook.ext_alert_id, self.case_id))
                    self.QRadarConnector.closeOffense(self.webhook.ext_alert_id)

                elif len(self.webhook.ext_alert_ids) > 0:
                    # Close offense for every linked offense
                    logger.info("Found multiple offenses {} for case {}".format(self.webhook.ext_alert_ids, self.case_id))
                    for offense_id in self.webhook.ext_alert_ids:
                        logger.info("Closing offense {} for case {}".format(offense_id, self.case_id))
                        self.QRadarConnector.closeOffense(offense_id)

            self.report_action = 'closeOffense'

        return self.report_action
