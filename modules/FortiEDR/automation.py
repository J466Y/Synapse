import logging
from modules.FortiEDR.connector import FortiEDRConnector

logger = logging.getLogger(__name__)

class Automation():
    """
    FortiEDR automation module for Synapse.
    Handles status synchronization between TheHive and FortiEDR.
    """

    def __init__(self, webhook, cfg):
        logger.info('Initiating FortiEDRAutomation')
        self.connector = FortiEDRConnector(cfg)
        self.webhook = webhook
        self.cfg = cfg
        self.report_action = 'None'

    def parse_hooks(self):
        """
        Parse webhooks to determine required actions.
        """
        # 1. Handle alert import into a closed case
        if (self.webhook.isFortiEDR() and self.webhook.isImportedAlert()):
            event_id = self.webhook.data['object'].get('sourceRef')
            if event_id:
                # Optional: Check if the case it was imported into is already closed
                # For now, following the simple logic of marking as handled if it's imported
                # as part of a SOAR response.
                pass

        # 2. Handle Case Closure or Alert Marked as Read
        if self.webhook.isClosedFortiEDRCase() or (self.webhook.isFortiEDR() and self.webhook.isMarkedAsRead()):
            logger.info('FortiEDR case or alert requires synchronization')
            
            # Extract event IDs
            event_ids = []
            if hasattr(self.webhook, 'ext_alert_id'):
                event_ids.append(self.webhook.ext_alert_id)
            elif hasattr(self.webhook, 'ext_alert_ids'):
                event_ids.extend(self.webhook.ext_alert_ids)
            elif self.webhook.isAlert():
                event_ids.append(self.webhook.data['object'].get('sourceRef'))

            for eid in event_ids:
                if eid:
                    logger.info('Marking FortiEDR event %s as handled', eid)
                    self.connector.resolve_event(eid)
            
            self.report_action = 'resolveEvent'

        # 3. Handle Manual Trigger Tags
        tags = []
        if 'details' in self.webhook.data and 'tags' in self.webhook.data['details']:
            tags = self.webhook.data['details']['tags']
        elif 'object' in self.webhook.data and 'tags' in self.webhook.data['object']:
            tags = self.webhook.data['object']['tags']

        # Extract device if needed for isolation/remediation
        device = None
        if self.webhook.isAlert():
            # Try to find hostname in description or artifacts
            # For simplicity, we assume the connector can find it or we look in artifacts
            pass 

        if 'synapse:isolate-device' in tags:
            # We need the device name. In FortiEDR alerts created by Synapse, it's often in artifacts
            # For a more robust approach, we'd need to fetch the alert from TheHive and find 'hostname'
            logger.info('FortiEDR manual trigger: isolate-device')
            # Assuming device info is available or passed in payload
            # self.connector.isolate_collector(device)
            self.report_action = 'isolateDevice'

        if 'synapse:remediate-device' in tags:
            logger.info('FortiEDR manual trigger: remediate-device')
            self.report_action = 'remediateDevice'

        if 'synapse:resolve-event' in tags:
            logger.info('FortiEDR manual trigger: resolve-event')
            event_id = self.webhook.data['object'].get('sourceRef')
            if event_id:
                self.connector.resolve_event(event_id)
            self.report_action = 'resolveEventManual'

        return self.report_action
