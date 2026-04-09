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

        return self.report_action
