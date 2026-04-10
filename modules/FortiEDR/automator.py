import logging
from modules.FortiEDR.connector import FortiEDRConnector

class Automators:
    """
    FortiEDR automator module for Synapse.
    Handles remediation actions triggered by TheHive tags.
    """
    def __init__(self, cfg, automation_config):
        self.logger = logging.getLogger('synapse.modules.FortiEDR.automator')
        self.connector = FortiEDRConnector(cfg)
        self.automation_config = automation_config

    def _get_event_context(self, webhook):
        """
        Helper to get eventId, collectorId and processId from webhook/FortiEDR
        """
        # sourceRef is usually the eventId
        event_id = None
        if 'sourceRef' in webhook.get('object', {}):
            event_id = webhook['object']['sourceRef']
        
        if not event_id:
            self.logger.error("No eventId found in sourceRef for remediation")
            return None

        # Fetch details from connector
        result = self.connector.get_event_details(event_id)
        if result['status'] and result['data']:
            event_data = result['data']
            # collectors is a list
            collector_id = None
            collectors = event_data.get('collectors', [])
            if collectors:
                collector_id = collectors[0].get('device') # API uses device name/ID interchangeably in some calls
            
            process_id = event_data.get('processId', 0)
            
            return {
                'event_id': event_id,
                'collector_id': collector_id,
                'process_id': process_id
            }
        
        return None

    def isolateDevice(self, action_config, webhook):
        """
        Isolate a device in FortiEDR.
        Tag: fc-isolate-host
        """
        context = self._get_event_context(webhook)
        if not context or not context['collector_id']:
            return False, "Could not determine collector ID for isolation"

        self.logger.info(f"Isolating device: {context['collector_id']}")
        success, message = self.connector.isolate_collector(context['collector_id'])
        return success, message

    def remediateDevice(self, action_config, webhook):
        """
        Remediate a device (kill process).
        """
        context = self._get_event_context(webhook)
        if not context or not context['collector_id']:
            return False, "Could not determine context for remediation"

        self.logger.info(f"Remediating process {context['process_id']} on device {context['collector_id']}")
        success, message = self.connector.remediate_device(context['collector_id'], context['process_id'])
        return success, message

    def createException(self, action_config, webhook):
        """
        Create an exception in FortiEDR.
        Tags: fc-global-exception, fc-targeted-exception
        """
        event_id = webhook.get('object', {}).get('sourceRef')
        if not event_id:
            return False, "No event ID found in sourceRef"

        tags = webhook.get('details', {}).get('tags', [])
        scoped = 'fc-targeted-exception' in tags
        
        self.logger.info(f"Creating {'scoped' if scoped else 'global'} exception for event {event_id}")
        success, message = self.connector.create_exception(event_id, scoped=scoped)
        return success, message
