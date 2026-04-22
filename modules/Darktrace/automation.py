import logging
from modules.Darktrace.connector import DarktraceConnector

class Automation:
    def __init__(self, webhook, cfg):
        self.logger = logging.getLogger('synapse.modules.Darktrace.automation')
        self.webhook = webhook
        self.cfg = cfg
        self.connector = DarktraceConnector(cfg)

    def parse_hooks(self):
        """
        Parse webhooks from TheHive/Cortex to perform actions.
        """
        webhook_data = self.webhook.data
        object_data = webhook_data.get('object', {})
        tags = object_data.get('tags', [])
        
        action_performed = False
        
        # We need the PBID (Breach ID) which we store in sourceRef
        pbid = object_data.get('sourceRef') or object_data.get('id')

        if pbid and 'synapse:acknowledge-breach' in tags:
            self.logger.info(f"Triggering Darktrace Acknowledge for breach {pbid}")
            
            # Extract comment if passed via the webhook custom data or description
            # Sometimes responders pass custom parameters in a specific field
            comment = object_data.get('synapse_comment') or object_data.get('message')
            
            ack_result = self.connector.acknowledge_breach(pbid)
            if ack_result.get('status'):
                action_performed = {'status': True, 'message': f"Acknowledge: Success for breach {pbid}"}
                
                # If there is a comment, add it
                if comment:
                    self.logger.info(f"Adding comment to Darktrace breach {pbid}: {comment}")
                    comment_result = self.connector.add_comment(pbid, comment)
                    if comment_result.get('status'):
                        action_performed['message'] += " | Comment added"
                    else:
                        action_performed['message'] += f" | Failed to add comment: {comment_result.get('data')}"
            else:
                action_performed = {'status': False, 'message': f"Acknowledge: Failed for breach {pbid}. Error: {ack_result.get('data')}"}

        if action_performed:
            return action_performed

        return False
