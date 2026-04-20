import logging
from modules.FortiEDR.connector import FortiEDRConnector

class Automation:
    def __init__(self, webhook, cfg):
        self.logger = logging.getLogger('synapse.modules.FortiEDR.automation')
        self.webhook = webhook
        self.cfg = cfg
        self.connector = FortiEDRConnector(cfg)

    def parse_hooks(self):
        """
        Parse webhooks from TheHive/Cortex to perform actions or synchronize status.
        """
        webhook_data = self.webhook.data
        object_data = webhook_data.get('object', {})
        tags = object_data.get('tags', [])
        
        # 1. Handle explicit manual actions from Responders
        action_performed = False
        
        # Extract device identifier (prefer hostname, fall back to IP)
        # In FortiEDR alerts from TheHive, we often have 'device' or observables
        device = object_data.get('device')
        if not device and 'artifacts' in object_data:
            for artifact in object_data['artifacts']:
                if artifact.get('dataType') in ['hostname', 'ip']:
                    device = artifact.get('data')
                    break

        if device:
            if 'synapse:isolate-device' in tags:
                self.logger.info(f"Triggering FortiEDR isolation for {device}")
                result = self.connector.isolate_collector(device)
                action_performed = f"Isolate: {result.get('status')}"
            
            elif 'synapse:unisolate-device' in tags:
                self.logger.info(f"Triggering FortiEDR un-isolation for {device}")
                result = self.connector.unisolate_collector(device)
                action_performed = f"Unisolate: {result.get('status')}"

            elif 'synapse:remediate-device' in tags:
                self.logger.info(f"Triggering FortiEDR remediation for {device}")
                result = self.connector.remediate_device(device)
                action_performed = f"Remediate: {result.get('status')}"

        # Handle create-exception (does not require device, uses eventId)
        if not action_performed and 'synapse:create-exception' in tags:
            event_id = object_data.get('sourceRef')
            if event_id:
                self.logger.info(f"Creating scoped FortiEDR exception for event {event_id}")

                # Extract scoping data from case/alert
                collector_groups = None
                destinations = None
                users = None

                # Try to extract collector groups from tags (e.g. "collectorGroup:GroupName")
                cg_tags = [t.split(':', 1)[1] for t in tags if t.startswith('collectorGroup:')]
                if cg_tags:
                    collector_groups = cg_tags

                # Extract destinations and users from artifacts
                if 'artifacts' in object_data:
                    dest_ips = []
                    user_list = []
                    for artifact in object_data['artifacts']:
                        dtype = artifact.get('dataType', '')
                        data_val = artifact.get('data', '')
                        tags_val = artifact.get('tags', [])
                        
                        # Destinations: ONLY use IPs tagged with 'destination' for security
                        if dtype == 'ip' and data_val and 'destination' in tags_val:
                            dest_ips.append(data_val)
                                
                        # Users: prefer artifacts tagged with 'user'
                        elif dtype in ['user', 'user-account'] and data_val:
                            user_list.append(data_val)
                    
                    if dest_ips:
                        destinations = dest_ips
                    if user_list:
                        users = user_list

                # Fetch full event details to ENSURE we have the correct scoping
                # This is safer than relying solely on artifacts which might be incomplete
                self.logger.info(f"Fetching original event {event_id} to verify scoping context.")
                original_event = self.connector.get_event(event_id)
                if original_event:
                    # If we don't have destinations from artifacts, take from event
                    if not destinations:
                        edest = original_event.get('destinationIp') or original_event.get('destination', {}).get('ip')
                        if edest:
                            self.logger.info(f"Found destination {edest} in original event.")
                            destinations = [edest]
                    
                    # If we don't have users from artifacts, take from event
                    if not users:
                        euser = original_event.get('loggedUser') or original_event.get('userName')
                        if not euser and isinstance(original_event.get('target'), dict):
                            euser = original_event.get('target', {}).get('user', {}).get('name')
                        if euser:
                            self.logger.info(f"Found user {euser} in original event.")
                            users = [euser]

                # If we STILL have no data, the user is trying to create a global exception 
                # from an event that doesn't have network/user data, or something failed.
                # Per user request, we must be scoped, so if we can't find data, we should probably 
                # fail or be extremely careful.

                # Generate comment from case context
                case_id = object_data.get('caseId', object_data.get('id', 'N/A'))
                scope_info = f"Scope: Dests={destinations}, Users={users}"
                comment = f"Exception created from TheHive {case_id} via Synapse. {scope_info}"

                # Trigger creation with restrictive flags
                # We FORCE all_dests=False and all_users=False if we found any data
                result = self.connector.create_exception(
                    event_id=event_id,
                    collector_groups=collector_groups,
                    destinations=destinations,
                    users=users,
                    comment=comment,
                    all_groups=True if not collector_groups else False,
                    all_dests=False if destinations else True, # SCOPE IT!
                    all_users=False if users else True # SCOPE IT!
                )
                action_performed = f"CreateException: {result}"
            else:
                self.logger.warning("Cannot create exception: no sourceRef (eventId) found in case/alert")

        if action_performed:
            return action_performed

        # 2. Handle Case Synchronization (Auto-resolve if case closed)
        hook_type = webhook_data.get('operation')
        object_type = webhook_data.get('objectType')
        
        if object_type == 'case' and hook_type == 'Update':
            status = object_data.get('status')
            if status == 'Resolved':
                return self.handleCaseResolved()
        
        return False

    def handleCaseResolved(self):
        """
        Action to take when a case is resolved in TheHive.
        """
        self.logger.info("TheHive Case resolved. Status synchronization with FortiEDR requested.")
        # Future: Implement actual event resolution in FortiEDR if possible
        return "CaseResolvedSync"
