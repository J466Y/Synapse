import logging
import ipaddress
from modules.FortiEDR.connector import FortiEDRConnector


class Automation:
    def __init__(self, webhook, cfg):
        self.logger = logging.getLogger("synapse.modules.FortiEDR.automation")
        self.webhook = webhook
        self.cfg = cfg
        self.connector = FortiEDRConnector(cfg)

    def parse_hooks(self):
        """
        Parse webhooks from TheHive/Cortex to perform actions or synchronize status.
        """
        webhook_data = self.webhook.data
        object_data = webhook_data.get("object", {})
        tags = object_data.get("tags", [])

        # 1. Handle explicit manual actions from Responders
        action_performed = False

        # Extract device identifier (prefer hostname, fall back to IP)
        # In FortiEDR alerts from TheHive, we often have 'device' or observables
        device = object_data.get("device")
        if not device and "artifacts" in object_data:
            for artifact in object_data["artifacts"]:
                if artifact.get("dataType") in ["hostname", "ip"]:
                    device = artifact.get("data")
                    break

        if device:
            if "synapse:isolate-device" in tags:
                self.logger.info(f"Triggering FortiEDR isolation for {device}")
                result = self.connector.isolate_collector(device)
                action_performed = f"Isolate: {result.get('status')}"

            elif "synapse:unisolate-device" in tags:
                self.logger.info(f"Triggering FortiEDR un-isolation for {device}")
                result = self.connector.unisolate_collector(device)
                action_performed = f"Unisolate: {result.get('status')}"

            elif "synapse:remediate-device" in tags:
                self.logger.info(f"Triggering FortiEDR remediation for {device}")
                result = self.connector.remediate_device(device)
                action_performed = f"Remediate: {result.get('status')}"

        # Handle create-exception (does not require device, uses eventId)
        if not action_performed and "synapse:create-exception" in tags:
            event_id = object_data.get("sourceRef")
            if event_id:
                self.logger.info(
                    f"Creating scoped FortiEDR exception for event {event_id}"
                )

                # Scoping data will be extracted from original_event for reliability
                collector_groups = None
                destinations = None
                users = None

                # Extract destinations and users from artifacts
                if "artifacts" in object_data:
                    dest_ips = []
                    user_list = []
                    for artifact in object_data["artifacts"]:
                        dtype = artifact.get("dataType", "")
                        data_val = artifact.get("data", "")
                        tags_val = artifact.get("tags", [])

                        # Destinations: ONLY use IPs tagged with 'destination' for security
                        if dtype == "ip" and data_val and "destination" in tags_val:
                            dest_ips.append(data_val)

                        # Users: prefer artifacts tagged with 'user'
                        elif dtype in ["user", "user-account"] and data_val:
                            user_list.append(data_val)

                    if dest_ips:
                        destinations = dest_ips
                    if user_list:
                        users = user_list

                # Fetch full event details to ENSURE we have the correct scoping
                # This is safer than relying solely on artifacts which might be incomplete
                # Get event data for scoping if needed
                use_in_exception = None
                use_any_path = None

                self.logger.info(
                    f"Fetching original event {event_id} to verify scoping context."
                )
                original_event = self.connector.get_event(event_id)

                if original_event:
                    # Parse event using same logic as enrichment
                    collectors = original_event.get("collectors", [])
                    collector = (
                        collectors[0]
                        if isinstance(collectors, list) and len(collectors) > 0
                        else {}
                    )

                    rules = original_event.get("rules", [])
                    rule_name = (
                        rules[0]
                        if isinstance(rules, list) and len(rules) > 0
                        else original_event.get("rule")
                    )
                    process_name = original_event.get("process")

                    # 1. Collector Group scoping (Mandatory fallback)
                    if not collector_groups:
                        cg = collector.get("collectorGroup") or original_event.get(
                            "collectorGroupName"
                        )
                        if not cg:
                            # Try to find collector metadata
                            dev_name = collector.get("device") or original_event.get(
                                "device"
                            )
                            if dev_name:
                                self.logger.info(
                                    f"Fetching collector metadata for {dev_name} to find group."
                                )
                                collectors_result = self.connector.list_collectors()
                                if collectors_result.get("status") and isinstance(
                                    collectors_result.get("data"), list
                                ):
                                    for coll in collectors_result["data"]:
                                        if coll.get("name") == dev_name:
                                            cg = coll.get("group")
                                            break

                        if cg:
                            self.logger.info(
                                f"Scoping exception to collector group: {cg}"
                            )
                            collector_groups = [cg]
                        else:
                            self.logger.warning(
                                f"Could not determine collector group for event {event_id}."
                            )

                    # 2. Scoping destinations/users from event if not in artifacts
                    if not destinations:
                        dests = original_event.get("destinations", [])
                        valid_dests = []
                        if isinstance(dests, list):
                            for d in dests:
                                try:
                                    ipaddress.ip_address(str(d))
                                    valid_dests.append(d)
                                except ValueError:
                                    self.logger.debug(
                                        f"Filtering out non-IP destination: {d}"
                                    )

                        if valid_dests:
                            destinations = valid_dests
                        else:
                            edest = original_event.get("destinationIp")
                            if edest:
                                try:
                                    ipaddress.ip_address(str(edest))
                                    destinations = [edest]
                                except ValueError:
                                    self.logger.debug(
                                        f"Filtering out non-IP destinationIp: {edest}"
                                    )

                    if not users:
                        user_list = original_event.get("loggedUsers", [])
                        if isinstance(user_list, list) and len(user_list) > 0:
                            users = user_list

                    # 3. Extract process and rule for the exception body
                    wildcard_files = None
                    wildcard_paths = None

                    if process_name and rule_name:
                        self.logger.info(
                            f"Scoping exception to process '{process_name}' and rule '{rule_name}'"
                        )
                        use_in_exception = {process_name: {rule_name: True}}
                        use_any_path = {process_name: {rule_name: True}}

                        # Add wildcards for better coverage if process path is available
                        process_path = original_event.get("processPath")
                        if process_path:
                            # Standard FortiEDR wildcard format: directory + \
                            if "\\" in process_path:
                                wildcard_path = process_path.rsplit("\\", 1)[0] + "\\"
                                wildcard_paths = [wildcard_path]
                            wildcard_files = [process_name]
                    else:
                        self.logger.warning(
                            f"Could not find process/rule in event {event_id}. Scoping only by group."
                        )

                # Final parameters
                all_groups = False if collector_groups else True
                all_dests = False if destinations else True

                # Check if any destinations are internal and add 'internal destinations' if so
                if destinations:

                    has_internal = False
                    for d in destinations:
                        try:
                            if ipaddress.ip_address(str(d)).is_private:
                                has_internal = True
                                break
                        except ValueError:
                            pass
                    if has_internal and "internal destinations" not in destinations:
                        destinations.append("internal destinations")

                # Generate simple comment (avoid special chars in raw URL)
                case_id = object_data.get("caseId", object_data.get("id", "N/A"))
                comment = (
                    f"Exception from TheHive case {case_id.strip('~')} via Synapse"
                )

                result = self.connector.create_exception(
                    event_id=event_id,
                    collector_groups=collector_groups,
                    destinations=destinations,
                    comment=comment,
                    all_groups=all_groups,
                    all_dests=all_dests,
                    use_any_path=use_any_path,
                    use_in_exception=use_in_exception,
                    wildcard_files=wildcard_files,
                    wildcard_paths=wildcard_paths,
                    force_create=False,
                )

                if result.get("status"):
                    action_performed = {
                        "status": True,
                        "message": f"CreateException: Success for event {event_id}",
                    }
                else:
                    data = result.get("data")
                    if isinstance(data, dict):
                        error_msg = data.get("error_message", str(data))
                    else:
                        error_msg = str(data)
                    action_performed = {
                        "status": False,
                        "message": f"CreateException: Failed for event {event_id}. Error: {error_msg}",
                    }
            else:
                self.logger.warning(
                    "Cannot create exception: no sourceRef (eventId) found in case/alert"
                )

        if action_performed:
            return action_performed

        # 2. Handle Case Synchronization (Auto-resolve if case closed)
        hook_type = webhook_data.get("operation")
        object_type = webhook_data.get("objectType")

        if object_type == "case" and hook_type == "Update":
            status = object_data.get("status")
            if status == "Resolved":
                return self.handleCaseResolved()

        return False

    def handleCaseResolved(self):
        """
        Action to take when a case is resolved in TheHive.
        """
        self.logger.info(
            "TheHive Case resolved. Status synchronization with FortiEDR requested."
        )
        # Future: Implement actual event resolution in FortiEDR if possible
        return "CaseResolvedSync"
