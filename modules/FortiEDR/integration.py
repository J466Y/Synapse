#!/usr/bin/env python3
# -*- coding: utf8 -*-

import logging
import copy
import json
import datetime
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
        Enrich a FortiEDR event with observables (artifacts) as per documentation.
        """
        enriched = copy.deepcopy(event)
        artifacts = []

        # 1. Event ID
        eid = event.get("eventId") or event.get("id")
        enriched["id"] = eid

        # 2. Collector / Device Data (Extract from the first collector)
        collectors = event.get("collectors", [])
        collector = (
            collectors[0]
            if isinstance(collectors, list) and len(collectors) > 0
            else {}
        )

        device = collector.get("device")
        if device:
            artifacts.append(
                {
                    "data": device,
                    "dataType": "hostname",
                    "message": "Endpoint Name",
                    "tags": ["FortiEDR", "endpoint"],
                }
            )
        enriched["device"] = device

        # IP handling (Try deviceIp from doc, fallback to 'ip' seen in some logs)
        device_ip = collector.get("deviceIp") or collector.get("ip")
        if device_ip:
            artifacts.append(
                {
                    "data": device_ip,
                    "dataType": "ip",
                    "message": "Endpoint IP",
                    "tags": ["FortiEDR", "endpoint"],
                }
            )
        enriched["deviceIp"] = device_ip

        # 3. Collector Group
        collector_group = collector.get("collectorGroup")
        enriched["collectorGroupName"] = collector_group

        # 4. Process Name
        process = event.get("process")
        if process:
            artifacts.append(
                {
                    "data": process,
                    "dataType": "filename",
                    "message": "Process Name",
                    "tags": ["FortiEDR"],
                }
            )
        enriched["process"] = process

        # 5. File Hash
        file_hash = event.get("fileHash") or event.get("hash")
        if file_hash:
            data_type = "hash"
            if len(file_hash) == 32:
                data_type = "md5"
            elif len(file_hash) == 40:
                data_type = "sha1"
            elif len(file_hash) == 64:
                data_type = "sha256"
            artifacts.append(
                {
                    "data": file_hash,
                    "dataType": data_type,
                    "message": "Process File Hash",
                    "tags": ["FortiEDR"],
                }
            )

        # 6. Process Path
        path = event.get("processPath") or event.get("path")
        if path:
            artifacts.append(
                {
                    "data": path,
                    "dataType": "other",
                    "message": "Process Path",
                    "tags": ["FortiEDR"],
                }
            )

        # 7. Destination IPs (from documentation: 'destinations' or 'destination')
        dests = event.get("destinations", [])
        if not dests and event.get("destination"):
            dests = [event.get("destination")]

        if isinstance(dests, list):
            for dest in dests:
                artifacts.append(
                    {
                        "data": dest,
                        "dataType": "ip",
                        "message": "Destination IP",
                        "tags": ["FortiEDR", "destination"],
                    }
                )

        # 8. User discovery
        users = event.get("loggedUsers", [])
        if isinstance(users, list) and len(users) > 0:
            user = users[0]
            for u in users:
                artifacts.append(
                    {
                        "data": u,
                        "dataType": "other",
                        "message": "Involved User",
                        "tags": ["FortiEDR", "user"],
                    }
                )
            enriched["user"] = user

        # 9. Rule Name & Classification
        rules = event.get("rules", [])
        rule = (
            rules[0]
            if isinstance(rules, list) and len(rules) > 0
            else event.get("rule")
        )
        enriched["rule"] = rule

        classification = event.get("classification")
        enriched["classification"] = classification

        tags = ["FortiEDR"]
        if rule:
            enriched["automation_identifiers"] = [rule]
            tags.append(f"rule:{rule}")

        if collector_group:
            tags.append(f"collectorGroup:{collector_group}")

        # Standard Synapse enrichment processing
        artifacts = self.checkObservableExclusionList(artifacts)
        artifacts = self.checkObservableTLP(artifacts)

        hiveArtifacts = []
        for artifact in artifacts:
            hiveArtifact = self.theHiveConnector.craftAlertArtifact(
                dataType=artifact["dataType"],
                data=artifact["data"],
                message=artifact["message"],
                tags=artifact["tags"],
                tlp=artifact.get(
                    "tlp",
                    self.cfg.get("Automation", "default_observable_tlp", fallback=2),
                ),
            )
            hiveArtifacts.append(hiveArtifact)

        enriched["artifacts"] = hiveArtifacts
        enriched["tags"] = tags
        return enriched

    def fortiedrEventToHiveAlert(self, event):
        """
        Convert an enriched FortiEDR event to TheHive alert format
        :param event: enriched event dict
        :return: TheHive alert dict
        """
        # Severity mapping
        severity_map = {"Critical": 4, "High": 4, "Medium": 3, "Low": 2, "Info": 1}
        severity = severity_map.get(event.get("severity"), 2)

        # Case Template
        case_template = self.cfg.get("FortiEDR", "case_template", fallback="FortiEDR")

        # Description
        description = "### FortiEDR Security Event\n\n"
        description += f"* **ID:** {event.get('id')}\n"
        description += f"* **Device:** {event.get('device')}\n"
        description += f"* **IP:** {event.get('deviceIp', 'N/A')}\n"
        description += f"* **Group:** {event.get('collectorGroupName', 'N/A')}\n"
        description += f"* **Process:** {event.get('process', 'N/A')}\n"
        description += f"* **Severity:** {event.get('severity')}\n"
        description += f"* **Classification:** {event.get('classification', 'N/A')}\n"
        description += f"* **Rule:** {event.get('rule', 'N/A')}\n"
        description += f"* **First Seen:** {event.get('firstSeen', 'N/A')}\n"

        # Date handling: TheHive 4 requires epoch milliseconds
        # FortiEDR usually returns YYYY-MM-DD HH:MM:SS or similar
        event_date = event.get("firstSeen")
        if isinstance(event_date, str):
            try:
                # Try common FortiEDR formats
                dt = datetime.datetime.strptime(event_date, "%Y-%m-%d %H:%M:%S")
                epoch_ms = int(dt.timestamp() * 1000)
            except Exception:
                # Fallback to current time if parsing fails
                epoch_ms = int(datetime.datetime.now().timestamp() * 1000)
        else:
            epoch_ms = int(datetime.datetime.now().timestamp() * 1000)

        eid = event.get("id") or event.get("eventId")

        # Build TheHive alert using craftAlert
        alert = self.theHiveConnector.craftAlert(
            title=f"FORTIEDR: {event.get('process', 'Unknown Process')} - {event.get('classification', 'Security Event')}",
            description=description,
            severity=severity,
            date=epoch_ms,
            tags=event.get("tags", ["FortiEDR"]),
            tlp=int(self.cfg.get("Automation", "default_observable_tlp", fallback=2)),
            status="New",
            type="FortiEDR Alert",
            source="Synapse",
            sourceRef=str(eid),
            artifacts=event.get("artifacts", []),
            caseTemplate=case_template,
        )

        return alert

    def validateRequest(self, request):
        """
        Handle incoming API requests to the FortiEDR endpoint
        """
        if request.is_json:
            content = request.get_json()
            if "timerange" in content:
                workflowReport = self.allEvents2Alerts(content["timerange"])
                if workflowReport["success"]:
                    return json.dumps(workflowReport), 200
                else:
                    return json.dumps(workflowReport), 500
            else:
                self.logger.error("Missing <timerange> key/value")
                return (
                    json.dumps(
                        {
                            "success": False,
                            "message": "timerange key missing in request",
                        }
                    ),
                    400,
                )
        else:
            self.logger.error("Not json request")
            return (
                json.dumps(
                    {"success": False, "message": "Request didn't contain valid JSON"}
                ),
                400,
            )

    def allEvents2Alerts(self, timerange_minutes=60):
        """
        Pull events and create alerts in TheHive with deduplication
        """
        self.logger.info(
            "FortiEDR.allEvents2Alerts starts (timerange: %s min)", timerange_minutes
        )

        if not getattr(self.fortiedrConnector, "health_check", lambda: True)():
            self.logger.warning(
                "Target server is unreachable. Aborting pull to prevent hangs."
            )
            return {"success": False, "reason": "server_down"}

        report = {"success": True, "events": []}

        result = self.fortiedrConnector.list_events(timerange_minutes=timerange_minutes)
        if not result["status"]:
            self.logger.error("Failed to pull events: %s", result["data"])
            report["success"] = False
            report["message"] = str(result["data"])
            return report

        events = result["data"]
        if not isinstance(events, list):
            events = events.get("events", [])

        for event in events:
            self.logger.debug("Inspecting event: %s", json.dumps(event))
            # Temporary fix/guess: try 'eventId' if 'id' is missing
            eid = event.get("id") or event.get("eventId")
            event_report = {"event_id": eid, "success": True}

            # Deduplication: check if alert already exists
            query = And(
                Eq("sourceRef", str(eid)),
                Eq("source", "Synapse"),
                Eq("type", "FortiEDR Alert"),
            )
            results = self.theHiveConnector.findAlert(query)

            if len(results) == 0:
                self.logger.info("Event %s not found in TheHive, creating alert", eid)
                try:
                    enriched = self.enrichEvent(event)
                    alert = self.fortiedrEventToHiveAlert(enriched)
                    created_alert = self.theHiveConnector.createAlert(alert)
                    event_report["raised_alert_id"] = created_alert["id"]
                except Exception as e:
                    self.logger.error(
                        "Failed to create alert for event %s: %s", eid, e, exc_info=True
                    )
                    event_report["success"] = False
                    event_report["message"] = str(e)
                    report["success"] = False
            else:
                self.logger.info("Event %s already imported as alert, skipping", eid)
                event_report["message"] = "Already imported"

            report["events"].append(event_report)

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
