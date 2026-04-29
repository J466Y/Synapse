import logging
from modules.FortiEDR.connector import FortiEDRConnector


class Automator:
    def __init__(self):
        self.logger = logging.getLogger("synapse.modules.FortiEDR.automator")
        self.connector = FortiEDRConnector()

    def isolateDevice(self, action_config, webhook):
        """
        Isolate a device in FortiEDR.
        Expected webhook data should contain the collector ID.
        """
        collector_id = webhook.get("collector_id")
        if not collector_id:
            self.logger.error("No collector_id found in webhook for isolateDevice")
            return False, "No collector_id found"

        self.logger.info(f"Isolating device with collector_id: {collector_id}")
        success, message = self.connector.isolateCollector(collector_id)
        return success, message

    def unisolateDevice(self, action_config, webhook):
        """
        Unisolate a device in FortiEDR.
        """
        collector_id = webhook.get("collector_id")
        if not collector_id:
            self.logger.error("No collector_id found in webhook for unisolateDevice")
            return False, "No collector_id found"

        self.logger.info(f"Unisolating device with collector_id: {collector_id}")
        success, message = self.connector.unisolateCollector(collector_id)
        return success, message

    def remediateDevice(self, action_config, webhook):
        """
        Remediate a device in FortiEDR (kill process, delete file, etc.)
        """
        collector_id = webhook.get("collector_id")
        process_id = webhook.get("process_id", 0)

        if not collector_id:
            self.logger.error("No collector_id found in webhook for remediateDevice")
            return False, "No collector_id found"

        self.logger.info(f"Remediating device {collector_id} for process {process_id}")
        success, message = self.connector.remediateDevice(collector_id, process_id)
        return success, message
