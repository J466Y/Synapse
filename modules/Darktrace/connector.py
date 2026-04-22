#!/usr/bin/env python3
# -*- coding: utf8 -*-

import logging
from darktrace.client import DarktraceClient

class DarktraceConnector:
    """Darktrace connector for Synapse"""

    def __init__(self, cfg):
        """
        Class constructor
        :param cfg: synapse configuration
        :type cfg: YamlCP
        """
        self.logger = logging.getLogger(__name__)
        self.cfg = cfg
        
        try:
            self.host = self.cfg.get('Darktrace', 'host')
            self.public_token = self.cfg.get('Darktrace', 'public_token')
            self.private_token = self.cfg.get('Darktrace', 'private_token')
            # The SDK handles cert verification natively using 'verify' parameter, defaulting to requests' handling.
            self.cert_verification = self.cfg.getboolean('Darktrace', 'cert_verification', fallback=True)
            
            # Authenticate / Initialize client
            self.authenticate()
            
        except Exception as e:
            self.logger.error('Failed to initialize Darktrace connector: %s', e, exc_info=True)
            raise

    def authenticate(self):
        """
        Initialize the DarktraceClient
        """
        self.logger.debug('Initializing DarktraceClient at %s', self.host)
        try:
            self.client = DarktraceClient(
                host=self.host,
                public_token=self.public_token,
                private_token=self.private_token,
                verify=self.cert_verification
            )
            self.logger.info('Darktrace client initialized successfully')
            return {'status': True, 'data': 'Client initialized'}
        except Exception as e:
            self.logger.error('Unexpected error during Darktrace initialization: %s', e, exc_info=True)
            return {'status': False, 'data': str(e)}

    def get_breaches(self, from_time, to_time):
        """
        Fetch recent model breaches
        :param from_time: Start time in "YYYY-MM-DD HH:MM:SS"
        :param to_time: End time in "YYYY-MM-DD HH:MM:SS"
        :return: list of breach dicts or empty list
        """
        self.logger.debug('Fetching Darktrace breaches from %s to %s', from_time, to_time)
        try:
            # We want readable fields and device information at the top
            breaches_data = self.client.breaches.get(
                from_time=from_time,
                to_time=to_time,
                expandenums=True,
                deviceattop=True
            )
            return breaches_data if breaches_data else []
        except Exception as e:
            self.logger.error('Failed to get Darktrace breaches: %s', e, exc_info=True)
            return []

    def acknowledge_breach(self, pbid):
        """
        Acknowledge a specific model breach alert
        :param pbid: specific breach ID
        """
        self.logger.debug('Acknowledging Darktrace breach: %s', pbid)
        try:
            result = self.client.breaches.acknowledge(pbid=pbid)
            return {'status': True, 'data': result}
        except Exception as e:
            self.logger.error('Failed to acknowledge Darktrace breach %s: %s', pbid, e, exc_info=True)
            return {'status': False, 'data': str(e)}

    def add_comment(self, pbid, comment):
        """
        Add a comment to a specific model breach alert
        :param pbid: specific breach ID
        :param comment: string comment to add
        """
        self.logger.debug('Adding comment to Darktrace breach: %s', pbid)
        try:
            result = self.client.breaches.add_comment(pbid=pbid, message=comment)
            return {'status': True, 'data': result}
        except Exception as e:
            self.logger.error('Failed to add comment to Darktrace breach %s: %s', pbid, e, exc_info=True)
            return {'status': False, 'data': str(e)}
