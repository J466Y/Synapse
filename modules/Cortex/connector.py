#!/usr/bin/env python3
# -*- coding: utf8 -*-

import logging
import json

from cortex4py.api import Api


class CortexConnector:
    'Cortex connector'

    def __init__(self, cfg):
        self.logger = logging.getLogger('workflows.' + __name__)
        self.cfg = cfg

        self.CortexApi = self.connect()

    def connect(self):
        self.logger.info('%s.connect starts', __name__)

        url = self.cfg.get('Cortex', 'url')
        api_key = self.cfg.get('Cortex', 'api_key')
        cert = self.cfg.get('Cortex', 'ca', fallback=True)

        return Api(url, api_key, cert)
    
    def runResponder(self, responder_id, data):
        """
        :param responder_id: name of the responder used by the job
        :param data: data for the responder
        :rtype: json
        """
        self.logger.info('%s.runResponder starts', __name__)
        response = self.CortexApi.responders.run_by_id(responder_id, data)
        return response.json()

    def runAnalyzer(self, analyzer_name, data, data_type, tlp=2, message=''):
        """
        :param analyzer_name: name of the analyzer to run
        :param data: observable data
        :param data_type: type of observable
        :param tlp: TLP level (default 2)
        :param message: optional message for the job
        :rtype: dict
        """
        self.logger.info('%s.runAnalyzer starts for %s', __name__, analyzer_name)
        observable = {
            'data': data,
            'dataType': data_type,
            'tlp': tlp,
            'message': message
        }
        response = self.CortexApi.analyzers.run_by_name(analyzer_name, observable)
        # cortex4py returns a Job model object, converting to dict
        return response.__dict__