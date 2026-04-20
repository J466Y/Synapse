#!/usr/bin/env python3
# -*- coding: utf8 -*-

import logging
import json
from datetime import datetime, timedelta, timezone
import fortiedr

class FortiEDRConnector:
    """FortiEDR connector for Synapse"""

    def __init__(self, cfg):
        """
        Class constructor
        :param cfg: synapse configuration
        :type cfg: YamlCP
        """
        self.logger = logging.getLogger(__name__)
        self.cfg = cfg
        
        try:
            self.host = self.cfg.get('FortiEDR', 'host')
            self.user = self.cfg.get('FortiEDR', 'user')
            self.password = self.cfg.get('FortiEDR', 'password')
            self.organization = self.cfg.get('FortiEDR', 'organization')
            
            # Authenticate on instantiation
            self.authenticate()
            
        except Exception as e:
            self.logger.error('Failed to initialize FortiEDR connector: %s', e, exc_info=True)
            raise

    def authenticate(self):
        """
        Authenticate with FortiEDR
        """
        self.logger.debug('Authenticating with FortiEDR at %s', self.host)
        try:
            auth_result = fortiedr.auth(
                user=self.user,
                passw=self.password,
                host=self.host,
                org=self.organization
            )
            
            if not auth_result['status']:
                self.logger.error('FortiEDR authentication failed: %s', auth_result['data'])
                # Handle auth failure gracefully - we store the status but don't necessarily crash
                # although Subsequent calls will fail if not authenticated.
            else:
                self.logger.info('FortiEDR authentication successful')
            
            return auth_result
        except Exception as e:
            self.logger.error('Unexpected error during FortiEDR authentication: %s', e, exc_info=True)
            return {'status': False, 'data': str(e)}

    def list_events(self, timerange_minutes=None):
        """
        Fetch recent security events
        :param timerange_minutes: range in minutes to fetch events for
        :return: normalized dict {'status': bool, 'data': ...}
        """
        self.logger.debug('Listing FortiEDR events (timerange: %s min)', timerange_minutes)
        try:
            events_api = fortiedr.Events()
            
            params = {'organization': self.organization}
            
            if timerange_minutes:
                # Calculate time range
                # FortiEDR API uses yyyy-MM-dd HH:mm:ss for firstSeenFrom/To
                now = datetime.now(timezone.utc)
                start_time = now - timedelta(minutes=timerange_minutes)
                
                params['lastSeenFrom'] = start_time.strftime('%Y-%m-%d %H:%M:%S')
                params['lastSeenTo'] = now.strftime('%Y-%m-%d %H:%M:%S')
                
            result = events_api.list_events(**params)
            return result
        except Exception as e:
            self.logger.error('Failed to list FortiEDR events: %s', e, exc_info=True)
            return {'status': False, 'data': str(e)}

    def count_events(self):
        """
        Count total events
        :return: normalized dict {'status': bool, 'data': ...}
        """
        self.logger.debug('Counting FortiEDR events')
        try:
            events_api = fortiedr.Events()
            result = events_api.count_events(organization=self.organization)
            return result
        except Exception as e:
            self.logger.error('Failed to count FortiEDR events: %s', e, exc_info=True)
            return {'status': False, 'data': str(e)}

    def list_collectors(self):
        """
        List protected endpoints
        :return: normalized dict {'status': bool, 'data': ...}
        """
        self.logger.debug('Listing FortiEDR collectors')
        try:
            inventory_api = fortiedr.SystemInventory()
            result = inventory_api.list_collectors(organization=self.organization)
            return result
        except Exception as e:
            self.logger.error('Failed to list FortiEDR collectors: %s', e, exc_info=True)
            return {'status': False, 'data': str(e)}

    def isolate_collector(self, device):
        """
        Isolate/contain an endpoint
        :param device: device name or ID
        :return: normalized dict {'status': bool, 'data': ...}
        """
        self.logger.info('Isolating device: %s', device)
        try:
            inventory_api = fortiedr.SystemInventory()
            # The library takes devices as a list
            result = inventory_api.isolate_collectors(devices=[device], organization=self.organization)
            return result
        except Exception as e:
            self.logger.error('Failed to isolate device %s: %s', device, e, exc_info=True)
            return {'status': False, 'data': str(e)}

    def unisolate_collector(self, device):
        """
        Release isolation
        :param device: device name or ID
        :return: normalized dict {'status': bool, 'data': ...}
        """
        self.logger.info('Unisolating device: %s', device)
        try:
            inventory_api = fortiedr.SystemInventory()
            result = inventory_api.unisolate_collectors(devices=[device], organization=self.organization)
            return result
        except Exception as e:
            self.logger.error('Failed to unisolate device %s: %s', device, e, exc_info=True)
            return {'status': False, 'data': str(e)}

    def remediate_device(self, device, process_id=None):
        """
        Trigger remediation
        :param device: device name or ID
        :param process_id: process ID to terminate (optional, defaults to 0 if not provided)
        :return: normalized dict {'status': bool, 'data': ...}
        """
        self.logger.info('Remediating device: %s', device)
        try:
            forensics_api = fortiedr.Forensics()
            # fortiedr.py requires terminatedProcessId
            # If not provided, we might need a default or a way to discover it.
            # For now, following the user's simplified request structure.
            pid = process_id if process_id else 0
            result = forensics_api.remediate_device(terminatedProcessId=pid, device=device, organization=self.organization)
            return result
        except Exception as e:
            self.logger.error('Failed to remediate device %s: %s', device, e, exc_info=True)
            return {'status': False, 'data': str(e)}


    def get_event(self, event_id):
        """
        Get details of a specific event
        :param event_id: FortiEDR event ID
        :return: event dictionary or None
        """
        self.logger.debug('Fetching details for event %s', event_id)
        try:
            events_api = fortiedr.Events()
            result = events_api.list_events(eventIds=[int(event_id)], organization=self.organization)
            if result['status'] and isinstance(result['data'], list) and len(result['data']) > 0:
                return result['data'][0]
            elif result['status'] and isinstance(result['data'], dict) and result['data'].get('events'):
                events = result['data'].get('events')
                if events:
                    return events[0]
            return None
        except Exception as e:
            self.logger.error('Failed to get event %s: %s', event_id, e)
            return None

    def create_exception(self, event_id, collector_groups=None, destinations=None, users=None, comment=None, all_groups=True, all_dests=True, all_users=True):
        """
        Create a security exception
        :param event_id: FortiEDR event ID
        :param collector_groups: list of collector group names
        :param destinations: list of destination IPs
        :param users: list of user names
        :param comment: comment
        :param all_groups: bool (True = all groups)
        :param all_dests: bool (True = all destinations)
        :param all_users: bool (True = all users)
        :return: normalized dict
        """
        self.logger.info('Creating exception for event: %s (Scoped: groups=%s, dests=%s, users=%s)', event_id, not all_groups, not all_dests, not all_users)
        try:
            events_api = fortiedr.Events()

            # The FortiEDR SDK might be sensitive to boolean objects vs lowercase strings
            def botos(b):
                return str(b).lower() if isinstance(b, bool) else b

            params = {
                'eventId': int(event_id),
                'organization': self.organization,
                'allCollectorGroups': botos(all_groups),
                'allDestinations': botos(all_dests),
                'allUsers': botos(all_users)
            }

            if collector_groups:
                params['collectorGroups'] = collector_groups
                params['allCollectorGroups'] = 'false'
            if destinations:
                params['destinations'] = destinations
                params['allDestinations'] = 'false'
            if users:
                params['users'] = users
                params['allUsers'] = 'false'
            if comment:
                params['comment'] = comment

            result = events_api.create_exception(**params)
            return result
        except Exception as e:
            self.logger.error('Failed to create exception for event %s: %s', event_id, e, exc_info=True)
            return {'status': False, 'data': str(e)}
