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

    def health_check(self):
        """
        Quickly check if the target server is reachable on port 443.
        Returns True if reachable, False otherwise.
        """
        import socket
        self.logger.debug("Performing health check on target server %s", self.host)
        try:
            with socket.create_connection((self.host, 443), timeout=3):
                return True
        except (socket.timeout, socket.error):
            self.logger.warning("FortiEDR server %s is unreachable", self.host)
            return False

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
                # We need it in CEST (Europe/Madrid) as per user request
                import zoneinfo
                tz = zoneinfo.ZoneInfo('Europe/Madrid')
                now = datetime.now(tz)
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

    def create_exception(self, event_id, collector_groups=None, destinations=None,
                         comment=None, all_groups=True, all_dests=True,
                         use_any_path=None, use_in_exception=None,
                         wildcard_files=None, wildcard_paths=None,
                         force_create=True):
        """
        Create a FortiEDR exception for a security event.
        Bypasses the library's create_exception because it stringifies the JSON body.
        Follows the documented sample:
          .../create-exception?eventId=1000&allCollectorGroups=false&collectorGroups=OSX Users,Home Users&allDestinations=false&destinations=1.2.3.4,5.6.7.8,internal destinations&forceCreate=true
        """
        try:
            self.authenticate()

            # Build URL with raw f-strings (NO urlencode — FortiEDR expects raw values)
            url = '/management-rest/events/create-exception'
            url_params = []

            url_params.append(f'eventId={int(event_id)}')

            if all_groups is not None:
                url_params.append(f'allCollectorGroups={str(all_groups).lower()}')
            if collector_groups:
                cg = ",".join(collector_groups) if isinstance(collector_groups, list) else collector_groups
                url_params.append(f'collectorGroups={cg}')

            if all_dests is not None:
                url_params.append(f'allDestinations={str(all_dests).lower()}')
            if destinations:
                d = ",".join(destinations) if isinstance(destinations, list) else destinations
                url_params.append(f'destinations={d}')

            if force_create is not None:
                url_params.append(f'forceCreate={str(force_create).lower()}')

            if comment:
                url_params.append(f'comment={comment}')

            #if self.organization:
            #    url_params.append(f'organization={self.organization}')

            url += '?' + '&'.join(url_params)

            self.logger.info('Creating exception for event %s', event_id)
            self.logger.debug('Create-exception URL: %s', url)

            from fortiedr import fortiedr as fortiedr_lib
            result = fortiedr_lib.fortiedr_connection.send(url)
            
            # Log the full error response for debugging
            if not result.get('status'):
                self.logger.error('Exception creation FAILED. Full API response: %s', json.dumps(result.get('data', {}), indent=2, default=str))
            
            return result
        except Exception as e:
            self.logger.error('Failed to create exception for event %s: %s', event_id, e, exc_info=True)
            return {'status': False, 'data': str(e)}
