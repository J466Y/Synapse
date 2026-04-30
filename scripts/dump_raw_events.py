#!/usr/bin/env python3
# -*- coding: utf8 -*-

import json
import datetime
import logging
import os
import sys

# Add the project root to the path so we can import core and modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.functions import getConf
from modules.QRadar.connector import QRadarConnector
from modules.Darktrace.connector import DarktraceConnector

# Setup basic logging to see what's happening
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("DumpRawEvents")

def dump_qradar(cfg):
    logger.info("Starting QRadar dump...")
    try:
        connector = QRadarConnector(cfg)
        # 24 hours in minutes
        timerange = 24 * 60
        logger.info(f"Fetching QRadar offenses for the last {timerange} minutes...")
        offenses = connector.getOffenses(timerange)
        
        # For each offense, we want to enrich it with rule names and logs as the pulls do
        enriched_offenses = []
        for offense in offenses:
            logger.info(f"Enriching QRadar offense {offense['id']}...")
            # We add rule names
            offense['rule_names'] = connector.getRuleNames(offense)
            # We add logs (first 3)
            offense['raw_logs'] = connector.getOffenseLogs(offense)
            # We add offense type string
            offense['offense_type_str'] = connector.getOffenseTypeStr(offense['offense_type'])
            enriched_offenses.append(offense)
            
        output_file = "qradar_raw.json"
        with open(output_file, "w") as f:
            json.dump(enriched_offenses, f, indent=4)
        logger.info(f"QRadar dump completed. Saved to {output_file}")
    except Exception as e:
        logger.error(f"Failed to dump QRadar data: {e}", exc_info=True)

def dump_darktrace(cfg):
    logger.info("Starting Darktrace dump...")
    try:
        connector = DarktraceConnector(cfg)
        
        to_dt = datetime.datetime.now(datetime.timezone.utc)
        from_dt = to_dt - datetime.timedelta(days=1)
        starttime_ms = int(from_dt.timestamp() * 1000)
        endtime_ms = int(to_dt.timestamp() * 1000)
        
        logger.info(f"Fetching Darktrace breaches from {from_dt} to {to_dt}...")
        breaches = connector.get_breaches(starttime_ms, endtime_ms)
        
        output_file = "darktrace_raw.json"
        with open(output_file, "w") as f:
            json.dump(breaches, f, indent=4)
        logger.info(f"Darktrace dump completed. Saved to {output_file}")
    except Exception as e:
        logger.error(f"Failed to dump Darktrace data: {e}", exc_info=True)

if __name__ == "__main__":
    cfg = getConf()
    
    # Check if modules are enabled in config before running
    if cfg.getboolean("QRadar", "enabled", fallback=False):
        dump_qradar(cfg)
    else:
        logger.warning("QRadar module is disabled in synapse.conf")
        
    if cfg.getboolean("Darktrace", "enabled", fallback=False):
        #dump_darktrace(cfg)
        pass
    else:
        logger.warning("Darktrace module is disabled in synapse.conf")
