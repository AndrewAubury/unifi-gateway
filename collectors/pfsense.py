"""pfSense-specific data collection (running ON the router).

For collecting from a REMOTE pfSense via its REST API instead, use
platform = pfsense-api (collectors.pfsense_api.PfSenseAPICollector).
"""

import logging

from .freebsd import FreeBSDCollector

logger = logging.getLogger("unifi-gateway")


class PfSenseCollector(FreeBSDCollector):
    pass
