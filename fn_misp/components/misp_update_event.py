# -*- coding: utf-8 -*-
# pragma pylint: disable=unused-argument, no-self-use
"""Function implementation"""

import logging
import sys
if sys.version_info.major < 3:
    from fn_misp.lib import misp_2_helper as misp_helper
else:
    from fn_misp.lib import misp_3_helper as misp_helper
from resilient_circuits import ResilientComponent, function, handler, StatusMessage, FunctionResult, FunctionError
from fn_misp.lib import common


PACKAGE= "fn_misp"

class FunctionComponent(ResilientComponent):
    """Component that implements Resilient function(s)"""

    def __init__(self, opts):
        """constructor provides access to the configuration options"""
        super(FunctionComponent, self).__init__(opts)
        self.opts = opts
        self.options = opts.get(PACKAGE, {})

    @handler("reload")
    def _reload(self, event, opts):
        """Configuration options have changed, save new values"""
        self.opts = opts
        self.options = opts.get(PACKAGE, {})

    @function("misp_update_event")
    def _misp_update_event_function(self, event, *args, **kwargs):
        """Function: create a MISP event from an incident """
        try:

            API_KEY, URL, VERIFY_CERT = common.validate(self.options)

            # Get the function parameters:
            misp_event_uuid = kwargs.get("misp_event_uuid")  # text
            misp_event_name = kwargs.get("misp_event_name")  # text
            misp_distribution_level = kwargs.get("misp_distribution_level")  # number
            misp_analysis_level = kwargs.get("misp_analysis_level")  # number
            misp_threat_level = kwargs.get("misp_threat_level")  # number
            misp_tags_string = kwargs.get("misp_tags")  # text
            misp_tags = misp_tags_string.split(",")

            log = logging.getLogger(__name__)
            log.info("misp_event_uuid: %s", misp_event_uuid)
            log.info("misp_event_name: %s", misp_event_name)
            log.info("misp_distribution: %s", misp_distribution_level)
            log.info("misp_analysis_level: %s", misp_analysis_level)
            log.info("misp_threat_level: %s", misp_threat_level)
            log.info("misp_tags: %s", misp_tags_string)

            yield StatusMessage("Setting up connection to MISP")

            proxies = common.get_proxies(self.opts, self.options)

            misp_client = misp_helper.get_misp_client(URL, API_KEY, VERIFY_CERT, proxies=proxies)

            yield StatusMessage(f"Updating event {misp_event_name} ({misp_event_uuid})")

            event = misp_helper.update_misp_event(misp_client, misp_event_uuid, misp_distribution_level, misp_threat_level, misp_analysis_level, misp_event_name, misp_tags)

            log.debug(event)

            yield StatusMessage("Event has been updated.")

            results = {
                "success": True,
                "content": event
            }

            # Produce a FunctionResult with the results
            yield FunctionResult(results)
        except Exception:
            yield FunctionError()
