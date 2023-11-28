# -*- coding: utf-8 -*-
# pragma pylint: disable=unused-argument, no-self-use
"""Function implementation"""

import logging
import sys
import os
import json
if sys.version_info.major < 3:
    from fn_misp.lib import misp_2_helper as misp_helper
else:
    from fn_misp.lib import misp_3_helper as misp_helper
from resilient_circuits import ResilientComponent, function, handler, StatusMessage, FunctionResult, FunctionError
from fn_misp.lib import common
from resilient_lib import IntegrationError

PACKAGE= "fn_misp"

class FunctionComponent(ResilientComponent):
    """Component that implements Resilient function(s)"""

    def __init__(self, opts):
        """constructor provides access to the configuration options"""
        super(FunctionComponent, self).__init__(opts)
        self.opts = opts
        self.options = opts.get(PACKAGE, {})
        self.misp_mapping_config = f"{os.path.dirname(os.getenv('APP_CONFIG_FILE'))}/misp_mapping.cfg"
        with open(self.misp_mapping_config) as f:
            self.misp_type_mapping = json.load(f)


    @handler("reload")
    def _reload(self, event, opts):
        """Configuration options have changed, save new values"""
        self.opts = opts
        self.options = opts.get(PACKAGE, {})

    @function("misp_create_attribute")
    def _misp_create_attribute_function(self, event, *args, **kwargs):
        """Function: """
        try:

            API_KEY, URL, VERIFY_CERT = common.validate(self.options)

            # Get the function parameters:
            misp_event_uuid = kwargs.get("misp_event_uuid")  # string (uuid4)
            misp_attribute_value = kwargs.get("misp_attribute_value")  # text
            resilient_attribute_type = kwargs.get("resilient_attribute_type")  # text
            misp_override_warninglist = kwargs.get("misp_override_warninglist", False)  # bool

            # ensure misp_event_uuid is an integer so we can get an event by it's index
            if not isinstance(misp_event_uuid, str):
                raise IntegrationError(f"Unexpected input type for MISP Event ID. Expected and integer, received {type(misp_event_uuid)}")

            log = logging.getLogger(__name__)
            log.info("misp_event_uuid: %s", misp_event_uuid)
            log.info("misp_attribute_value: %s", misp_attribute_value)
            log.info("misp_attribute_type: %s", resilient_attribute_type)

            yield StatusMessage("Setting up connection to MISP")

            proxies = common.get_proxies(self.opts, self.options)

            misp_client = misp_helper.get_misp_client(URL, API_KEY, VERIFY_CERT, proxies=proxies)

            # Check misp_attribute_value against MISP Warninglists
            # if misp_override_warninglist is NOT set
            if misp_helper.check_misp_warninglist(misp_client, misp_attribute_value, misp_override_warninglist):
                message = f"'{misp_attribute_value}' is member of at least one MISP Warninglist. Skipping..."
                yield StatusMessage(message)
                # Produce a FunctionResult with the results
                yield FunctionResult({}, success=False, reason=str(message))

            else:
                yield StatusMessage(f"Creating new misp attribute {resilient_attribute_type} {misp_attribute_value}")

                attribute = misp_helper.create_misp_attribute(misp_client, misp_event_uuid, resilient_attribute_type, misp_attribute_value)

                log.debug(attribute)

                yield StatusMessage("Attribute has been created")

                results = { "success": True,
                            "content": attribute
                        }

                # Produce a FunctionResult with the results
                yield FunctionResult(results)

        except Exception:
            yield FunctionError()
