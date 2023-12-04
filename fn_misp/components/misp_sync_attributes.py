# -*- coding: utf-8 -*-
# pragma pylint: disable=unused-argument, no-self-use
"""Function implementation"""

from resilient_circuits import ResilientComponent, function, handler, StatusMessage, FunctionResult, FunctionError
from fn_misp.lib import common
from resilient_lib import IntegrationError
import logging
import sys
import os
import json
if sys.version_info.major < 3:
    from fn_misp.lib import misp_2_helper as misp_helper
else:
    from fn_misp.lib import misp_3_helper as misp_helper

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

    @function("misp_sync_attributes")
    def _misp_sync_attributes_function(self, event, *args, **kwargs):
        """Function: """
        try:

            API_KEY, URL, VERIFY_CERT = common.validate(self.options)

            # Get the function parameters:
            misp_event_uuid = kwargs.get("misp_event_uuid")  # number
            incident_id = kwargs.get("incident_id")  # number
            misp_override_warninglist = kwargs.get("misp_override_warninglist", False)  # bool

            # ensure misp_event_uuid is an integer so we can get an event by it's index
            if not isinstance(misp_event_uuid, str):
                raise IntegrationError(f"Unexpected input type for MISP Event ID. Expected and integer, received {type(misp_event_uuid)}")

            # ensure incident_id is an integer so we can get an incident by it's index
            if not isinstance(incident_id, int):
                raise IntegrationError(f"Unexpected input type for Incident ID. Expected and integer, received {type(incident_id)}")

            log = logging.getLogger(__name__)
            log.info("misp_event_uuid: %s", misp_event_uuid)
            log.info("incident_id: %s", incident_id)

            # Instantiate a rest client
            res_client = self.rest_client()

            # Get artifacts for this incident
            log.info("Start: Gathering artifacts from API")
            artifacts = res_client.post("/incidents/{}/artifacts/query_paged?handle_format=names".format(incident_id), payload={})
            log.info("Stopped: Gathering artifacts from API")
            yield StatusMessage(f"Caught {len(artifacts)} from Incident {incident_id}")

            yield StatusMessage("Setting up connection to MISP")

            proxies = common.get_proxies(self.opts, self.options)

            misp_client = misp_helper.get_misp_client(URL, API_KEY, VERIFY_CERT, proxies=proxies)
            misp_event_uuid = kwargs.get("misp_event_uuid")  # string (uuid4)

            loop_cnt = 0
            artifact_cnt = len(artifacts.get('data'))
            for artifact in artifacts.get('data'):
                # Do something with the artifact
                log.info(artifact)
                misp_override_warninglist = False
                # Skip if blacklisted artifact type
                if self.misp_type_mapping.get(artifact.get('type')) is None:
                    log.info("Data Type blacklisted in mapping!")
                else:
                    # Check misp_attribute_value against MISP Warninglists
                    # if misp_override_warninglist is NOT set
                    misp_attribute_value = artifact.get('value')
                    misp_attribute_type = self.misp_type_mapping.get(artifact.get('type'))

                    artifact_tags = artifact['global_info'].get('tags')
                    for tag in artifact_tags:
                        if tag.get('tag_handle') == "override-warninglist":
                            misp_override_warninglist = True

                    if misp_helper.check_misp_warninglist(misp_client, misp_attribute_value, misp_override_warninglist):
                        message = f"'{misp_attribute_value}' is member of at least one MISP Warninglist. Skipping..."
                        yield StatusMessage(message)
                        # Produce a FunctionResult with the results
                        yield FunctionResult({"success": False, "content": str(message)})

                    else:
                        yield StatusMessage(f"Creating new misp attribute {misp_attribute_type} {misp_attribute_value}")

                        attribute = misp_helper.create_misp_attribute(misp_client, misp_event_uuid, misp_attribute_type, misp_attribute_value)

                        log.debug(attribute)
                        loop_cnt += 1
                        yield StatusMessage(f"Attribute '{misp_attribute_value}' has been created")

            yield StatusMessage(f"Created {loop_cnt}/{artifact_cnt} attributes.")

            results = { "success": True,
                        "content": f"Created {loop_cnt}/{artifact_cnt} attributes."
                      }

            # Produce a FunctionResult with the results
            yield FunctionResult(results)
        except Exception:
            yield FunctionError()
