import time
import json
import logging
from pymisp import ExpandedPyMISP, MISPAttribute, MISPEvent, MISPSighting
from resilient_lib import IntegrationError


log = logging.getLogger(__name__)

def get_misp_client(URL, API_KEY, VERIFY_CERT, proxies):
    misp_client = ExpandedPyMISP(URL, API_KEY, ssl=VERIFY_CERT, proxies=proxies)
    return misp_client

def create_misp_event(misp_client, misp_distribution, misp_threat_level, misp_analysis_level, misp_event_name, misp_tags):
    misp_event = MISPEvent()
    misp_event.distribution = misp_distribution
    misp_event.threat_level_id = misp_threat_level
    misp_event.analysis = misp_analysis_level
    misp_event.info = misp_event_name

    for misp_tag in misp_tags:
        misp_event.add_tag(misp_tag)

    event_response = misp_client.add_event(misp_event)
    return event_response

def update_misp_event(misp_client, misp_event_uuid, misp_distribution, misp_threat_level, misp_analysis_level, misp_event_name, misp_tags):
    misp_event = misp_client.get_event(event=misp_event_uuid, pythonify=True)
    misp_event.distribution = misp_distribution
    misp_event.threat_level_id = misp_threat_level
    misp_event.analysis = misp_analysis_level
    misp_event.info = misp_event_name

    # Remove all tags directly in MISP
    for t in misp_event.tags:
        t.delete()

    # (re-) Add Tags
    for misp_tag in misp_tags:
        misp_event.add_tag(misp_tag)

    event_response = misp_client.update_event(misp_event)
    return event_response

def clean_orphaned_attribute(misp_client, misp_event_uuid, artifact_name):
    misp_event = misp_client.get_event(event=misp_event_uuid, pythonify=True)
    for a in misp_event.Attribute:
        if a.value==artifact_name:
            a.delete()

    event_response = misp_client.update_event(misp_event)
    return event_response

def create_misp_attribute(misp_client, misp_event_uuid, misp_attribute_type, misp_attribute_value):
    misp_event = MISPEvent()
    misp_event.id = get_event_id(misp_client, misp_event_uuid)
    misp_event.uuid = misp_event_uuid
    misp_attribute = MISPAttribute()
    misp_attribute.type = misp_attribute_type
    misp_attribute.value = misp_attribute_value
    attribute_response = misp_client.add_attribute(misp_event, misp_attribute)
    return attribute_response

def create_misp_sighting(misp_client, my_misp_sighting):
    misp_sighting = MISPSighting()
    misp_sighting.value = my_misp_sighting
    misp_sighting.timestamp = int(time.time())
    misp_sighting.source = "IBM Resilient SOAR"
    sighting_response = misp_client.add_sighting(misp_sighting)
    return sighting_response

def search_misp_attribute(misp_client, search_attribute):
    search_results = misp_client.search(value=search_attribute)
    if not isinstance(search_results, list):
        raise IntegrationError("Received an unexpected response type from the MISP API. Expected a list but received: {}".format(type(search_results)))
    search_results_len = len(search_results)
    if search_results_len == 0:
        success_status = False
    elif search_results_len > 0:
        success_status = True
    else:
        success_status = False
    search_results_response = { 
                                "search_status": success_status,
                                "search_results" : search_results
                            }
    return search_results_response

def check_misp_warninglist(misp_client, search_attribute, misp_override_warninglist) -> bool:
    if misp_override_warninglist:
        return False
    warning_list_entries = misp_client.values_in_warninglist(search_attribute)
    if len(warning_list_entries) > 0:
        return True
    else:
        return False

def get_event_tags(event):
    search_tags = []
    if "Tag" in event["Event"]:
        tags = event["Event"]["Tag"]
        for tag in tags:
            log.info("found tag %s", tag["name"])
            search_tags.append(tag["name"])
    return search_tags

def get_attribute_tags(attribute):
    search_tags = []
    if "Tag" in attribute:
        for tag in attribute["Tag"]:
            log.info("found tag %s", tag["name"])
            search_tags.append(tag["name"])
    return search_tags

def get_misp_attribute_tags(misp_client, search_results):
    search_tags = []
    log.debug(json.dumps(search_results, indent=4))
    for event in search_results:
        # Grab Event Tags
        search_tags += get_event_tags(event)
        # Grab Attribute Tags
        for attribute in event["Event"]["Attribute"]:
            search_tags += get_attribute_tags(attribute)
    search_tags = list(set(search_tags))
    return search_tags

def get_misp_sighting_list(misp_client, misp_event_uuid):
    misp_event = MISPEvent()
    misp_event.uuid = misp_event_uuid
    sighting_result = misp_client.sightings(misp_event)
    return sighting_result

def get_event_id(misp_client, misp_event_uuid):
    # returns list with a single element: an event dict
    result = misp_client.search(eventid=misp_event_uuid)
    for event in result:
        event_uuid = event['Event']['id']
    return event_uuid

def get_event_uuid(misp_client, misp_event_id):
    # returns list with a single element: an event dict
    result = misp_client.search(eventid=misp_event_id)
    for event in result:
        event_uuid = event['Event']['uuid']
    return event_uuid
  
def get_attribute_uuid(misp_client, misp_attribute_value, misp_event_uuid):
    misp_event = MISPEvent()
    misp_event.id = misp_event_uuid
    event_response = misp_client.get_event(misp_event)
    attribute_uuid = None
    if not event_response['Event']['Attribute']:
        log.error("Could not get a uuid for event = %s and attribute = %s. Does it exist?", misp_event_uuid, misp_attribute_value)
        raise IntegrationError("Failed to find any attributes on event {}".format(misp_event_uuid))

    else:
        for attribute in event_response['Event']['Attribute']:
            if attribute['value'] == misp_attribute_value:
                attribute_uuid = attribute['uuid']
        if attribute_uuid:
            return attribute_uuid
        else:
            raise IntegrationError("Failed to match attribute value = {} for any attributes associated with event = {}".format(misp_attribute_value, misp_event_uuid))

def create_tag(misp_client, misp_attribute_value, misp_tag_type, misp_tag_name, misp_event_uuid):
    if misp_tag_type == "Event":
        object_uuid = misp_event_uuid
    elif misp_tag_type == "Attribute":
        object_uuid = get_attribute_uuid(misp_client, misp_attribute_value, misp_event_uuid)
    tag_result = misp_client.tag(object_uuid, misp_tag_name)
    return tag_result

def publish_event(misp_client, misp_event_uuid):
    # returns list with a single element: an event dict
    result = misp_client.publish(event=misp_event_uuid)
    return result.get('message')
