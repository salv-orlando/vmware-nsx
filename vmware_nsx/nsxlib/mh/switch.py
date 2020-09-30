# Copyright 2014 VMware, Inc.
# All Rights Reserved
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#

from neutron_lib import exceptions as exception
from oslo_config import cfg
from oslo_log import log
from oslo_serialization import jsonutils

from vmware_nsx.api_client import exception as api_exc
from vmware_nsx.common import utils
from vmware_nsx.nsxlib import mh as nsxlib

HTTP_GET = "GET"
HTTP_POST = "POST"
HTTP_DELETE = "DELETE"
HTTP_PUT = "PUT"

LSWITCH_RESOURCE = "lswitch"
LSWITCHPORT_RESOURCE = "lport/%s" % LSWITCH_RESOURCE

LOG = log.getLogger(__name__)


def _configure_extensions(lport_obj, mac_address, fixed_ips,
                          port_security_enabled, security_profiles,
                          queue_id, mac_learning_enabled,
                          allowed_address_pairs):
    lport_obj['allowed_address_pairs'] = []
    if port_security_enabled:
        for fixed_ip in fixed_ips:
            ip_address = fixed_ip.get('ip_address')
            if ip_address:
                lport_obj['allowed_address_pairs'].append(
                    {'mac_address': mac_address, 'ip_address': ip_address})
        # add address pair allowing src_ip 0.0.0.0 to leave
        # this is required for outgoing dhcp request
        lport_obj["allowed_address_pairs"].append(
            {"mac_address": mac_address,
             "ip_address": "0.0.0.0"})
    lport_obj['security_profiles'] = list(security_profiles or [])
    lport_obj['queue_uuid'] = queue_id
    if mac_learning_enabled is not None:
        lport_obj["mac_learning"] = mac_learning_enabled
        lport_obj["type"] = "LogicalSwitchPortConfig"
    for address_pair in list(allowed_address_pairs or []):
        lport_obj['allowed_address_pairs'].append(
            {'mac_address': address_pair['mac_address'],
             'ip_address': address_pair['ip_address']})


def get_lswitches(cluster, neutron_net_id):

    def lookup_switches_by_tag():
        # Fetch extra logical switches
        lswitch_query_path = nsxlib._build_uri_path(
            LSWITCH_RESOURCE,
            fields="uuid,display_name,tags,lport_count",
            relations="LogicalSwitchStatus",
            filters={'tag': neutron_net_id,
                     'tag_scope': 'quantum_net_id'})
        return nsxlib.get_all_query_pages(lswitch_query_path, cluster)

    lswitch_uri_path = nsxlib._build_uri_path(LSWITCH_RESOURCE, neutron_net_id,
                                              relations="LogicalSwitchStatus")
    results = []
    try:
        ls = nsxlib.do_request(HTTP_GET, lswitch_uri_path, cluster=cluster)
        results.append(ls)
        for tag in ls['tags']:
            if (tag['scope'] == "multi_lswitch" and
                tag['tag'] == "True"):
                results.extend(lookup_switches_by_tag())
    except exception.NotFound:
        # This is legit if the neutron network was created using
        # a post-Havana version of the plugin
        results.extend(lookup_switches_by_tag())
    if results:
        return results
    raise exception.NetworkNotFound(net_id=neutron_net_id)


# This api is currently used only for unittests
def create_lswitch(cluster, neutron_net_id, tenant_id, display_name,
                   transport_zones_config,
                   shared=None,
                   **kwargs):
    # The tag scope adopts a slightly different naming convention for
    # historical reasons
    lswitch_obj = {"display_name": utils.check_and_truncate(display_name),
                   "transport_zones": transport_zones_config,
                   "replication_mode": cfg.CONF.NSX.replication_mode,
                   "tags": utils.get_tags(os_tid=tenant_id,
                                          quantum_net_id=neutron_net_id)}
    # TODO(salv-orlando): Now that we have async status synchronization
    # this tag is perhaps not needed anymore
    if shared:
        lswitch_obj["tags"].append({"tag": "true",
                                    "scope": "shared"})
    if "tags" in kwargs:
        lswitch_obj["tags"].extend(kwargs["tags"])
    uri = nsxlib._build_uri_path(LSWITCH_RESOURCE)
    lswitch = nsxlib.do_request(HTTP_POST, uri, jsonutils.dumps(lswitch_obj),
                                cluster=cluster)
    LOG.debug("Created logical switch: %s", lswitch['uuid'])
    return lswitch


def delete_port(cluster, switch, port):
    uri = "/ws.v1/lswitch/" + switch + "/lport/" + port
    try:
        nsxlib.do_request(HTTP_DELETE, uri, cluster=cluster)
    except exception.NotFound as e:
        LOG.error("Port or Network not found, Error: %s", str(e))
        raise exception.PortNotFoundOnNetwork(
            net_id=switch, port_id=port)
    except api_exc.NsxApiException:
        raise exception.NeutronException()


def get_port_by_neutron_tag(cluster, lswitch_uuid, neutron_port_id):
    """Get port by neutron tag.

    Returns the NSX UUID of the logical port with tag q_port_id equal to
    neutron_port_id or None if the port is not Found.
    """
    uri = nsxlib._build_uri_path(LSWITCHPORT_RESOURCE,
                                 parent_resource_id=lswitch_uuid,
                                 fields='uuid',
                                 filters={'tag': neutron_port_id,
                                          'tag_scope': 'q_port_id'})
    LOG.debug("Looking for port with q_port_id tag '%(neutron_port_id)s' "
              "on: '%(lswitch_uuid)s'",
              {'neutron_port_id': neutron_port_id,
               'lswitch_uuid': lswitch_uuid})
    res = nsxlib.do_request(HTTP_GET, uri, cluster=cluster)
    num_results = len(res["results"])
    if num_results >= 1:
        if num_results > 1:
            LOG.warning("Found '%(num_ports)d' ports with "
                        "q_port_id tag: '%(neutron_port_id)s'. "
                        "Only 1 was expected.",
                        {'num_ports': num_results,
                         'neutron_port_id': neutron_port_id})
        return res["results"][0]


# This api is currently used only for unittests
def get_port(cluster, network, port, relations=None):
    LOG.info("get_port() %(network)s %(port)s",
             {'network': network, 'port': port})
    uri = "/ws.v1/lswitch/" + network + "/lport/" + port + "?"
    if relations:
        uri += "relations=%s" % relations
    try:
        return nsxlib.do_request(HTTP_GET, uri, cluster=cluster)
    except exception.NotFound as e:
        LOG.error("Port or Network not found, Error: %s", str(e))
        raise exception.PortNotFoundOnNetwork(
            port_id=port, net_id=network)


def create_lport(cluster, lswitch_uuid, tenant_id, neutron_port_id,
                 display_name, device_id, admin_status_enabled,
                 mac_address=None, fixed_ips=None, port_security_enabled=None,
                 security_profiles=None, queue_id=None,
                 mac_learning_enabled=None, allowed_address_pairs=None):
    """Creates a logical port on the assigned logical switch."""
    display_name = utils.check_and_truncate(display_name)
    lport_obj = dict(
        admin_status_enabled=admin_status_enabled,
        display_name=display_name,
        tags=utils.get_tags(os_tid=tenant_id,
                            q_port_id=neutron_port_id,
                            vm_id=utils.device_id_to_vm_id(device_id))
    )

    _configure_extensions(lport_obj, mac_address, fixed_ips,
                          port_security_enabled, security_profiles,
                          queue_id, mac_learning_enabled,
                          allowed_address_pairs)

    path = nsxlib._build_uri_path(LSWITCHPORT_RESOURCE,
                                  parent_resource_id=lswitch_uuid)
    result = nsxlib.do_request(HTTP_POST, path, jsonutils.dumps(lport_obj),
                               cluster=cluster)

    LOG.debug("Created logical port %(result)s on logical switch %(uuid)s",
              {'result': result['uuid'], 'uuid': lswitch_uuid})
    return result
