# Copyright 2018 VMware, Inc.  All rights reserved.
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

from neutron_lib.callbacks import registry
from neutron_lib import context
from oslo_log import log as logging

from vmware_nsx.shell.admin.plugins.common import constants
from vmware_nsx.shell.admin.plugins.common import utils as admin_utils
from vmware_nsx.shell.admin.plugins.nsxp.resources import utils as p_utils
from vmware_nsx.shell import resources as shell
from vmware_nsxlib.v3 import nsx_constants

LOG = logging.getLogger(__name__)


@admin_utils.list_handler(constants.NETWORKS)
@admin_utils.output_header
@admin_utils.unpack_payload
def list_networks(resource, event, trigger, **kwargs):
    """List neutron networks

    With the NSX policy resources and realization state.
    """
    mappings = []
    nsxpolicy = p_utils.get_connected_nsxpolicy()
    ctx = context.get_admin_context()
    with p_utils.NsxPolicyPluginWrapper() as plugin:
        nets = plugin.get_networks(ctx)
        for net in nets:
            # skip non-backend networks
            if plugin._network_is_external(ctx, net['id']):
                continue
            segment_id = plugin._get_network_nsx_segment_id(ctx, net['id'])
            status = p_utils.get_realization_info(
                nsxpolicy.segment, segment_id)
            mappings.append({'ID': net['id'],
                             'Name': net.get('name'),
                             'Project': net.get('tenant_id'),
                             'NSX status': status})
    p_utils.log_info(constants.NETWORKS,
                     mappings,
                     attrs=['Project', 'Name', 'ID', 'NSX status'])
    return bool(mappings)


@admin_utils.output_header
@admin_utils.unpack_payload
def migrate_dhcp_to_policy(resource, event, trigger, **kwargs):
    errmsg = ("Need to specify policy dhcp config id. Add "
              "--property dhcp-config=<id>")
    if not kwargs.get('property'):
        LOG.error("%s", errmsg)
        return
    properties = admin_utils.parse_multi_keyval_opt(kwargs['property'])
    dhcp_config_id = properties.get('dhcp-config')
    if not dhcp_config_id:
        LOG.error("%s", errmsg)
        return

    nsxpolicy = p_utils.get_connected_nsxpolicy()
    if not nsxpolicy.feature_supported(
            nsx_constants.FEATURE_NSX_POLICY_DHCP):
        LOG.error("This utility is not available for NSX version %s",
                  nsxpolicy.get_version())
        return

    try:
        nsxpolicy.dhcp_server_config.get(dhcp_config_id)
    except Exception:
        LOG.error("%s", errmsg)
        return

    ctx = context.get_admin_context()
    migrate_count = 0
    with p_utils.NsxPolicyPluginWrapper() as plugin:
        nets = plugin.get_networks(ctx)
        for net in nets:
            # skip non-dhcp networks
            dhcp_port = plugin._get_net_dhcp_port(ctx, net['id'])
            if not dhcp_port:
                LOG.info("Skipping network %s: No DHCP subnet found",
                         net['id'])
                continue
            dhcp_subnet_id = [fip['subnet_id']
                              for fip in dhcp_port['fixed_ips']][0]
            az = plugin.get_network_az_by_net_id(ctx, net['id'])
            az._policy_dhcp_server_config = dhcp_config_id
            dhcp_subnet = plugin.get_subnet(ctx, dhcp_subnet_id)

            # Verify that this network does not use policy DHCP already
            segment_id = plugin._get_network_nsx_segment_id(ctx, net['id'])
            segment = nsxpolicy.segment.get(segment_id)
            if segment.get('dhcp_config_path'):
                LOG.info("Skipping network %s: Already using policy DHCP",
                         net['id'])
                continue

            LOG.info("Migrating network %s", net['id'])
            # Disable MP DHCP
            plugin._disable_native_dhcp(ctx, net['id'])
            # Enable Policy DHCP
            plugin._enable_subnet_dhcp(ctx, net, dhcp_subnet, az)
            migrate_count = migrate_count + 1

    LOG.info("Finished migrating %s networks", migrate_count)


@admin_utils.output_header
@admin_utils.unpack_payload
def update_admin_state(resource, event, trigger, **kwargs):
    """Upon upgrade to NSX3 update policy segments & ports
    So that the neutron admin state will match the policy one
    """
    nsxpolicy = p_utils.get_connected_nsxpolicy()
    if not nsxpolicy.feature_supported(
            nsx_constants.FEATURE_NSX_POLICY_ADMIN_STATE):
        LOG.error("This utility is not available for NSX version %s",
                  nsxpolicy.get_version())
        return

    ctx = context.get_admin_context()
    with p_utils.NsxPolicyPluginWrapper() as plugin:
        # Inconsistencies can happen only if the neutron state is Down
        filters = {'admin_state_up': [False]}
        nets = plugin.get_networks(ctx, filters=filters)
        for net in nets:
            seg_id = plugin._get_network_nsx_segment_id(ctx, net['id'])
            nsxpolicy.segment.set_admin_state(seg_id, False)

        ports = plugin.get_ports(ctx, filters=filters)
        for port in ports:
            seg_id = plugin._get_network_nsx_segment_id(
                ctx, port['network_id'])
            nsxpolicy.segment_port.set_admin_state(seg_id, port['id'], False)


@admin_utils.output_header
@admin_utils.unpack_payload
def update_metadata(resource, event, trigger, **kwargs):
    """
    Update the metadata proxy configuration of segments
    """
    errmsg = ("Need to specify metadata proxy ID and availability-zone. "
              "Add --property metadata-proxy=<id> --property az=<name>")
    if not kwargs.get('property'):
        LOG.error("%s", errmsg)
        return
    properties = admin_utils.parse_multi_keyval_opt(kwargs['property'])
    metaproxy = properties.get('metadata-proxy')
    az = properties.get('az')
    if not metaproxy or not az:
        LOG.error("%s", errmsg)
        raise SystemExit(errmsg)
    nsxpolicy = p_utils.get_connected_nsxpolicy()
    try:
        nsxpolicy.md_proxy.get(metaproxy)
    except Exception as e:
        LOG.error("Error while retrieving NSX metadata proxy %s: %s",
                  metaproxy, e)
        raise SystemExit(e)
    ctx = context.get_admin_context()
    with p_utils.NsxPolicyPluginWrapper() as plugin:
        nets = plugin.get_networks(ctx)
        for net in nets:
            if plugin._network_is_external(ctx, net['id']):
                continue
            network_az = plugin.get_network_az_by_net_id(ctx, net['id'])
            if az == network_az.name:
                seg_id = plugin._get_network_nsx_segment_id(ctx, net['id'])
                try:
                    nsxpolicy.segment.update(seg_id,
                                             metadata_proxy_id=metaproxy)
                except Exception as e:
                    LOG.error("Failed to update segment %s metadata proxy"
                              " configuration: %s",
                              seg_id, e)
                    raise SystemExit(e)
                else:
                    LOG.info("Updated segment %s to metadata proxy %s",
                             seg_id, metaproxy)
        LOG.info("Successfully updated all the networks' metadata proxy"
                 " configuration.")


@admin_utils.output_header
@admin_utils.unpack_payload
def update_dhcp_profile_edge(resource, event, trigger, **kwargs):
    """
    Bind the specified dhcp profile to the edge clusters of tier0 GW
    """
    errmsg = ("Need to specify dhcp profile ID and tier0 GW ID. Add "
              "--property dhcp-profile=<id> --property tier0=<id>")
    if not kwargs.get('property'):
        LOG.error("%s", errmsg)
        return
    properties = admin_utils.parse_multi_keyval_opt(kwargs['property'])
    dhcp_profile = properties.get('dhcp-profile')
    tier0 = properties.get('tier0')
    if not dhcp_profile or not tier0:
        LOG.error("%s", errmsg)
        raise SystemExit(errmsg)
    nsxpolicy = p_utils.get_connected_nsxpolicy()
    try:
        nsxpolicy.tier0.get(tier0)
    except Exception as e:
        LOG.error("Tier0 logical router %s was not found: %s", tier0, e)
        raise SystemExit(e)
    edge_path = nsxpolicy.tier0.get_edge_cluster_path(tier0)
    if edge_path:
        try:
            nsxpolicy.dhcp_server_config.update(dhcp_profile,
                                                edge_cluster_path=edge_path)
        except Exception as e:
            LOG.error("Failed to bind dhcp profile %s to edge cluster %s: %s",
                      dhcp_profile, edge_path, e)
            raise SystemExit(e)
        else:
            LOG.info("Successfully updated dhcp profile %s to edge cluster %s",
                     dhcp_profile, edge_path)
    else:
        LOG.error("Tier0 logical router %s miss the edge clusters binding."
                  "Skip the dhcp profile update action", tier0)


registry.subscribe(update_admin_state,
                   constants.NETWORKS,
                   shell.Operations.NSX_UPDATE_STATE.value)

registry.subscribe(migrate_dhcp_to_policy,
                   constants.DHCP_BINDING,
                   shell.Operations.MIGRATE_TO_POLICY.value)

registry.subscribe(update_metadata,
                   constants.NETWORKS,
                   shell.Operations.UPDATE_METADATA.value)

registry.subscribe(update_dhcp_profile_edge,
                   constants.DHCP_BINDING,
                   shell.Operations.UPDATE_DHCP_EDGE.value)
