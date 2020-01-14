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
import vmware_nsx.shell.resources as shell
from vmware_nsxlib.v3 import nsx_constants

LOG = logging.getLogger(__name__)


@admin_utils.list_handler(constants.NETWORKS)
@admin_utils.output_header
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


registry.subscribe(update_admin_state,
                   constants.NETWORKS,
                   shell.Operations.NSX_UPDATE_STATE.value)
