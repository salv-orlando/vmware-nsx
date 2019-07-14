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

from neutron.db import db_base_plugin_v2
from neutron.db import l3_db
from neutron_lib.callbacks import registry
from neutron_lib import context
from oslo_log import log as logging

from vmware_nsx.db import nsx_models
from vmware_nsx.shell.admin.plugins.common import constants
from vmware_nsx.shell.admin.plugins.common import utils as admin_utils
from vmware_nsx.shell.admin.plugins.nsxp.resources import utils as p_utils
from vmware_nsx.shell import resources as shell

LOG = logging.getLogger(__name__)


class RoutersPlugin(db_base_plugin_v2.NeutronDbPluginV2,
                    l3_db.L3_NAT_db_mixin):
    pass


@admin_utils.list_handler(constants.ROUTERS)
@admin_utils.output_header
def list_routers(resource, event, trigger, **kwargs):
    """List neutron routers

    With the NSX policy resources and realization state.
    """
    mappings = []
    nsxpolicy = p_utils.get_connected_nsxpolicy()
    ctx = context.get_admin_context()
    with p_utils.NsxPolicyPluginWrapper() as plugin:
        routers = plugin.get_routers(ctx, fields=['id', 'name', 'tenant_id'])
        for rtr in routers:
            status = p_utils.get_realization_info(
                nsxpolicy.tier1, rtr['id'])
            mappings.append({'ID': rtr['id'],
                             'Name': rtr.get('name'),
                             'Project': rtr.get('tenant_id'),
                             'NSX status': status})
    p_utils.log_info(constants.ROUTERS,
                     mappings,
                     attrs=['Project', 'Name', 'ID', 'NSX status'])
    return bool(mappings)


@admin_utils.output_header
def update_tier0(resource, event, trigger, **kwargs):
    """Replace old tier0 with a new one on the neutron DB and NSX backend"""
    errmsg = ("Need to specify old and new tier0 ID. Add --property "
              "old-tier0=<id> --property new-tier0=<id>")
    if not kwargs.get('property'):
        LOG.error("%s", errmsg)
        return
    properties = admin_utils.parse_multi_keyval_opt(kwargs['property'])
    old_tier0 = properties.get('old-tier0')
    new_tier0 = properties.get('new-tier0')
    if not old_tier0 or not new_tier0:
        LOG.error("%s", errmsg)
        return
    # Verify the id of the new tier0 (old one might not exist any more)
    nsxpolicy = p_utils.get_connected_nsxpolicy()
    try:
        nsxpolicy.tier0.get(new_tier0)
    except Exception:
        LOG.error("Tier0 logical router %s was not found", new_tier0)
        return

    # update all neutron DB entries
    old_tier0_networks = []
    ctx = context.get_admin_context()
    with ctx.session.begin(subtransactions=True):
        bindings = ctx.session.query(
            nsx_models.TzNetworkBinding).filter_by(phy_uuid=old_tier0).all()
        for bind in bindings:
            old_tier0_networks.append(bind.network_id)
            bind.phy_uuid = new_tier0

    if not old_tier0_networks:
        LOG.info("Did not find any provider networks using tier0 %s",
                 old_tier0)
        return

    LOG.info("Updated provider networks in DB: %s", old_tier0_networks)

    # Update tier1 routers GW to point to the new tier0 in the backend
    plugin = RoutersPlugin()
    neutron_routers = plugin.get_routers(ctx)
    for router in neutron_routers:
        router_gw_net = (router.get('external_gateway_info') and
                         router['external_gateway_info'].get('network_id'))
        if router_gw_net and router_gw_net in old_tier0_networks:
            try:
                nsxpolicy.tier1.update(router['id'], tier0=new_tier0)
            except Exception as e:
                LOG.error("Failed to update router %s linked port: %s",
                          router['id'], e)
            else:
                LOG.info("Updated router %s uplink port", router['id'])

    LOG.info("Done.")


registry.subscribe(update_tier0,
                   constants.ROUTERS,
                   shell.Operations.UPDATE_TIER0.value)
