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
from oslo_config import cfg
from oslo_log import log as logging

from vmware_nsx.db import nsx_models
from vmware_nsx.shell.admin.plugins.common import constants
from vmware_nsx.shell.admin.plugins.common import utils as admin_utils
from vmware_nsx.shell.admin.plugins.nsxp.resources import utils as p_utils
from vmware_nsx.shell import resources as shell

from vmware_nsxlib.v3 import nsx_constants
from vmware_nsxlib.v3.policy import constants as policy_constants
from vmware_nsxlib.v3.policy import transaction as policy_trans

LOG = logging.getLogger(__name__)


class RoutersPlugin(db_base_plugin_v2.NeutronDbPluginV2,
                    l3_db.L3_NAT_db_mixin):
    pass


@admin_utils.list_handler(constants.ROUTERS)
@admin_utils.output_header
@admin_utils.unpack_payload
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
@admin_utils.unpack_payload
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


@admin_utils.output_header
@admin_utils.unpack_payload
def recover_tier0(resource, event, trigger, **kwargs):
    """
    Reconfigure the tier1 routers with tier0 GW at NSX backend and update the
    neutron external network's physical network binding
    """
    errmsg = ("Need to specify tier0 ID and availability-zone. "
              "Add --property tier0=<id> --property az=<name>")
    if not kwargs.get('property'):
        LOG.error("%s", errmsg)
        return
    properties = admin_utils.parse_multi_keyval_opt(kwargs['property'])
    tier0 = properties.get('tier0')
    az = properties.get('az')
    if not tier0 or not az:
        LOG.error("%s", errmsg)
        raise SystemExit(errmsg)
    # Verify the id of the tier0
    nsxpolicy = p_utils.get_connected_nsxpolicy()
    try:
        nsxpolicy.tier0.get(tier0)
    except Exception as e:
        LOG.error("An error occurred while retrieving Tier0 gw router %s: %s",
                  tier0, e)
        raise SystemExit(e)
    tier0_edge_cluster = nsxpolicy.tier0.get_edge_cluster_path(tier0)
    if not tier0_edge_cluster:
        LOG.error("Tier0 gw router %s does not have an edge cluster "
                  "configured", tier0)
        return
    ctx = context.get_admin_context()
    plugin = RoutersPlugin()
    neutron_routers = plugin.get_routers(ctx)
    if not neutron_routers:
        LOG.info("There are not any neutron routers found")
    with p_utils.NsxPolicyPluginWrapper() as core_plugin:
        for router in neutron_routers:
            router_obj = core_plugin._get_router(ctx, router['id'])
            router_az = core_plugin._get_router_az_obj(router_obj)
            if router_obj.gw_port_id and az == router_az.name:
                old_tier0_path = nsxpolicy.tier1.get(router['id']).\
                    get('tier0_path')
                if old_tier0_path:
                    old_tier0_edge_cluster_path = nsxpolicy.tier0.\
                        get_edge_cluster_path(old_tier0_path.split('/')[-1])
                # Update tier1 routers GW to point to the tier0 in the backend
                try:
                    nsxpolicy.tier1.update(router['id'], tier0=tier0)
                except Exception as e:
                    LOG.error("Failed to update T0 uplink for router %s: %s",
                              router['id'], e)
                    raise SystemExit(e)
                else:
                    LOG.info("Updated router %s uplink port", router['id'])
                # Update tier1 routers' edge cluster information to new
                # tier0's edge cluster only if the tier1 router's old edge
                # cluster bind to the same edge cluster of old tier0 router
                old_tier1_edge_cluster_path = nsxpolicy.tier1.\
                    get_edge_cluster_path(router['id'])
                if old_tier1_edge_cluster_path and \
                        (old_tier1_edge_cluster_path ==
                         old_tier0_edge_cluster_path):
                    try:
                        nsxpolicy.tier1.\
                            set_edge_cluster_path(router['id'],
                                                  tier0_edge_cluster)
                    except Exception as e:
                        LOG.error("Failed to update router %s edge cluster:"
                                  " %s", router['id'], e)
                        raise SystemExit(e)
                    else:
                        LOG.info("Updated router %s edge cluster",
                                 router['id'])

        # Update Neutron external network's physical network binding
        nets = core_plugin.get_networks(ctx)
        for net in nets:
            network_az = core_plugin.get_network_az_by_net_id(ctx, net['id'])
            if az == network_az.name and net.get('router:external'):
                with ctx.session.begin(subtransactions=True):
                    bindings = ctx.session.query(nsx_models.TzNetworkBinding).\
                        filter_by(network_id=net['id']).first()
                    bindings.phy_uuid = tier0
                    LOG.info("Updated neutron external network %s binding "
                             "physical network", net['id'])
    LOG.info("Successfully updated all the tier0 GW binding information.")


@admin_utils.output_header
@admin_utils.unpack_payload
def update_nat_firewall_match(resource, event, trigger, **kwargs):
    """Update the firewall_match value in neutron nat rules with a new value"""
    errmsg = ("Need to specify internal/external firewall_match value. "
              "Add --property firewall-match=<match>")
    if not kwargs.get('property'):
        LOG.error("%s", errmsg)
        return
    properties = admin_utils.parse_multi_keyval_opt(kwargs['property'])
    firewall_match_str = properties.get('firewall-match')
    if (not firewall_match_str or
            firewall_match_str.lower() not in ('internal', 'external')):
        LOG.error("%s", errmsg)
        return

    if firewall_match_str.lower() == 'internal':
        new_firewall_match = policy_constants.NAT_FIREWALL_MATCH_INTERNAL
        old_firewall_match = policy_constants.NAT_FIREWALL_MATCH_EXTERNAL
        conf_match_internal = True
    else:
        new_firewall_match = policy_constants.NAT_FIREWALL_MATCH_EXTERNAL
        old_firewall_match = policy_constants.NAT_FIREWALL_MATCH_INTERNAL
        conf_match_internal = False

    cfg.CONF.set_override('firewall_match_internal_addr',
                          conf_match_internal, 'nsx_p')

    nsxpolicy = p_utils.get_connected_nsxpolicy()
    with p_utils.NsxPolicyPluginWrapper() as plugin:
        # Make sure FWaaS was initialized
        plugin.init_fwaas_for_admin_utils()

        ctx = context.get_admin_context()
        neutron_routers = plugin.get_routers(ctx)
        for router in neutron_routers:
            rules = nsxpolicy.tier1_nat_rule.list(router['id'])
            for rule in rules:
                if not nsxpolicy.feature_supported(
                    nsx_constants.FEATURE_PARTIAL_UPDATES):
                    if rule.get('firewall_match') == old_firewall_match:
                        nsxpolicy.tier1_nat_rule.update(
                            router['id'], rule['id'],
                            firewall_match=new_firewall_match)
                else:
                    with policy_trans.NsxPolicyTransaction():
                        if rule.get('firewall_match') == old_firewall_match:
                            nsxpolicy.tier1_nat_rule.update(
                                router['id'], rule['id'],
                                firewall_match=new_firewall_match)

            if plugin.fwaas_callbacks:
                # get all router interface networks
                interface_ports = plugin._get_router_interfaces(
                    ctx, router['id'])
                for port in interface_ports:
                    plugin.fwaas_callbacks.update_segment_group(
                        ctx, router['id'], port['network_id'])

    LOG.info("Done.")


registry.subscribe(update_tier0,
                   constants.ROUTERS,
                   shell.Operations.UPDATE_TIER0.value)

registry.subscribe(recover_tier0,
                   constants.ROUTERS,
                   shell.Operations.RECOVER_TIER0.value)

registry.subscribe(update_nat_firewall_match,
                   constants.ROUTERS,
                   shell.Operations.UPDATE_FIREWALL_MATCH.value)
