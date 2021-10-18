# Copyright 2015 VMware, Inc.  All rights reserved.
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

from oslo_log import log as logging

from neutron_lib.callbacks import registry
from neutron_lib import context as neutron_context

from vmware_nsx.db import db as nsx_db
from vmware_nsx.services.lbaas.nsx_v3.implementation import lb_utils
from vmware_nsx.services.lbaas.octavia import octavia_listener
from vmware_nsx.shell.admin.plugins.common import constants
from vmware_nsx.shell.admin.plugins.common import formatters
from vmware_nsx.shell.admin.plugins.common import utils as admin_utils
from vmware_nsx.shell.admin.plugins.nsxv3.resources import utils
from vmware_nsx.shell import resources as shell

LOG = logging.getLogger(__name__)


@admin_utils.list_handler(constants.LB_SERVICES)
@admin_utils.output_header
def nsx_list_lb_services(resource, event, trigger, **kwargs):
    """List LB services on NSX backend"""

    nsxlib = utils.get_connected_nsxlib()
    lb_services = nsxlib.load_balancer.service.list()
    LOG.info(formatters.output_formatter(
        constants.LB_SERVICES, lb_services['results'],
        ['display_name', 'id', 'virtual_server_ids', 'attachment']))
    return bool(lb_services)


@admin_utils.list_handler(constants.LB_VIRTUAL_SERVERS)
@admin_utils.output_header
def nsx_list_lb_virtual_servers(resource, event, trigger, **kwargs):
    """List LB virtual servers on NSX backend"""

    nsxlib = utils.get_connected_nsxlib()
    lb_virtual_servers = nsxlib.load_balancer.virtual_server.list()
    LOG.info(formatters.output_formatter(
        constants.LB_VIRTUAL_SERVERS, lb_virtual_servers['results'],
        ['display_name', 'id', 'ip_address', 'pool_id']))
    return bool(lb_virtual_servers)


@admin_utils.list_handler(constants.LB_POOLS)
@admin_utils.output_header
def nsx_list_lb_pools(resource, event, trigger, **kwargs):

    nsxlib = utils.get_connected_nsxlib()
    lb_pools = nsxlib.load_balancer.pool.list()
    LOG.info(formatters.output_formatter(
        constants.LB_POOLS, lb_pools['results'],
        ['display_name', 'id', 'active_monitor_ids', 'members']))
    return bool(lb_pools)


@admin_utils.list_handler(constants.LB_MONITORS)
@admin_utils.output_header
def nsx_list_lb_monitors(resource, event, trigger, **kwargs):

    nsxlib = utils.get_connected_nsxlib()
    lb_monitors = nsxlib.load_balancer.monitor.list()
    LOG.info(formatters.output_formatter(
        constants.LB_MONITORS, lb_monitors['results'],
        ['display_name', 'id', 'resource_type']))
    return bool(lb_monitors)


@admin_utils.output_header
def nsx_update_router_lb_advertisement(resource, event, trigger, **kwargs):
    """The implementation of the VIP advertisement changed.

    This utility will update existing LB/routers
    """
    nsxlib = utils.get_connected_nsxlib()
    # Get the list of neutron routers used by LB
    lb_services = nsxlib.load_balancer.service.list()['results']
    lb_routers = []
    for lb_srv in lb_services:
        for tag in lb_srv.get('tags', []):
            if tag['scope'] == 'os-neutron-router-id':
                lb_routers.append(tag['tag'])
    lb_routers = set(lb_routers)
    LOG.info("Going to update LB advertisement on %(num)s router(s): "
             "%(routers)s",
             {'num': len(lb_routers), 'routers': lb_routers})

    context = neutron_context.get_admin_context()
    with utils.NsxV3PluginWrapper() as plugin:
        for rtr_id in lb_routers:
            nsx_router_id = nsx_db.get_nsx_router_id(context.session, rtr_id)
            if not nsx_router_id:
                LOG.error("Router %s NSX Id was not found.", rtr_id)
                continue
            try:
                # disable the global vip advertisement flag
                plugin.nsxlib.logical_router.update_advertisement(
                    nsx_router_id, advertise_lb_vip=False)
                # Add an advertisement rule for the external network
                router = plugin.get_router(context, rtr_id)
                lb_utils.update_router_lb_vip_advertisement(
                    context, plugin, router, nsx_router_id)
            except Exception as e:
                LOG.error("Failed updating router %(id)s: %(e)s",
                          {'id': rtr_id, 'e': e})

    LOG.info("Done.")


def _orphaned_loadbalancer_handler(handler_callback):
    # Retrieve Octavia loadbalancers
    client = octavia_listener.get_octavia_rpc_client()
    o_endpoint = octavia_listener.NSXOctaviaListenerEndpoint(client=client)
    octavia_lb_ids = o_endpoint.get_active_loadbalancers()

    nsxlib = utils.get_connected_nsxlib()
    nsxlib_lb = nsxlib.load_balancer
    lb_services = nsxlib_lb.service.list()
    vs_client = nsxlib_lb.virtual_server

    for lb_service in lb_services.get('results', []):
        is_orphan = True
        for vs_id in lb_service.get('virtual_server_ids', []):
            vs = vs_client.get(vs_id)
            for tag in vs.get('tags', []):
                if tag['scope'] == 'os-lbaas-lb-id':
                    lb_id = tag['tag']

                    if lb_id in octavia_lb_ids:
                        is_orphan = False
                        break
        if is_orphan:
            handler_callback(lb_service)


@admin_utils.output_header
def list_orphaned_loadbalancers(resource, event, trigger, **kwargs):
    def _orphan_handler(lb_service):
        LOG.warning('NSX loadbalancer service %s has no valid Octavia '
                    'loadbalancers', lb_service['id'])

    _orphaned_loadbalancer_handler(_orphan_handler)


@admin_utils.output_header
def clean_orphaned_loadbalancers(resource, event, trigger, **kwargs):
    def _orphan_handler(lb_service):
        nsxlib = utils.get_connected_nsxlib()
        nsxlib_lb = nsxlib.load_balancer
        if lb_service.get('attachment'):
            try:
                nsxlib_lb.service.update(lb_service['id'], attachment=None)
            except Exception as e:
                LOG.error('Failed to detach NSX loadbalancer service %s with '
                          'error %s', lb_service['id'], e)

        try:
            nsxlib_lb.service.delete(lb_service['id'])
            LOG.info('Cleaned up NSX loadbalancer service %s',
                     lb_service['id'])
        except Exception as e:
            LOG.error('Failed to cleanup NSX loadbalancer service %s with '
                      'error %s', lb_service['id'], e)

    _orphaned_loadbalancer_handler(_orphan_handler)


registry.subscribe(nsx_update_router_lb_advertisement,
                   constants.LB_ADVERTISEMENT,
                   shell.Operations.NSX_UPDATE.value)


registry.subscribe(list_orphaned_loadbalancers,
                   constants.LB_SERVICES,
                   shell.Operations.LIST_ORPHANED.value)

registry.subscribe(clean_orphaned_loadbalancers,
                   constants.LB_SERVICES,
                   shell.Operations.CLEAN_ORPHANED.value)
