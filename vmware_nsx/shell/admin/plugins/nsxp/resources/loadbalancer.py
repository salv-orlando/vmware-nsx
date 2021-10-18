# Copyright 2020 VMware, Inc.  All rights reserved.
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
from neutron_lib import exceptions as n_exc
from oslo_log import log as logging

from vmware_nsx.services.lbaas.nsx_p.implementation import lb_utils
from vmware_nsx.services.lbaas.octavia import octavia_listener
from vmware_nsx.shell.admin.plugins.common import constants
from vmware_nsx.shell.admin.plugins.common import utils as admin_utils
from vmware_nsx.shell.admin.plugins.nsxp.resources import utils as p_utils
from vmware_nsx.shell import resources as shell

LOG = logging.getLogger(__name__)


@admin_utils.output_header
def update_lb_service_tags(resource, event, trigger, **kwargs):
    """Update the LB id tag on existing LB services"""
    nsxpolicy = p_utils.get_connected_nsxpolicy()
    service_client = nsxpolicy.load_balancer.lb_service
    services = service_client.list()
    n_updated = 0
    for lb_service in services:
        # First make sure it i a neutron service
        is_neutron = False
        for tag in lb_service.get('tags', []):
            if tag['scope'] == 'os-api-version':
                is_neutron = True
                break
        if is_neutron:
            # Add a tag with the id of this resource as the first Lb
            # creates the service with its id
            try:
                service_client.update_customized(
                    lb_service['id'],
                    lb_utils.add_service_tag_callback(lb_service['id'],
                                                      only_first=True))
            except n_exc.BadRequest:
                LOG.warning("Lb service %s already has a loadbalancer tag",
                            lb_service['id'])
            else:
                n_updated = n_updated + 1

    LOG.info("Done updating %s Lb services.", n_updated)


def _orphaned_loadbalancer_handler(handler_callback):
    # Retrieve Octavia loadbalancers
    client = octavia_listener.get_octavia_rpc_client()
    o_endpoint = octavia_listener.NSXOctaviaListenerEndpoint(client=client)
    octavia_lb_ids = o_endpoint.get_active_loadbalancers()

    # Retrieve NSX list of LB services
    nsxpolicy = p_utils.get_connected_nsxpolicy()
    service_client = nsxpolicy.load_balancer.lb_service
    services = service_client.list()

    for lb_service in services:
        is_orphan = True
        for tag in lb_service.get('tags', []):
            if (tag['scope'] == 'loadbalancer_id' and
                    tag['tag'] in octavia_lb_ids):
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
        nsxpolicy = p_utils.get_connected_nsxpolicy()
        nsxp_lb = nsxpolicy.load_balancer
        service_client = nsxp_lb.lb_service

        # Cleanup virtual servers
        vs_client = nsxp_lb.virtual_server
        vs_list = vs_client.list()
        for vs in vs_list:
            if (vs.get('lb_service_path') and
                    vs['lb_service_path'] == lb_service.get('path')):
                try:
                    vs_client.delete(vs['id'])
                except Exception as e:
                    LOG.error('Failed to delete virtual server %s from NSX '
                              'loadbalancer service %s with exception (%s)',
                              vs['id'], lb_service['id'], e)

        # Detach LB service from router
        try:
            service_client.update(lb_service['id'], connectivity_path=None)
        except Exception as e:
            LOG.error('Failed to clean up NSX loadbalancer service %s with '
                      'exception (%s)', lb_service['id'], e)

        # Delete LB service
        try:
            service_client.delete(lb_service['id'])
            LOG.info('Cleaned up NSX loadbalancer service %s from router',
                     lb_service['id'])
        except Exception as e:
            LOG.error('Failed to clean up NSX loadbalancer service %s with '
                      'exception (%s)', lb_service['id'], e)

    _orphaned_loadbalancer_handler(_orphan_handler)


registry.subscribe(update_lb_service_tags,
                   constants.LB_SERVICES,
                   shell.Operations.NSX_UPDATE_TAGS.value)

registry.subscribe(list_orphaned_loadbalancers,
                   constants.LB_SERVICES,
                   shell.Operations.LIST_ORPHANED.value)

registry.subscribe(clean_orphaned_loadbalancers,
                   constants.LB_SERVICES,
                   shell.Operations.CLEAN_ORPHANED.value)
