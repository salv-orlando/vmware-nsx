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


registry.subscribe(update_lb_service_tags,
                   constants.LB_SERVICES,
                   shell.Operations.NSX_UPDATE_TAGS.value)
