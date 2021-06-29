# Copyright 2017 VMware, Inc.
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


from neutron_lib import exceptions as n_exc
from oslo_log import log as logging
from oslo_utils import excutils

from vmware_nsx._i18n import _
from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.db import db as nsx_db
from vmware_nsx.services.lbaas import base_mgr
from vmware_nsx.services.lbaas import lb_const
from vmware_nsx.services.lbaas.nsx_v3.implementation import lb_utils
from vmware_nsx.services.lbaas.octavia import constants as oct_const
from vmware_nsxlib.v3 import exceptions as nsxlib_exc
from vmware_nsxlib.v3 import utils

LOG = logging.getLogger(__name__)


class EdgeLoadBalancerManagerFromDict(base_mgr.Nsxv3LoadbalancerBaseManager):

    def create(self, context, lb, completor):
        if not lb_utils.validate_lb_subnet(context, self.core_plugin,
                                           lb['vip_subnet_id']):
            completor(success=False)
            msg = (_('Cannot create lb on subnet %(sub)s for '
                     'loadbalancer %(lb)s. The subnet needs to connect a '
                     'router which is already set gateway.') %
                   {'sub': lb['vip_subnet_id'], 'lb': lb['id']})
            raise n_exc.BadRequest(resource='lbaas-subnet', msg=msg)

        service_client = self.core_plugin.nsxlib.load_balancer.service
        nsx_router_id = None
        lb_service = None
        nsx_router_id = lb_utils.NO_ROUTER_ID
        router_id = lb_utils.get_router_from_network(
            context, self.core_plugin, lb['vip_subnet_id'])
        if router_id:
            nsx_router_id = nsx_db.get_nsx_router_id(context.session,
                                                     router_id)
            lb_service = service_client.get_router_lb_service(nsx_router_id)
        if not lb_service:
            lb_size = lb_utils.get_lb_flavor_size(
                self.flavor_plugin, context, lb.get('flavor_id'), None)
            if router_id:
                # Make sure the NSX service router exists
                e_ctx = context.elevated()
                if not self.core_plugin.service_router_has_services(
                        e_ctx, router_id):
                    self.core_plugin.create_service_router(e_ctx, router_id)
                lb_service = self._create_lb_service(
                    e_ctx, service_client, lb['tenant_id'],
                    router_id, nsx_router_id, lb['id'], lb_size)
            else:
                lb_service = self._create_lb_service_without_router(
                    context, service_client, lb['tenant_id'],
                    lb, lb_size)
            if not lb_service:
                completor(success=False)
                msg = (_('Failed to create lb service for loadbalancer '
                         '%s') % lb['id'])
                raise nsx_exc.NsxPluginException(err_msg=msg)

        nsx_db.add_nsx_lbaas_loadbalancer_binding(
            context.session, lb['id'], lb_service['id'],
            nsx_router_id, lb['vip_address'])

        # Make sure the vip port is marked with a device owner
        port = self.core_plugin.get_port(
            context.elevated(), lb['vip_port_id'])
        if not port.get('device_owner'):
            self.core_plugin.update_port(
                context.elevated(), lb['vip_port_id'],
                {'port': {'device_id': oct_const.DEVICE_ID_PREFIX + lb['id'],
                          'device_owner': lb_const.VMWARE_LB_VIP_OWNER}})

        completor(success=True)

    def _create_lb_service(self, context, service_client, tenant_id,
                           router_id, nsx_router_id, lb_id, lb_size):
        """Create NSX LB service for a specific neutron router"""
        router = self.core_plugin.get_router(context, router_id)
        if not router.get('external_gateway_info'):
            msg = (_('Tenant router %(router)s does not connect to '
                     'external gateway') % {'router': router['id']})
            raise n_exc.BadRequest(resource='lbaas-lbservice-create',
                                   msg=msg)
        lb_name = utils.get_name_and_uuid(router['name'] or 'router',
                                          router_id)
        tags = lb_utils.get_tags(self.core_plugin, router_id,
                                 lb_const.LR_ROUTER_TYPE,
                                 tenant_id, context.project_name)
        attachment = {'target_id': nsx_router_id,
                      'target_type': 'LogicalRouter'}
        try:
            lb_service = service_client.create(display_name=lb_name,
                                               tags=tags,
                                               attachment=attachment,
                                               size=lb_size)
        except nsxlib_exc.ManagerError as e:
            # If it failed, it is probably because the service was already
            # created by another loadbalancer simultaneously
            lb_service = service_client.get_router_lb_service(nsx_router_id)
            if lb_service:
                return lb_service
            LOG.error("Failed to create LB service: %s", e)
            return

        # Add rule to advertise external vips
        lb_utils.update_router_lb_vip_advertisement(
            context, self.core_plugin, router, nsx_router_id)

        return lb_service

    def _create_lb_service_without_router(self, context, service_client,
                                          tenant_id, lb, lb_size):
        """Create NSX LB service for an external VIP
        This service will not be attached to a router yet, and it will be
        updated once the first member is created.
        """
        lb_id = lb['id']
        lb_name = utils.get_name_and_uuid(lb['name'] or 'loadbalancer',
                                          lb_id)
        tags = lb_utils.get_tags(self.core_plugin, '',
                                 lb_const.LR_ROUTER_TYPE,
                                 tenant_id, context.project_name)
        try:
            lb_service = service_client.create(display_name=lb_name,
                                               tags=tags,
                                               size=lb_size)
        except nsxlib_exc.ManagerError as e:
            LOG.error("Failed to create LB service: %s", e)
            return

        return lb_service

    def update(self, context, old_lb, new_lb, completor):
        vs_client = self.core_plugin.nsxlib.load_balancer.virtual_server
        app_client = self.core_plugin.nsxlib.load_balancer.application_profile
        if new_lb['name'] != old_lb['name']:
            for listener in new_lb['listeners']:
                binding = nsx_db.get_nsx_lbaas_listener_binding(
                    context.session, new_lb['id'], listener['id'])
                if binding:
                    vs_id = binding['lb_vs_id']
                    app_profile_id = binding['app_profile_id']
                    new_lb_name = new_lb['name'][:utils.MAX_TAG_LEN]
                    try:
                        # Update tag on virtual server with new lb name
                        vs = vs_client.get(vs_id)
                        updated_tags = utils.update_v3_tags(
                            vs['tags'], [{'scope': lb_const.LB_LB_NAME,
                                          'tag': new_lb_name}])
                        vs_client.update(vs_id, tags=updated_tags)
                        # Update tag on application profile with new lb name
                        app_profile = app_client.get(app_profile_id)
                        app_client.update(
                            app_profile_id, tags=updated_tags,
                            resource_type=app_profile['resource_type'])

                    except nsxlib_exc.ManagerError:
                        with excutils.save_and_reraise_exception():
                            completor(success=False)
                            LOG.error('Failed to update tag %(tag)s for lb '
                                      '%(lb)s', {'tag': updated_tags,
                                                 'lb': new_lb['name']})

        completor(success=True)

    def delete(self, context, lb, completor):
        service_client = self.core_plugin.nsxlib.load_balancer.service
        router_client = self.core_plugin.nsxlib.logical_router
        lb_binding = nsx_db.get_nsx_lbaas_loadbalancer_binding(
            context.session, lb['id'])
        if lb_binding:
            lb_service_id = lb_binding['lb_service_id']
            nsx_router_id = lb_binding['lb_router_id']
            try:
                lb_service = service_client.get(lb_service_id)
            except nsxlib_exc.ManagerError:
                LOG.warning("LB service %(lbs)s is not found",
                            {'lbs': lb_service_id})
            else:
                vs_list = lb_service.get('virtual_server_ids')
                if not vs_list:
                    try:
                        service_client.delete(lb_service_id)
                        # If there is no lb service attached to the router,
                        # delete the router advertise_lb_vip rule.
                        if nsx_router_id != lb_utils.NO_ROUTER_ID:
                            router_client.update_advertisement_rules(
                                nsx_router_id, [],
                                name_prefix=lb_utils.ADV_RULE_NAME)
                    except nsxlib_exc.ManagerError:
                        completor(success=False)
                        msg = (_('Failed to delete lb service %(lbs)s from nsx'
                                 ) % {'lbs': lb_service_id})
                        raise n_exc.BadRequest(resource='lbaas-lb', msg=msg)
            nsx_db.delete_nsx_lbaas_loadbalancer_binding(
                context.session, lb['id'])
            if nsx_router_id != lb_utils.NO_ROUTER_ID:
                router_id = nsx_db.get_neutron_from_nsx_router_id(
                    context.session, nsx_router_id)
                # Service router is needed only when the LB exist, and
                # no other services are using it.
                if not self.core_plugin.service_router_has_services(
                        context,
                        router_id):
                    self.core_plugin.delete_service_router(context,
                                                           router_id)
        # Make sure the vip port is not marked with a vmware device owner
        try:
            port = self.core_plugin.get_port(
                context.elevated(), lb['vip_port_id'])
            if port.get('device_owner') == lb_const.VMWARE_LB_VIP_OWNER:
                self.core_plugin.update_port(
                    context.elevated(), lb['vip_port_id'],
                    {'port': {'device_id': '',
                              'device_owner': ''}})
        except n_exc.PortNotFound:
            # Only log the error and continue anyway
            LOG.warning("VIP port %s not found while deleting loadbalancer %s",
                        lb['vip_port_id'], lb['id'])
        except Exception as e:
            # Just log the error as all other resources were deleted
            LOG.error("Failed to update neutron port %s devices upon "
                      "loadbalancer deletion: %s", lb['vip_port_id'], e)

        completor(success=True)

    def delete_cascade(self, context, lb, completor):
        """Delete all backend and DB resources of this loadbalancer"""
        self.delete(context, lb, completor)

    def get_supported_flavor_metadata(self):
        return None

    def validate_flavor(self, flavor_metadata):
        return None

    def get_supported_availability_zone_metadata(self):
        return None

    def validate_availability_zone(self, availability_zone_metadata):
        return None
