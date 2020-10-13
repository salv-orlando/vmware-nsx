# Copyright 2018 VMware, Inc.
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
from vmware_nsx.services.lbaas import base_mgr
from vmware_nsx.services.lbaas import lb_const
from vmware_nsx.services.lbaas.nsx_p.implementation import lb_utils as p_utils
from vmware_nsx.services.lbaas.nsx_v3.implementation import lb_utils
from vmware_nsx.services.lbaas.octavia import constants as oct_const
from vmware_nsxlib.v3 import exceptions as nsxlib_exc
from vmware_nsxlib.v3.policy import utils as lib_p_utils

LOG = logging.getLogger(__name__)


class EdgeLoadBalancerManagerFromDict(base_mgr.NsxpLoadbalancerBaseManager):

    def _get_lb_router(self, context, lb):
        router_id = lb_utils.get_router_from_network(
            context, self.core_plugin, lb['vip_subnet_id'])

        return router_id

    def create(self, context, lb, completor):
        lb_id = lb['id']

        network = lb_utils.get_network_from_subnet(
            context, self.core_plugin, lb['vip_subnet_id'])
        router_id = self._get_lb_router(context, lb)
        if not router_id and network and not network.get('router:external'):
            completor(success=False)
            msg = (_('Cannot create a loadbalancer %(lb_id)s on subnet. '
                     '%(subnet)s is neither public nor connected to the LB '
                     'router') %
                   {'lb_id': lb_id, 'subnet': lb['vip_subnet_id']})
            raise n_exc.BadRequest(resource='lbaas-subnet', msg=msg)
        service_client = self.core_plugin.nsxpolicy.load_balancer.lb_service
        lb_service = None
        if router_id:
            # Check if a service was already created for this router
            lb_service = p_utils.get_router_nsx_lb_service(
                self.core_plugin.nsxpolicy, router_id)

            if lb_service:
                # Add the new LB to the service by adding the tag.
                # At the same time verify maximum number of tags
                try:
                    with p_utils.get_lb_rtr_lock(router_id):
                        service_client.update_customized(
                            lb_service['id'],
                            p_utils.add_service_tag_callback(lb['id']))
                except n_exc.BadRequest:
                    # This will fail if there are too many loadbalancers
                    completor(success=False)
                    msg = (_('Cannot create a loadbalancer %(lb_id)s on '
                             'router %(router)s, as it already has too many '
                             'loadbalancers') %
                           {'lb_id': lb_id, 'router': router_id})
                    raise n_exc.BadRequest(resource='lbaas-router', msg=msg)
                except Exception as e:
                    with excutils.save_and_reraise_exception():
                        completor(success=False)
                        LOG.error('Failed to create loadbalancer %(lb)s for '
                                  'lb with exception %(e)s',
                                  {'lb': lb['id'], 'e': e})
            else:
                # Create the Tier1 service router if it does not exist
                if not self.core_plugin.service_router_has_services(
                    context.elevated(), router_id):
                    self.core_plugin.create_service_router(context, router_id)

        if not lb_service:
            lb_name = p_utils.get_service_lb_name(lb, router_id)
            tags = p_utils.get_tags(self.core_plugin,
                                    router_id if router_id else '',
                                    lb_const.LR_ROUTER_TYPE,
                                    lb['tenant_id'], context.project_name)
            tags.append(p_utils.get_service_lb_tag(lb['id']))

            lb_size = lb_utils.get_lb_flavor_size(self.flavor_plugin, context,
                                                  lb.get('flavor_id'))

            try:
                if network and network.get('router:external'):
                    connectivity_path = None
                else:
                    tier1_srv = self.core_plugin.nsxpolicy.tier1
                    connectivity_path = tier1_srv.get_path(router_id)
                if connectivity_path:
                    with p_utils.get_lb_rtr_lock(router_id):
                        service_client.create_or_overwrite(
                            lb_name, lb_service_id=lb['id'],
                            description=lb['description'],
                            tags=tags, size=lb_size,
                            connectivity_path=connectivity_path)
                else:
                    # no lock
                    service_client.create_or_overwrite(
                        lb_name, lb_service_id=lb['id'],
                        description=lb['description'],
                        tags=tags, size=lb_size,
                        connectivity_path=connectivity_path)

                # Add rule to advertise external vips
                if router_id:
                    p_utils.update_router_lb_vip_advertisement(
                        context, self.core_plugin, router_id)
            except Exception as e:
                with excutils.save_and_reraise_exception():
                    completor(success=False)
                    LOG.error('Failed to create loadbalancer %(lb)s for lb '
                              'with exception %(e)s', {'lb': lb['id'], 'e': e})

        # Make sure the vip port is marked with a device owner
        port = self.core_plugin.get_port(
            context.elevated(), lb['vip_port_id'])
        if not port.get('device_owner'):
            self.core_plugin.update_port(
                context.elevated(), lb['vip_port_id'],
                {'port': {'device_id': oct_const.DEVICE_ID_PREFIX + lb['id'],
                          'device_owner': lb_const.VMWARE_LB_VIP_OWNER}})
        completor(success=True)

    def update(self, context, old_lb, new_lb, completor):
        completor(success=True)

    def delete(self, context, lb, completor):
        router_id = None
        try:
            router_id = lb_utils.get_router_from_network(
                context, self.core_plugin, lb['vip_subnet_id'])
        except n_exc.SubnetNotFound:
            LOG.warning("VIP subnet %s not found while deleting "
                        "loadbalancer %s", lb['vip_subnet_id'], lb['id'])
        service_client = self.core_plugin.nsxpolicy.load_balancer.lb_service
        service = p_utils.get_lb_nsx_lb_service(
            self.core_plugin.nsxpolicy, lb['id'])
        if service:
            lb_service_id = service['id']
            if not router_id:
                router_id = lib_p_utils.path_to_id(
                    service.get('connectivity_path', ''))

            if router_id:
                with p_utils.get_lb_rtr_lock(router_id):
                    # check if this is the last lb for this router and update
                    # tags / delete service
                    try:
                        service_client.update_customized(
                            lb_service_id,
                            p_utils.remove_service_tag_callback(lb['id']))
                    except n_exc.BadRequest:
                        # This is the last Lb and service should be deleted
                        try:
                            service_client.delete(lb_service_id)
                        except Exception as e:
                            with excutils.save_and_reraise_exception():
                                completor(success=False)
                                LOG.error('Failed to delete loadbalancer '
                                          '%(lb)s for lb with error %(err)s',
                                          {'lb': lb['id'], 'err': e})
                        # Remove the service router if no more services
                        if not self.core_plugin.service_router_has_services(
                                context.elevated(), router_id):
                            try:
                                self.core_plugin.delete_service_router(
                                    router_id)
                            except Exception as e:
                                with excutils.save_and_reraise_exception():
                                    completor(success=False)
                                    LOG.error('Failed to delete service '
                                              'router upon deletion '
                                              'of loadbalancer %(lb)s with '
                                              'error %(err)s',
                                              {'lb': lb['id'], 'err': e})
            else:
                # LB without router (meaning external vip and no members)
                try:
                    service_client.delete(lb_service_id)
                except Exception as e:
                    with excutils.save_and_reraise_exception():
                        completor(success=False)
                        LOG.error('Failed to delete loadbalancer %(lb)s for '
                                  'lb with error %(err)s',
                                  {'lb': lb['id'], 'err': e})

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


def _nsx_status_to_lb_status(nsx_status):
    if not nsx_status:
        # default fallback
        return lb_const.ONLINE

    # Statuses that are considered ONLINE:
    if nsx_status.upper() in ['UP', 'UNKNOWN', 'PARTIALLY_UP',
                              'NO_STANDBY']:
        return lb_const.ONLINE
    # Statuses that are considered OFFLINE:
    if nsx_status.upper() in ['PRIMARY_DOWN', 'DETACHED', 'DOWN', 'ERROR']:
        return lb_const.OFFLINE
    if nsx_status.upper() == 'DISABLED':
        return lb_const.DISABLED

    # default fallback
    LOG.debug("NSX LB status %s - interpreted as ONLINE", nsx_status)
    return lb_const.ONLINE


def _get_octavia_lb_status(result):
    if result.get('service_status'):
        # Use backend service_status
        lb_status = _nsx_status_to_lb_status(
            result['service_status'])
    elif result.get('alarm'):
        # No status, but has alarms -> ERROR
        lb_status = lb_const.OFFLINE
    else:
        # Unknown - assume it is ok
        lb_status = lb_const.ONLINE
    return lb_status


def status_getter(context, core_plugin):
    nsxlib_lb = core_plugin.nsxpolicy.load_balancer
    lb_client = nsxlib_lb.lb_service
    lbs = lb_client.list(silent=True)
    lb_statuses = []
    lsn_statuses = []
    pool_statuses = []
    member_statuses = []
    for lb in lbs:
        try:
            service_status = lb_client.get_status(lb['id'], silent=True)
            if not isinstance(service_status, dict):
                service_status = {}
        except nsxlib_exc.ManagerError:
            LOG.warning("LB service %(lbs)s is not found",
                        {'lbs': id})
            service_status = {}
        lb_status_results = service_status.get('results')
        if lb_status_results:
            result = lb_status_results[0]
            lb_operating_status = _get_octavia_lb_status(result)
            for vs_status in result.get('virtual_servers', []):
                vs_id = lib_p_utils.path_to_id(
                    vs_status['virtual_server_path'])
                lsn_statuses.append({
                    'id': vs_id,
                    'operating_status': _nsx_status_to_lb_status(
                        vs_status['status'])})
            for pool_status in result.get('pools', []):
                if not pool_status.get('pool_path'):
                    LOG.warning("pool_path missing from lb status: %s",
                                lb_status_results)
                    continue
                pool_id = lib_p_utils.path_to_id(pool_status['pool_path'])
                pool_statuses.append({
                    'id': pool_id,
                    'operating_status': _nsx_status_to_lb_status(
                        pool_status.get('status'))})
                for member in pool_status.get('members', []):
                    member_statuses.append({
                        'pool_id': pool_id,
                        'member_ip': member.get('ip_address'),
                        'operating_status': _nsx_status_to_lb_status(
                            member.get('status'))})

        else:
            lb_operating_status = lb_const.OFFLINE

        for tag in lb['tags']:
            if tag['scope'] == 'loadbalancer_id':
                lb_statuses.append(
                    {'id': tag['tag'],
                     'operating_status': lb_operating_status})

    return {lb_const.LOADBALANCERS: lb_statuses,
            lb_const.LISTENERS: lsn_statuses,
            lb_const.POOLS: pool_statuses,
            lb_const.MEMBERS: member_statuses}
