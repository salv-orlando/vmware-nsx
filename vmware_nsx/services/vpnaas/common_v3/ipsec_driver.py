# Copyright 2019 VMware, Inc.
# All Rights Reserved
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import netaddr
from oslo_log import log as logging

from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants
from neutron_lib import context as n_context
from neutron_lib import exceptions as nexception
from neutron_lib.plugins import directory
from neutron_vpnaas.services.vpn import service_drivers

from vmware_nsx.extensions import projectpluginmap
from vmware_nsx.services.vpnaas.common_v3 import ipsec_utils

LOG = logging.getLogger(__name__)
IPSEC = 'ipsec'


class RouterWithSNAT(nexception.BadRequest):
    message = _("Router %(router_id)s has a VPN service and cannot enable "
                "SNAT")


class RouterWithOverlapNoSnat(nexception.BadRequest):
    message = _("Router %(router_id)s has a subnet overlapping with a VPN "
                "local subnet, and cannot disable SNAT")


class RouterOverlapping(nexception.BadRequest):
    message = _("Router %(router_id)s interface is overlapping with a VPN "
                "local subnet and cannot be added")


class NSXcommonIPsecVpnDriver(service_drivers.VpnDriver):

    def __init__(self, service_plugin, validator):
        self.vpn_plugin = service_plugin
        self._core_plugin = directory.get_plugin()
        if self._core_plugin.is_tvd_plugin():
            # TVD only supports nsx-T, and not nsx-P
            self._core_plugin = self._core_plugin.get_plugin_by_type(
                projectpluginmap.NsxPlugins.NSX_T)
        super(NSXcommonIPsecVpnDriver, self).__init__(
            service_plugin, validator)

        registry.subscribe(
            self._verify_overlap_subnet, resources.ROUTER_INTERFACE,
            events.BEFORE_CREATE)

    @property
    def l3_plugin(self):
        return self._core_plugin

    @property
    def service_type(self):
        return IPSEC

    def _get_dpd_profile_name(self, connection):
        return (connection['name'] or connection['id'])[:240] + '-dpd-profile'

    def _find_vpn_service_port(self, context, router_id):
        """Look for the neutron port created for the vpnservice of a router"""
        filters = {'device_id': ['router-' + router_id],
                   'device_owner': [ipsec_utils.VPN_PORT_OWNER]}
        ports = self.l3_plugin.get_ports(context, filters=filters)
        if ports:
            return ports[0]

    def _get_service_local_address(self, context, vpnservice):
        """Find/Allocate a port on the external network
        to allocate the ip to be used as the local ip of this service
        """
        router_id = vpnservice['router_id']
        # check if this router already have an IP
        port = self._find_vpn_service_port(context, router_id)
        if not port:
            # create a new port, on the external network of the router
            # Note(asarfaty): using a unique device owner and device id to
            # make sure tis port will be ignored in certain queries
            ext_net = vpnservice['router']['gw_port']['network_id']
            port_data = {
                'port': {
                    'network_id': ext_net,
                    'name': 'VPN local address port',
                    'admin_state_up': True,
                    'device_id': 'router-' + router_id,
                    'device_owner': ipsec_utils.VPN_PORT_OWNER,
                    'fixed_ips': constants.ATTR_NOT_SPECIFIED,
                    'mac_address': constants.ATTR_NOT_SPECIFIED,
                    'port_security_enabled': False,
                    'tenant_id': vpnservice['tenant_id']}}
            port = self.l3_plugin.base_create_port(context, port_data)

        # return the port ip(v4) as the local address
        for fixed_ip in port['fixed_ips']:
            if (len(port['fixed_ips']) == 1 or
                netaddr.IPNetwork(fixed_ip['ip_address']).version == 4):
                return fixed_ip['ip_address']

    def _update_status(self, context, vpn_service_id, ipsec_site_conn_id,
                       status, updated_pending_status=True):
        vpn_status = {'id': vpn_service_id,
                      'updated_pending_status': updated_pending_status,
                      'status': status,
                      'ipsec_site_connections': {}}
        if ipsec_site_conn_id:
            ipsec_site_conn = {
                'status': status,
                'updated_pending_status': updated_pending_status}
            vpn_status['ipsec_site_connections'] = {
                ipsec_site_conn_id: ipsec_site_conn}
        status_list = [vpn_status]
        self.service_plugin.update_status_by_agent(context, status_list)

    def _check_subnets_overlap_with_all_conns(self, context, subnets):
        # find all vpn services with connections
        filters = {'status': [constants.ACTIVE, constants.DOWN]}
        connections = self.vpn_plugin.get_ipsec_site_connections(
            context, filters=filters)
        # Check if any of the connections overlap with the given subnets
        for conn in connections:
            local_cidrs = self.validator._get_local_cidrs(context, conn)
            if netaddr.IPSet(subnets) & netaddr.IPSet(local_cidrs):
                return False

        return True

    def _verify_overlap_subnet(self, resource, event, trigger, **kwargs):
        """Upon router interface creation validation overlapping with vpn"""
        router_db = kwargs.get('router_db')
        port = kwargs.get('port')
        if not port or not router_db:
            LOG.warning("NSX V3 VPNaaS ROUTER_INTERFACE BEFORE_CREATE "
                        "callback didn't get all the relevant information")
            return

        if router_db.enable_snat:
            # checking only no-snat routers
            return

        admin_con = n_context.get_admin_context()
        # Get the (ipv4) subnet of the interface
        subnet_id = None
        for fixed_ip in port['fixed_ips']:
            if netaddr.IPNetwork(fixed_ip['ip_address']).version == 4:
                subnet_id = fixed_ip.get('subnet_id')
                break
        if subnet_id:
            subnet = self._core_plugin.get_subnet(admin_con, subnet_id)
            # find all vpn services with connections
            if not self._check_subnets_overlap_with_all_conns(
                admin_con, [subnet['cidr']]):
                raise RouterOverlapping(router_id=kwargs.get('router_id'))
