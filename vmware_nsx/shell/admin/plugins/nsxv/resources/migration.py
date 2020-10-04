# Copyright 2019 VMware, Inc.  All rights reserved.
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

import sys

import netaddr
from oslo_log import log as logging

from neutron_lib.api.definitions import allowedaddresspairs as addr_apidef
from neutron_lib.api.definitions import provider_net as pnet
from neutron_lib.api import validators
from neutron_lib.callbacks import registry
from neutron_lib import constants as nl_constants
from neutron_lib import context as n_context

from vmware_nsx.common import nsxv_constants
from vmware_nsx.common import utils as c_utils
from vmware_nsx.services.lbaas.nsx_v3.implementation import lb_utils
from vmware_nsx.services.lbaas.octavia import constants as oct_const
from vmware_nsx.shell.admin.plugins.common import constants
from vmware_nsx.shell.admin.plugins.common import utils as admin_utils
from vmware_nsx.shell.admin.plugins.nsxv.resources import utils
from vmware_nsx.shell import resources as shell
from vmware_nsxlib.v3 import nsx_constants as nsxlib_consts

LOG = logging.getLogger(__name__)


@admin_utils.output_header
def validate_config_for_migration(resource, event, trigger, **kwargs):
    """Validate the nsxv configuration before migration to nsx-t"""

    transit_networks = ["100.64.0.0/16"]
    if kwargs.get('property'):
        # input validation
        properties = admin_utils.parse_multi_keyval_opt(kwargs['property'])
        transit_network = properties.get('transit-network')
        if transit_network:
            transit_networks = [transit_network]

    # Max number of allowed address pairs (allowing 3 for fixed ips)
    num_allowed_addr_pairs = nsxlib_consts.NUM_ALLOWED_IP_ADDRESSES - 3

    admin_context = n_context.get_admin_context()
    n_errors = 0

    with utils.NsxVPluginWrapper() as plugin:
        # Ports validations:
        ports = plugin.get_ports(admin_context)
        for port in ports:
            net_id = port['network_id']
            # Too many address pairs in a port
            address_pairs = port.get(addr_apidef.ADDRESS_PAIRS)
            if len(address_pairs) > num_allowed_addr_pairs:
                n_errors = n_errors + 1
                LOG.error("%s allowed address pairs for port %s. Only %s are "
                          "allowed.",
                          len(address_pairs), port['id'],
                          num_allowed_addr_pairs)

            # Compute port on external network
            if (port.get('device_owner', '').startswith(
                    nl_constants.DEVICE_OWNER_COMPUTE_PREFIX) and
                plugin._network_is_external(admin_context, net_id)):
                n_errors = n_errors + 1
                LOG.error("Compute port %s on external network %s is not "
                          "allowed.", port['id'], net_id)

        # Networks & subnets validations:
        networks = plugin.get_networks(admin_context)
        for net in networks:
            # skip internal networks
            if net['project_id'] == nsxv_constants.INTERNAL_TENANT_ID:
                continue

            # VXLAN or portgroup provider networks
            net_type = net.get(pnet.NETWORK_TYPE)
            if (net_type == c_utils.NsxVNetworkTypes.VXLAN or
                net_type == c_utils.NsxVNetworkTypes.PORTGROUP):
                n_errors = n_errors + 1
                LOG.error("Network %s of type %s is not supported.",
                          net['id'], net_type)

            subnets = plugin._get_subnets_by_network(admin_context, net['id'])
            n_dhcp_subnets = 0

            # Multiple DHCP subnets per network
            for subnet in subnets:
                if subnet['enable_dhcp']:
                    n_dhcp_subnets = n_dhcp_subnets + 1
            if n_dhcp_subnets > 1:
                n_errors = n_errors + 1
                LOG.error("Network %s has %s dhcp subnets. Only 1 is allowed.",
                          net['id'], n_dhcp_subnets)

            # Subnets overlapping with the transit network
            for subnet in subnets:
                # get the subnet IPs
                if ('allocation_pools' in subnet and
                    validators.is_attr_set(subnet['allocation_pools'])):
                    # use the pools instead of the cidr
                    subnet_networks = [
                        netaddr.IPRange(pool.get('start'), pool.get('end'))
                        for pool in subnet.get('allocation_pools')]
                else:
                    cidr = subnet.get('cidr')
                    if not validators.is_attr_set(cidr):
                        return
                    subnet_networks = [netaddr.IPNetwork(subnet['cidr'])]

                for subnet_net in subnet_networks:
                    if (netaddr.IPSet(subnet_net) &
                        netaddr.IPSet(transit_networks)):
                        n_errors = n_errors + 1
                        LOG.error("Subnet %s overlaps with the transit "
                                  "network ips: %s.",
                                  subnet['id'], transit_networks)

            # Network attached to multiple routers
            intf_ports = plugin._get_network_interface_ports(
                admin_context, net['id'])
            if len(intf_ports) > 1:
                n_errors = n_errors + 1
                LOG.error("Network %s has interfaces on multiple routers. "
                          "Only 1 is allowed.", net['id'])

        # Routers validations:
        routers = plugin.get_routers(admin_context)
        for router in routers:
            # Interface subnets overlap with the GW subnet
            gw_subnets = plugin._find_router_gw_subnets(admin_context, router)
            gw_cidrs = [subnet['cidr'] for subnet in gw_subnets]
            gw_ip_set = netaddr.IPSet(gw_cidrs)

            if_cidrs = plugin._find_router_subnets_cidrs(
                admin_context, router['id'])
            if_ip_set = netaddr.IPSet(if_cidrs)

            if gw_ip_set & if_ip_set:
                n_errors = n_errors + 1
                LOG.error("Interface network of router %s cannot overlap with "
                          "router GW network", router['id'])

        # TODO(asarfaty): missing validations:
        # - Vlan provider network with the same VLAN tag as the uplink
        #   profile tag used in the relevant transport node
        #   (cannot check this without access to the T manager)

        # Octavia loadbalancers validation:
        filters = {'device_owner': [nl_constants.DEVICE_OWNER_LOADBALANCERV2,
                                    oct_const.DEVICE_OWNER_OCTAVIA]}
        lb_ports = plugin.get_ports(admin_context, filters=filters)
        for port in lb_ports:
            fixed_ips = port.get('fixed_ips', [])
            if fixed_ips:
                subnet_id = fixed_ips[0]['subnet_id']
                network = lb_utils.get_network_from_subnet(
                    admin_context, plugin, subnet_id)
                router_id = lb_utils.get_router_from_network(
                    admin_context, plugin, subnet_id)
                # Loadbalancer vip subnet must be connected to a router or
                # belong to an external network
                if (not router_id and network and
                    not network.get('router:external')):
                    n_errors = n_errors + 1
                    LOG.error("Loadbalancer %s subnet %s is not external "
                              "nor connected to a router.",
                              port.get('device_id'), subnet_id)

            # TODO(asarfaty): Multiple listeners on the same pool is not
            # supported, but currently the admin utility has no access to this
            # information from octavia

            # TODO(asarfaty): Member on external subnet must have fip as ip,
            # but currently the admin utility has no access to this information
            # from octavia

    if n_errors > 0:
        plural = n_errors > 1
        LOG.error("The NSX-V plugin configuration is not ready to be "
                  "migrated to NSX-T. %s error%s found.", n_errors,
                  's were' if plural else ' was')
        sys.exit(n_errors)

    LOG.info("The NSX-V plugin configuration is ready to be migrated to "
             "NSX-T.")


registry.subscribe(validate_config_for_migration,
                   constants.NSX_MIGRATE_V_T,
                   shell.Operations.VALIDATE.value)
