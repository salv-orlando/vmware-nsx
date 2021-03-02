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
from oslo_config import cfg
from oslo_log import log as logging
from oslo_serialization import jsonutils
from oslo_utils import uuidutils

from networking_l2gw.db.l2gateway import l2gateway_models
from neutron.services.qos import qos_plugin
from neutron_lib.api.definitions import allowedaddresspairs as addr_apidef
from neutron_lib.api.definitions import portbindings as pbin
from neutron_lib.api.definitions import provider_net as pnet
from neutron_lib.api import validators
from neutron_lib.callbacks import registry
from neutron_lib import constants as nl_constants
from neutron_lib import context as n_context

from vmware_nsx.common import config
from vmware_nsx.common import nsxv_constants
from vmware_nsx.common import utils as c_utils
from vmware_nsx.db import nsx_portbindings_db as portbinding
from vmware_nsx.db import nsxv_db
from vmware_nsx.plugins.nsx_v import availability_zones as nsx_az
from vmware_nsx.services.lbaas.nsx_v import lbaas_common as lb_common
from vmware_nsx.services.lbaas.nsx_v3.implementation import lb_utils
from vmware_nsx.services.lbaas.octavia import constants as oct_const
from vmware_nsx.services.qos.nsx_v3 import pol_utils as qos_utils
from vmware_nsx.shell.admin.plugins.common import constants
from vmware_nsx.shell.admin.plugins.common import formatters
from vmware_nsx.shell.admin.plugins.common import utils as admin_utils
from vmware_nsx.shell.admin.plugins.nsxv.resources import utils
from vmware_nsx.shell import resources as shell
from vmware_nsxlib.v3 import nsx_constants as nsxlib_consts

LOG = logging.getLogger(__name__)


def _get_router_from_network(context, plugin, subnet_id):
    subnet = plugin.get_subnet(context.elevated(), subnet_id)
    network_id = subnet['network_id']
    ports = plugin._get_network_interface_ports(
        context.elevated(), network_id)
    if ports:
        return ports[0]['device_id']


@admin_utils.output_header
def validate_config_for_migration(resource, event, trigger, **kwargs):
    """Validate the nsxv configuration before migration to nsx-t"""

    # Read the command line parameters
    transit_networks = ["100.64.0.0/16"]
    strict = False
    if kwargs.get('property'):
        # input validation
        properties = admin_utils.parse_multi_keyval_opt(kwargs['property'])
        transit_network = properties.get('transit-network')
        if transit_network:
            transit_networks = [transit_network]
        strict = bool(properties.get('strict', 'false').lower() == 'true')

    LOG.info("Running migration config validation in %sstrict mode",
             '' if strict else 'non-')

    admin_context = n_context.get_admin_context()
    n_errors = 0

    # General config options / per AZ which are unsupported
    config.register_nsxv_azs(cfg.CONF, cfg.CONF.nsxv.availability_zones)
    zones = nsx_az.NsxVAvailabilityZones()
    unsupported_configs = ['edge_ha', 'edge_host_groups']
    for az in zones.list_availability_zones_objects():
        for attr in unsupported_configs:
            if getattr(az, attr):
                LOG.warning("WARNING: \'%s\' configuration is not supported "
                            "and will not be honored by NSX-T (availability "
                            "zone %s)", attr, az.name)
                if strict:
                    n_errors = n_errors + 1

    with utils.NsxVPluginWrapper() as plugin:
        # The migration is supported only for NSX 6.4.9 and above
        nsx_ver = plugin.nsx_v.vcns.get_version()
        if not c_utils.is_nsxv_version_6_4_9(nsx_ver):
            LOG.error("ERROR: Migration with NSX-V version %s is not "
                      "supported.", nsx_ver)
            n_errors = n_errors + 1

        # Ports validations:
        # Max number of allowed address pairs (allowing 1 for fixed ips)
        num_allowed_addr_pairs = nsxlib_consts.NUM_ALLOWED_IP_ADDRESSES_v4 - 1
        ports = plugin.get_ports(admin_context)
        for port in ports:
            net_id = port['network_id']
            # Too many address pairs in a port
            address_pairs = port.get(addr_apidef.ADDRESS_PAIRS)
            if len(address_pairs) > num_allowed_addr_pairs:
                LOG.warning("WARNING: %s allowed address pairs for port %s. "
                            "Only %s are allowed.",
                            len(address_pairs), port['id'],
                            num_allowed_addr_pairs)
                if strict:
                    n_errors = n_errors + 1

            # Compute port on external network
            if (port.get('device_owner', '').startswith(
                    nl_constants.DEVICE_OWNER_COMPUTE_PREFIX) and
                plugin._network_is_external(admin_context, net_id)):
                n_errors = n_errors + 1
                LOG.error("ERROR: Compute port %s on external network %s is "
                          "not allowed.", port['id'], net_id)

            vnic = port.get(pbin.VNIC_TYPE)
            if vnic in portbinding.VNIC_TYPES_DIRECT_PASSTHROUGH:
                net = plugin.get_network(admin_context, port['network_id'])
                net_type = net.get(pnet.NETWORK_TYPE)
                if net_type not in portbinding.SUPPORTED_T_NETWORK_TYPES:
                    n_errors = n_errors + 1
                    LOG.error("ERROR: Port %s vnic type %s is not supported "
                              "with network type %s.", port['id'],
                              vnic, net_type)

        # Networks & subnets validations:
        networks = plugin.get_networks(admin_context)
        for net in networks:
            # Skip internal networks
            if net['project_id'] == nsxv_constants.INTERNAL_TENANT_ID:
                continue

            # Skip public networks
            if plugin._network_is_external(admin_context, net['id']):
                continue

            # VXLAN or portgroup provider networks
            net_type = net.get(pnet.NETWORK_TYPE)
            overlay_net = bool(net_type != c_utils.NsxVNetworkTypes.VLAN)
            if (net_type == c_utils.NsxVNetworkTypes.VXLAN or
                net_type == c_utils.NsxVNetworkTypes.PORTGROUP):
                n_errors = n_errors + 1
                LOG.error("ERROR: Network %s of type %s is not supported.",
                          net['id'], net_type)

            subnets = plugin._get_subnets_by_network(admin_context, net['id'])
            n_dhcp_subnets = 0

            # Multiple DHCP subnets per network
            for subnet in subnets:
                if subnet['enable_dhcp']:
                    n_dhcp_subnets = n_dhcp_subnets + 1
            if n_dhcp_subnets > 1:
                n_errors = n_errors + 1
                LOG.error("ERROR: Network %s has %s dhcp subnets. Only 1 is "
                          "allowed.", net['id'], n_dhcp_subnets)

            # Network attached to multiple routers
            intf_ports = plugin._get_network_interface_ports(
                admin_context, net['id'])
            if len(intf_ports) > 1:
                n_errors = n_errors + 1
                LOG.error("ERROR: Network %s has interfaces on multiple "
                          "routers. Only 1 is allowed.", net['id'])

            if (cfg.CONF.vlan_transparent and
                net.get('vlan_transparent') is True):
                if len(intf_ports) > 0:
                    n_errors = n_errors + 1
                    LOG.error("ERROR: VLAN Transparent network %s cannot be "
                              "attached to a logical router.", net['id'])
                if n_dhcp_subnets > 0:
                    n_errors = n_errors + 1
                    LOG.error("ERROR: DHCP is not supported for VLAN "
                              "transparent network %s.", net['id'])

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
                        LOG.error("ERROR: Subnet %s overlaps with the transit "
                                  "network ips: %s.",
                                  subnet['id'], transit_networks)

                # Cannot support non-dhcp overlay subnet attached to a router
                # if there is also a dhcp subnet on the same network
                if (overlay_net and n_dhcp_subnets > 0 and
                    not subnet['enable_dhcp']):
                    # look for a router interface for this subnet
                    for if_port in intf_ports:
                        if if_port['fixed_ips']:
                            if_sub = if_port['fixed_ips'][0]['subnet_id']
                            if subnet['id'] == if_sub:
                                n_errors = n_errors + 1
                                LOG.error("ERROR: Network %s has non-dhcp "
                                          "subnet attached to a router, and "
                                          "another dhcp subnet. This is not "
                                          "allowed.", net['id'])

                # Cannot use a non-gateway subnet attached to a router
                if not subnet['gateway_ip']:
                    for if_port in intf_ports:
                        if if_port['fixed_ips']:
                            if_sub = if_port['fixed_ips'][0]['subnet_id']
                            if subnet['id'] == if_sub:
                                n_errors = n_errors + 1
                                LOG.error("ERROR: Subnet %s attached to a "
                                          "router must have a gateway IP.",
                                          subnet['id'])

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
                LOG.error("ERROR: Interface network of router %s cannot "
                          "overlap with router GW network", router['id'])

            # router without external gw cannot be attached to a vlan subnet
            router_db = plugin._get_router(admin_context, router['id'])
            if not router_db.gw_port:
                router_subnets = plugin._load_router_subnet_cidrs_from_db(
                    admin_context, router['id'])
                for subnet in router_subnets:
                    net_id = subnet['network_id']
                    net = plugin.get_network(admin_context, net_id)
                    net_type = net.get(pnet.NETWORK_TYPE)
                    if net_type == c_utils.NsxVNetworkTypes.VLAN:
                        n_errors = n_errors + 1
                        LOG.error("ERROR: Vlan network %s cannot be attached "
                                  "to router %s without a gateway", net_id,
                                router['id'])

        # Look for orphaned neutron networks and non neutron backend networks
        backend_networks = utils.get_networks()
        missing_networks = utils.get_orphaned_networks(backend_networks)
        for net in missing_networks:
            if strict:
                n_errors = n_errors + 1
            LOG.warning("WARNING: NSX backend network %s:%s is missing from "
                        "neutron and is probably an orphaned. Please delete "
                        "it.", net.get('moref'), net.get('name'))

        for net in backend_networks:
            moref = net['moref']
            name = net['name']
            net_type = net['type']

            if ((len(name) < 36 or not uuidutils.is_uuid_like(name)) and
                net_type in ['DistributedVirtualPortgroup', 'VirtualWire']):
                if (net_type == 'DistributedVirtualPortgroup' and
                    name.startswith('edge-')):
                    continue
                if (name == 'DPortGroup' and net_type ==
                    'DistributedVirtualPortgroup'):
                    continue

                if name:
                    # Find the vlan networks
                    id_from_name = name[-36:]
                    if nsxv_db.get_network_bindings(admin_context.session,
                                                    id_from_name):
                        continue
                if net_type == 'DistributedVirtualPortgroup':
                    if nsxv_db.get_network_bindings_by_physical_net(
                        admin_context.session, moref):
                        continue

                if strict:
                    n_errors = n_errors + 1
                LOG.warning("WARNING: NSX backend network %s:%s is not a "
                            "neutron network and cannot be migrated. "
                            "Please delete it or migrate it manually.",
                            moref, name)

        # Octavia loadbalancers validation:
        filters = {'device_owner': [nl_constants.DEVICE_OWNER_LOADBALANCERV2,
                                    oct_const.DEVICE_OWNER_OCTAVIA]}
        lb_ports = plugin.get_ports(admin_context, filters=filters)
        for port in lb_ports:
            lb_id = port.get('device_id')
            fixed_ips = port.get('fixed_ips', [])
            if fixed_ips:
                subnet_id = fixed_ips[0]['subnet_id']
                network = lb_utils.get_network_from_subnet(
                    admin_context, plugin, subnet_id)
                lb_router_id = _get_router_from_network(
                    admin_context, plugin, subnet_id)
                # Loadbalancer vip subnet must be connected to a router or
                # belong to an external network
                if (not lb_router_id and network and
                    not network.get('router:external')):
                    n_errors = n_errors + 1
                    LOG.error("ERROR: Loadbalancer %s subnet %s is not "
                              "external nor connected to a router.",
                              port.get('device_id'), subnet_id)

            if not lb_id:
                continue

            lb_id = lb_id[3:]
            lb_binding = nsxv_db.get_nsxv_lbaas_loadbalancer_binding(
                admin_context.session, lb_id)
            if not lb_binding or not lb_binding['edge_id']:
                LOG.warning("Cannot find edge for Loadbalancer %s", lb_id)
                continue
            edge_id = lb_binding['edge_id']

            # Multiple listeners on the same pool is not supported
            result = plugin.nsx_v.vcns.get_vips(edge_id)
            if len(result) == 2:
                edge_vs = result[1]
                pools = []
                for vip in edge_vs.get('virtualServer', []):
                    if not vip.get('defaultPoolId'):
                        continue
                    if vip['defaultPoolId'] in pools:
                        LOG.error("ERROR: Found multiple listeners using the "
                                  "same default pool with loadbalancer %s. "
                                  "This is not supported.", lb_id)
                        n_errors = n_errors + 1
                        break
                    pools.append(vip['defaultPoolId'])

            # Cannot support LB with members from various subnets not uplinked
            # to the same edge router. This can be indicated by multiple
            # internal interfaces on the LB edge
            is_old_lb = lb_common.is_lb_on_router_edge(
                admin_context, plugin, edge_id)
            if not is_old_lb:
                filters = {'device_id': [lb_id],
                           'device_owner': [lb_common.LBAAS_DEVICE_OWNER]}
                lb_ports = plugin.get_ports(admin_context, filters=filters)
                # get the subnets of those ports
                lb_subnets = list(set([port['fixed_ips'][0]['subnet_id']
                                       for port in lb_ports]))
                # make sure all subnets are connected to the same router
                lb_routers = [lb_router_id]
                for sub_id in lb_subnets:
                    router_id = _get_router_from_network(
                        admin_context, plugin, sub_id)
                    if not router_id:
                        LOG.error("ERROR: Found member of subnet %s not "
                                  "uplinked to any router on loadbalancer "
                                  "%s. This is not supported.",
                                  sub_id, lb_id)
                        n_errors = n_errors + 1
                    elif router_id not in lb_routers:
                        lb_routers.append(router_id)
                if len(lb_routers) > 1:
                    LOG.error("ERROR: Found members/vips from different "
                              "subnets or uplinks to different routers on "
                              "loadbalancer %s. This is not supported.", lb_id)
                    n_errors = n_errors + 1
                    break

    # Security groups without policies
    sgs = plugin.get_security_groups(admin_context)
    for sg in sgs:
        if plugin._is_policy_security_group(admin_context, sg['id']):
            LOG.error("ERROR: Security group %s has NSX policy. This is not "
                      "supported.", sg['id'])
            n_errors = n_errors + 1

    # Validate QoS limits
    qos_plugin_inst = qos_plugin.QoSPlugin()
    policies = qos_plugin_inst.get_policies(admin_context)
    for policy in policies:
        for rule in policy.get('rules', []):
            if rule.get('type') == 'bandwidth_limit':
                # Validate the limits
                if rule.get('max_kbps') < qos_utils.MAX_KBPS_MIN_VALUE:
                    LOG.error("ERROR: QoS Policy %s has max_kbps below the "
                              "minimal value of %s. This is not supported.",
                              policy['id'], rule['max_kbps'])
                    n_errors = n_errors + 1
                if rule.get('max_burst_kbps') > qos_utils.MAX_BURST_MAX_VALUE:
                    LOG.error("ERROR: QoS Policy %s has max_burst_kbps above "
                              "the maximal value of %s. This is not "
                              "supported.",
                              policy['id'], rule['max_burst_kbps'])
                    n_errors = n_errors + 1

    # L2GW is not supported with the policy plugin
    try:
        l2gws = admin_context.session.query(l2gateway_models.L2Gateway).all()
    except Exception:
        # L2GW DB was not initialized
        pass
    else:
        if len(l2gws):
            LOG.error("ERROR: Found %s L2Gws: %s. Networking-l2gw is not "
                      "supported.", len(l2gws), [l2gw.id for l2gw in l2gws])
            n_errors = n_errors + 1

    if n_errors > 0:
        plural = n_errors > 1
        LOG.error("The NSX-V plugin configuration is not ready to be "
                  "migrated to NSX-T. %s error%s found.", n_errors,
                  's were' if plural else ' was')
        sys.exit(n_errors)

    LOG.info("The NSX-V plugin configuration is ready to be migrated to "
             "NSX-T.")


@admin_utils.output_header
def list_ports_vif_ids(resource, event, trigger, **kwargs):
    filename = None
    if kwargs.get('property'):
        properties = admin_utils.parse_multi_keyval_opt(kwargs['property'])
        filename = properties.get('map-file')

    admin_context = n_context.get_admin_context()
    table_results = []
    map_results = {}

    with utils.NsxVPluginWrapper() as plugin:
        neutron_ports = plugin.get_ports(admin_context)
        for port in neutron_ports:
            # skip non compute ports
            if (not port.get('device_owner').startswith(
                nl_constants.DEVICE_OWNER_COMPUTE_PREFIX)):
                continue
            device_id = port.get('device_id')
            port_id = port['id']
            vnic_index = plugin._get_port_vnic_index(admin_context, port_id)
            table_results.append({'neutron_id': port_id,
                                  'instance_id': device_id,
                                  'vnic_index': vnic_index})
            if vnic_index is not None:
                map_results[port_id] = '%s:%s' % (device_id, 4000 + vnic_index)

    LOG.info(formatters.output_formatter(
        "Compute ports VID IDs", table_results,
        ['neutron_id', 'instance_id', 'vnic_index']))
    if filename:
        f = open(filename, "w")
        f.write("%s" % jsonutils.dumps(map_results))
        f.close()
        LOG.info("Mapping data saved into %s", filename)


registry.subscribe(validate_config_for_migration,
                   constants.NSX_MIGRATE_V_T,
                   shell.Operations.VALIDATE.value)

registry.subscribe(list_ports_vif_ids,
                   constants.PORTS,
                   shell.Operations.LIST.value)
