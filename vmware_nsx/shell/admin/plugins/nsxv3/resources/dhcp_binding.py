# Copyright 2016 VMware, Inc.  All rights reserved.
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
from neutron_lib import context as neutron_context
from neutron_lib import exceptions
from oslo_config import cfg
from oslo_log import log as logging

from vmware_nsx.common import utils as nsx_utils
from vmware_nsx.shell.admin.plugins.common import constants
from vmware_nsx.shell.admin.plugins.common import formatters
from vmware_nsx.shell.admin.plugins.common import utils as admin_utils
from vmware_nsx.shell.admin.plugins.nsxv3.resources import utils
import vmware_nsx.shell.resources as shell

LOG = logging.getLogger(__name__)
neutron_client = utils.NeutronDbClient()


@admin_utils.output_header
def list_dhcp_bindings(resource, event, trigger, **kwargs):
    """List DHCP bindings in Neutron."""

    comp_ports = [port for port in neutron_client.get_ports()
                  if nsx_utils.is_port_dhcp_configurable(port)]
    LOG.info(formatters.output_formatter(constants.DHCP_BINDING, comp_ports,
                                         ['id', 'mac_address', 'fixed_ips']))


@admin_utils.output_header
def nsx_recreate_dhcp_server(resource, event, trigger, **kwargs):
    """Recreate DHCP server & binding for a neutron network"""
    if not cfg.CONF.nsx_v3.native_dhcp_metadata:
        LOG.error("Native DHCP is disabled.")
        return

    errmsg = ("Need to specify net-id property. Add --property net-id=<id>")
    if not kwargs.get('property'):
        LOG.error("%s", errmsg)
        return
    properties = admin_utils.parse_multi_keyval_opt(kwargs['property'])
    net_id = properties.get('net-id')
    if not net_id:
        LOG.error("%s", errmsg)
        return

    context = neutron_context.get_admin_context()
    with utils.NsxV3PluginWrapper() as plugin:
        # verify that this is an existing network with dhcp enabled
        try:
            network = plugin._get_network(context, net_id)
        except exceptions.NetworkNotFound:
            LOG.error("Network %s was not found", net_id)
            return
        if plugin._has_no_dhcp_enabled_subnet(context, network):
            LOG.error("Network %s has no DHCP enabled subnet", net_id)
            return
        dhcp_relay = plugin.get_network_az_by_net_id(
            context, net_id).dhcp_relay_service
        if dhcp_relay:
            LOG.error("Native DHCP should not be enabled with dhcp relay")
            return

        # find the dhcp subnet of this network
        subnet_id = None
        for subnet in network.subnets:
            if subnet.enable_dhcp:
                subnet_id = subnet.id
                break
        if not subnet_id:
            LOG.error("Network %s has no DHCP enabled subnet", net_id)
            return
        dhcp_subnet = plugin.get_subnet(context, subnet_id)
        # disable and re-enable the dhcp
        plugin._enable_native_dhcp(context, network, dhcp_subnet)
    LOG.info("Done.")


registry.subscribe(list_dhcp_bindings,
                   constants.DHCP_BINDING,
                   shell.Operations.LIST.value)
registry.subscribe(nsx_recreate_dhcp_server,
                   constants.DHCP_BINDING,
                   shell.Operations.NSX_RECREATE.value)
