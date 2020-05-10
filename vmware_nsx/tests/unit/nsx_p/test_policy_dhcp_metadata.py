# Copyright (c) 2015 OpenStack Foundation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from unittest import mock

import netaddr
from oslo_config import cfg
from oslo_utils import uuidutils

from neutron.extensions import securitygroup as secgrp
from neutron_lib import constants
from neutron_lib import context
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import directory

from vmware_nsx.common import config
from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.extensions import advancedserviceproviders as as_providers
from vmware_nsx.plugins.nsx_p import availability_zones as nsx_az
from vmware_nsx.tests.unit.nsx_p import test_plugin
from vmware_nsxlib.v3.policy import core_resources as nsx_resources
from vmware_nsxlib.v3 import utils as nsxlib_utils


def set_az_in_config(name, metadata_proxy="metadata_proxy1",
                     dhcp_server_config="dsc1",
                     native_metadata_route="2.2.2.2",
                     dns_domain='aaaa',
                     nameservers=['bbbb']):
    group_name = 'az:%s' % name
    cfg.CONF.set_override('availability_zones', [name], group="nsx_p")
    config.register_nsxp_azs(cfg.CONF, [name])
    cfg.CONF.set_override("metadata_proxy", metadata_proxy,
                          group=group_name)
    cfg.CONF.set_override("dhcp_profile", dhcp_server_config,
                          group=group_name)
    cfg.CONF.set_override("native_metadata_route", native_metadata_route,
                          group=group_name)
    cfg.CONF.set_override("dns_domain", dns_domain,
                          group=group_name)
    cfg.CONF.set_override("nameservers", nameservers,
                          group=group_name)


class NsxPolicyDhcpTestCase(test_plugin.NsxPPluginTestCaseMixin):
    """Test native dhcp config when using MP DHCP"""
    #TODO(asarfaty): Add tests for DHCPv6
    def setUp(self):
        self._orig_dhcp_agent_notification = cfg.CONF.dhcp_agent_notification
        cfg.CONF.set_override('dhcp_agent_notification', False)
        cfg.CONF.set_override('dhcp_profile', 'dsc1', 'nsx_p')
        super(NsxPolicyDhcpTestCase, self).setUp()
        self._az_name = 'zone1'
        self.az_metadata_route = '3.3.3.3'
        set_az_in_config(self._az_name,
                         native_metadata_route=self.az_metadata_route)
        self._initialize_azs()
        self.plugin._init_dhcp_metadata()

    def tearDown(self):
        cfg.CONF.set_override('dhcp_agent_notification',
                              self._orig_dhcp_agent_notification)
        super(NsxPolicyDhcpTestCase, self).tearDown()

    def _make_subnet_data(self,
                          name=None,
                          network_id=None,
                          cidr=None,
                          gateway_ip=None,
                          tenant_id=None,
                          allocation_pools=None,
                          enable_dhcp=True,
                          dns_nameservers=None,
                          ip_version=4,
                          host_routes=None,
                          shared=False):
        return {'subnet': {
            'name': name,
            'network_id': network_id,
            'cidr': cidr,
            'gateway_ip': gateway_ip,
            'tenant_id': tenant_id,
            'allocation_pools': allocation_pools,
            'ip_version': ip_version,
            'enable_dhcp': enable_dhcp,
            'dns_nameservers': dns_nameservers,
            'host_routes': host_routes,
            'shared': shared}}

    def _bind_name(self, port, ip_version=4):
        return 'IPv%s binding for port %s' % (ip_version, port['port']['id'])

    def _verify_dhcp_service(self, network_id, tenant_id, enabled):
        # Verify if DHCP service is enabled on a network.
        port_res = self._list_ports('json', 200, network_id,
                                    tenant_id=tenant_id,
                                    device_owner=constants.DEVICE_OWNER_DHCP)
        port_list = self.deserialize('json', port_res)
        self.assertEqual(len(port_list['ports']) == 1, enabled)

    def _verify_dhcp_binding(self, subnet, port_data, update_data,
                             assert_data):
        # Verify if DHCP binding is updated.
        with mock.patch('vmware_nsxlib.v3.policy.core_resources.'
                        'SegmentDhcpStaticBindingConfigApi.'
                        'create_or_overwrite_v4') as update_dhcp_binding:
            device_owner = constants.DEVICE_OWNER_COMPUTE_PREFIX + 'None'
            device_id = uuidutils.generate_uuid()
            with self.port(subnet=subnet, device_owner=device_owner,
                           device_id=device_id, **port_data) as port:
                binding_name = self._bind_name(port)
                ip_address = port['port']['fixed_ips'][0]['ip_address']
                options = {'option121': {'static_routes': [
                               {'network': '%s' %
                                cfg.CONF.nsx_p.native_metadata_route,
                                'next_hop': '0.0.0.0'},
                               {'network': '%s' %
                                cfg.CONF.nsx_p.native_metadata_route,
                                'next_hop': ip_address},
                               {'network': subnet['subnet']['cidr'],
                                'next_hop': '0.0.0.0'},
                               {'network': constants.IPv4_ANY,
                                'next_hop': subnet['subnet']['gateway_ip']}]}}
                if 'extra_dhcp_opts' in port_data:
                    other_opts = []
                    options['others'] = []
                    for opt in port_data['extra_dhcp_opts']:
                        other_opts.append(
                            {'code': nsxlib_utils.get_dhcp_opt_code(
                                  opt['opt_name']),
                             'values': [opt['opt_value']]})
                    options['others'] = other_opts

                binding_data = {'mac_address': port['port']['mac_address'],
                                'ip_address': ip_address,
                                'gateway_address':
                                    subnet['subnet']['gateway_ip'],
                                'host_name':
                                    'host-%s' % ip_address.replace('.', '-'),
                                'lease_time': 86400,
                                'options': options}
                # Verify the initial bindings call.
                update_dhcp_binding.assert_called_once_with(
                    binding_name, subnet['subnet']['network_id'],
                    binding_id=port['port']['id'] + '-ipv4',
                    **binding_data)
                update_dhcp_binding.reset_mock()
                # Update the port with provided data.
                self.plugin.update_port(
                    context.get_admin_context(), port['port']['id'],
                    update_data)
                # Extend basic binding data with to-be-asserted data.
                binding_data.update(assert_data)
                # Verify the update call.
                update_dhcp_binding.assert_called_once_with(
                    binding_name, subnet['subnet']['network_id'],
                    binding_id=port['port']['id'] + '-ipv4',
                    **binding_data)

    def _verify_dhcp_binding_v6(self, subnet, port_data, update_data,
                                assert_data):
        # Verify if DHCP-v6 binding is updated.
        with mock.patch('vmware_nsxlib.v3.policy.core_resources.'
                        'SegmentDhcpStaticBindingConfigApi.'
                        'create_or_overwrite_v6') as update_dhcp_binding:
            device_owner = constants.DEVICE_OWNER_COMPUTE_PREFIX + 'None'
            device_id = uuidutils.generate_uuid()
            with self.port(subnet=subnet, device_owner=device_owner,
                           device_id=device_id, **port_data) as port:
                binding_name = self._bind_name(port, 6)
                ip_address = port['port']['fixed_ips'][0]['ip_address']
                binding_data = {'mac_address': port['port']['mac_address'],
                                'ip_addresses': [ip_address],
                                'lease_time': 86400}
                # Verify the initial bindings call.
                update_dhcp_binding.assert_called_once_with(
                    binding_name, subnet['subnet']['network_id'],
                    binding_id=port['port']['id'] + '-ipv6',
                    **binding_data)
                update_dhcp_binding.reset_mock()
                # Update the port with provided data.
                self.plugin.update_port(
                    context.get_admin_context(), port['port']['id'],
                    update_data)
                # Extend basic binding data with to-be-asserted data.
                binding_data.update(assert_data)
                # Verify the update call.
                update_dhcp_binding.assert_called_once_with(
                    binding_name, subnet['subnet']['network_id'],
                    binding_id=port['port']['id'] + '-ipv6',
                    **binding_data)

    def test_dhcp_service_with_create_network(self):
        # Test if DHCP service is disabled on a network when it is created.
        with self.network() as network:
            self._verify_dhcp_service(network['network']['id'],
                                      network['network']['tenant_id'], False)

    def test_dhcp_service_with_delete_dhcp_network(self):
        # Test if DHCP service is disabled when directly deleting a network
        # with a DHCP-enabled subnet.
        with self.network() as network:
            # make sure the plugin does not wait for segment realization
            with mock.patch.object(self.plugin, '_get_network_nsx_id',
                                   side_effect=Exception),\
                self.subnet(network=network, enable_dhcp=True):
                self.plugin.delete_network(context.get_admin_context(),
                                           network['network']['id'])
                self._verify_dhcp_service(network['network']['id'],
                                          network['network']['tenant_id'],
                                          False)

    def test_dhcp_service_with_create_non_dhcp_subnet(self):
        # Test if DHCP service is disabled on a network when a DHCP-disabled
        # subnet is created.
        with self.network() as network:
            with self.subnet(network=network, enable_dhcp=False):
                self._verify_dhcp_service(network['network']['id'],
                                          network['network']['tenant_id'],
                                          False)

    def test_dhcp_service_with_create_multiple_non_dhcp_subnets(self):
        # Test if DHCP service is disabled on a network when multiple
        # DHCP-disabled subnets are created.
        with self.network() as network:
            with self.subnet(network=network, cidr='10.0.0.0/24',
                             enable_dhcp=False):
                with self.subnet(network=network, cidr='20.0.0.0/24',
                                 enable_dhcp=False):
                    self._verify_dhcp_service(network['network']['id'],
                                              network['network']['tenant_id'],
                                              False)

    def test_dhcp_service_with_create_dhcp_subnet(self):
        # Test if DHCP service is enabled on a network when a DHCP-enabled
        # subnet is created.
        with self.network() as network:
            # make sure the plugin does not wait for segment realization
            with mock.patch.object(self.plugin, '_get_network_nsx_id',
                                   side_effect=Exception),\
                self.subnet(network=network, enable_dhcp=True):
                self._verify_dhcp_service(network['network']['id'],
                                          network['network']['tenant_id'],
                                          True)

    def test_dhcp_service_with_create_multiple_dhcp_subnets(self):
        # Test if multiple DHCP-enabled subnets cannot be created in a network.
        with self.network() as network:
            # make sure the plugin does not wait for segment realization
            with mock.patch.object(self.plugin, '_get_network_nsx_id',
                                   side_effect=Exception),\
                self.subnet(network=network, cidr='10.0.0.0/24',
                            enable_dhcp=True):
                subnet = {'subnet': {'network_id': network['network']['id'],
                                     'cidr': '20.0.0.0/24',
                                     'enable_dhcp': True}}
                self.assertRaises(
                    n_exc.InvalidInput, self.plugin.create_subnet,
                    context.get_admin_context(), subnet)

    def test_dhcp_service_with_delete_dhcp_subnet(self):
        # Test if DHCP service is disabled on a network when a DHCP-disabled
        # subnet is deleted.
        with self.network() as network:
            # make sure the plugin does not wait for segment realization
            with mock.patch.object(self.plugin, '_get_network_nsx_id',
                                   side_effect=Exception),\
                self.subnet(network=network, enable_dhcp=True) as subnet:
                self._verify_dhcp_service(network['network']['id'],
                                          network['network']['tenant_id'],
                                          True)
                self.plugin.delete_subnet(context.get_admin_context(),
                                          subnet['subnet']['id'])
                self._verify_dhcp_service(network['network']['id'],
                                          network['network']['tenant_id'],
                                          False)

    def test_dhcp_service_with_update_dhcp_subnet(self):
        # Test if DHCP service is enabled on a network when a DHCP-disabled
        # subnet is updated to DHCP-enabled.
        with self.network() as network:
            # make sure the plugin does not wait for segment realization
            with mock.patch.object(self.plugin, '_get_network_nsx_id',
                                   side_effect=Exception),\
                self.subnet(network=network, enable_dhcp=False) as subnet:
                self._verify_dhcp_service(network['network']['id'],
                                          network['network']['tenant_id'],
                                          False)
                data = {'subnet': {'enable_dhcp': True}}
                self.plugin.update_subnet(context.get_admin_context(),
                                          subnet['subnet']['id'], data)
                self._verify_dhcp_service(network['network']['id'],
                                          network['network']['tenant_id'],
                                          True)

    def test_dhcp_service_with_update_multiple_dhcp_subnets(self):
        # Test if a DHCP-disabled subnet cannot be updated to DHCP-enabled
        # if a DHCP-enabled subnet already exists in the same network.
        with self.network() as network:
            # make sure the plugin does not wait for segment realization
            with mock.patch.object(self.plugin, '_get_network_nsx_id',
                                   side_effect=Exception),\
                self.subnet(network=network, cidr='10.0.0.0/24',
                            enable_dhcp=True),\
                self.subnet(network=network, cidr='20.0.0.0/24',
                            enable_dhcp=False) as subnet:
                self._verify_dhcp_service(network['network']['id'],
                                          network['network']['tenant_id'],
                                          True)
                data = {'subnet': {'enable_dhcp': True}}
                self.assertRaises(
                    n_exc.InvalidInput, self.plugin.update_subnet,
                    context.get_admin_context(), subnet['subnet']['id'],
                    data)

    def test_dhcp_service_with_update_dhcp_port(self):
        # Test if DHCP server IP is updated when the corresponding DHCP port
        # IP is changed.
        with mock.patch('vmware_nsxlib.v3.policy.core_resources.'
                        'NsxPolicySegmentApi.'
                        'update') as update_segment_dhcp:
            # make sure the plugin does not wait for segment realization
            with mock.patch.object(self.plugin, '_get_network_nsx_id',
                                   side_effect=Exception),\
                self.subnet(cidr='10.0.0.0/24', enable_dhcp=True) as subnet:
                filters = {
                    'network_id': [subnet['subnet']['network_id']],
                    'device_owner': [constants.DEVICE_OWNER_DHCP]
                }
                dhcp_ports = self.plugin.get_ports(
                    context.get_admin_context(), filters=filters)
                port = dhcp_ports[0]
                old_ip = port['fixed_ips'][0]['ip_address']
                new_ip = str(netaddr.IPAddress(old_ip) + 1)
                data = {'port': {'fixed_ips': [
                    {'subnet_id': subnet['subnet']['id'],
                     'ip_address': new_ip}]}}
                update_segment_dhcp.reset_mock()
                self.plugin.update_port(context.get_admin_context(),
                                        port['id'], data)
                update_segment_dhcp.assert_called_once()

    def test_dhcp_binding_with_create_port(self):
        # Test if DHCP binding is added when a compute port is created.
        with mock.patch('vmware_nsxlib.v3.policy.core_resources.'
                        'SegmentDhcpStaticBindingConfigApi.'
                        'create_or_overwrite_v4') as create_dhcp_binding:
            with self.subnet(enable_dhcp=True) as subnet:
                device_owner = constants.DEVICE_OWNER_COMPUTE_PREFIX + 'None'
                device_id = uuidutils.generate_uuid()
                with self.port(subnet=subnet, device_owner=device_owner,
                               device_id=device_id) as port:
                    binding_name = self._bind_name(port)
                    ip = port['port']['fixed_ips'][0]['ip_address']
                    hostname = 'host-%s' % ip.replace('.', '-')
                    options = {'option121': {'static_routes': [
                        {'network': '%s' %
                         cfg.CONF.nsx_p.native_metadata_route,
                         'next_hop': '0.0.0.0'},
                        {'network': '%s' %
                         cfg.CONF.nsx_p.native_metadata_route,
                         'next_hop': ip},
                        {'network': subnet['subnet']['cidr'],
                         'next_hop': '0.0.0.0'},
                        {'network': '0.0.0.0/0',
                         'next_hop': subnet['subnet']['gateway_ip']}]}}
                    create_dhcp_binding.assert_called_once_with(
                        binding_name, subnet['subnet']['network_id'],
                        binding_id=port['port']['id'] + '-ipv4',
                        mac_address=port['port']['mac_address'],
                        ip_address=ip,
                        host_name=hostname,
                        lease_time=cfg.CONF.nsx_p.dhcp_lease_time,
                        options=options,
                        gateway_address=subnet['subnet']['gateway_ip'])

    def test_dhcp_binding_with_create_port_with_opts(self):
        # Test if DHCP binding is added when a compute port is created
        # with extra options.
        opt_name = 'interface-mtu'
        opt_code = 26
        opt_val = '9000'
        with mock.patch('vmware_nsxlib.v3.policy.core_resources.'
                        'SegmentDhcpStaticBindingConfigApi.'
                        'create_or_overwrite_v4') as create_dhcp_binding:
            with self.subnet(enable_dhcp=True) as subnet:
                device_owner = constants.DEVICE_OWNER_COMPUTE_PREFIX + 'None'
                device_id = uuidutils.generate_uuid()
                extra_dhcp_opts = [{'opt_name': opt_name,
                                    'opt_value': opt_val}]
                with self.port(subnet=subnet, device_owner=device_owner,
                               device_id=device_id,
                               extra_dhcp_opts=extra_dhcp_opts,
                               arg_list=('extra_dhcp_opts',)) as port:
                    binding_name = self._bind_name(port)
                    ip = port['port']['fixed_ips'][0]['ip_address']
                    hostname = 'host-%s' % ip.replace('.', '-')
                    options = {'option121': {'static_routes': [
                        {'network': '%s' %
                         cfg.CONF.nsx_p.native_metadata_route,
                         'next_hop': '0.0.0.0'},
                        {'network': '%s' %
                         cfg.CONF.nsx_p.native_metadata_route,
                         'next_hop': ip},
                        {'network': subnet['subnet']['cidr'],
                         'next_hop': '0.0.0.0'},
                        {'network': '0.0.0.0/0',
                         'next_hop': subnet['subnet']['gateway_ip']}]},
                        'others': [{'code': opt_code, 'values': [opt_val]}]}
                    create_dhcp_binding.assert_called_once_with(
                        binding_name, subnet['subnet']['network_id'],
                        binding_id=port['port']['id'] + '-ipv4',
                        mac_address=port['port']['mac_address'],
                        ip_address=ip,
                        host_name=hostname,
                        lease_time=cfg.CONF.nsx_p.dhcp_lease_time,
                        options=options,
                        gateway_address=subnet['subnet']['gateway_ip'])

    def test_dhcp_binding_with_create_port_with_opts121(self):
        # Test if DHCP binding is added when a compute port is created
        # with extra option121.
        with mock.patch('vmware_nsxlib.v3.policy.core_resources.'
                        'SegmentDhcpStaticBindingConfigApi.'
                        'create_or_overwrite_v4') as create_dhcp_binding:
            with self.subnet(enable_dhcp=True) as subnet:
                device_owner = constants.DEVICE_OWNER_COMPUTE_PREFIX + 'None'
                device_id = uuidutils.generate_uuid()
                extra_dhcp_opts = [{'opt_name': 'classless-static-route',
                                    'opt_value': '1.0.0.0/24,1.2.3.4'}]
                with self.port(subnet=subnet, device_owner=device_owner,
                               device_id=device_id,
                               extra_dhcp_opts=extra_dhcp_opts,
                               arg_list=('extra_dhcp_opts',)) as port:
                    ip = port['port']['fixed_ips'][0]['ip_address']
                    binding_name = self._bind_name(port)
                    hostname = 'host-%s' % ip.replace('.', '-')
                    options = {'option121': {'static_routes': [
                        {'network': '%s' %
                         cfg.CONF.nsx_p.native_metadata_route,
                         'next_hop': '0.0.0.0'},
                        {'network': '%s' %
                         cfg.CONF.nsx_p.native_metadata_route,
                         'next_hop': ip},
                        {'network': subnet['subnet']['cidr'],
                         'next_hop': '0.0.0.0'},
                        {'network': '0.0.0.0/0',
                         'next_hop': subnet['subnet']['gateway_ip']},
                        {'network': '1.0.0.0/24',
                         'next_hop': '1.2.3.4'}]}}
                    create_dhcp_binding.assert_called_once_with(
                        binding_name, subnet['subnet']['network_id'],
                        binding_id=port['port']['id'] + '-ipv4',
                        mac_address=port['port']['mac_address'],
                        ip_address=ip,
                        host_name=hostname,
                        lease_time=cfg.CONF.nsx_p.dhcp_lease_time,
                        options=options,
                        gateway_address=subnet['subnet']['gateway_ip'])

    def test_dhcp_binding_with_create_port_with_bad_opts(self):
        with self.subnet(enable_dhcp=True) as subnet:
            device_owner = constants.DEVICE_OWNER_COMPUTE_PREFIX + 'None'
            device_id = uuidutils.generate_uuid()
            ctx = context.get_admin_context()

            # Use illegal opt-name
            extra_dhcp_opts = [{'opt_name': 'Dummy',
                                'opt_value': 'Dummy'}]
            data = {'port': {
                'name': 'dummy',
                'network_id': subnet['subnet']['network_id'],
                'tenant_id': subnet['subnet']['tenant_id'],
                'device_owner': device_owner,
                'device_id': device_id,
                'extra_dhcp_opts': extra_dhcp_opts,
                'admin_state_up': True,
                'fixed_ips': [],
                'mac_address': '00:00:00:00:00:01',
            }}
            self.assertRaises(n_exc.InvalidInput,
                self.plugin.create_port, ctx, data)

            # Use illegal option121 value
            extra_dhcp_opts = [{'opt_name': 'classless-static-route',
                                'opt_value': '1.0.0.0/24,5.5.5.5,cc'}]
            data['port']['extra_dhcp_opts'] = extra_dhcp_opts
            self.assertRaises(n_exc.InvalidInput,
                self.plugin.create_port, ctx, data)

    def test_dhcp_binding_with_delete_port(self):
        # Test if DHCP binding is removed when the associated compute port
        # is deleted.
        with mock.patch('vmware_nsxlib.v3.policy.core_resources.'
                        'SegmentDhcpStaticBindingConfigApi.'
                        'delete') as delete_dhcp_binding:
            with self.subnet(enable_dhcp=True) as subnet:
                device_owner = constants.DEVICE_OWNER_COMPUTE_PREFIX + 'None'
                device_id = uuidutils.generate_uuid()
                with self.port(subnet=subnet, device_owner=device_owner,
                               device_id=device_id) as port:
                    self.plugin.delete_port(
                        context.get_admin_context(), port['port']['id'])
                    delete_dhcp_binding.assert_called_with(
                        port['port']['network_id'],
                        port['port']['id'] + '-ipv4')

    def test_dhcp_binding_with_update_port_delete_ip(self):
        # Test if DHCP binding is deleted when the IP of the associated
        # compute port is deleted.
        with mock.patch('vmware_nsxlib.v3.policy.core_resources.'
                        'SegmentDhcpStaticBindingConfigApi.'
                        'delete') as delete_dhcp_binding:
            with self.subnet(enable_dhcp=True) as subnet:
                device_owner = constants.DEVICE_OWNER_COMPUTE_PREFIX + 'None'
                device_id = uuidutils.generate_uuid()
                with self.port(subnet=subnet, device_owner=device_owner,
                               device_id=device_id) as port:
                    data = {'port': {'fixed_ips': [],
                                     'admin_state_up': False,
                                     secgrp.SECURITYGROUPS: []}}
                    self.plugin.update_port(
                        context.get_admin_context(), port['port']['id'], data)
                    delete_dhcp_binding.assert_called_with(
                        port['port']['network_id'],
                        port['port']['id'] + '-ipv4')

    def test_dhcp_binding_with_update_port_ip(self):
        # Test if DHCP binding is updated when the IP of the associated
        # compute port is changed.
        with self.subnet(cidr='10.0.0.0/24', enable_dhcp=True) as subnet:
            port_data = {'fixed_ips': [{'subnet_id': subnet['subnet']['id'],
                                        'ip_address': '10.0.0.3'}]}
            new_ip = '10.0.0.4'
            update_data = {'port': {'fixed_ips': [
                {'subnet_id': subnet['subnet']['id'], 'ip_address': new_ip}]}}
            assert_data = {'host_name': 'host-%s' % new_ip.replace('.', '-'),
                           'ip_address': new_ip,
                           'options': {'option121': {'static_routes': [
                               {'network': '%s' %
                                cfg.CONF.nsx_p.native_metadata_route,
                                'next_hop': '0.0.0.0'},
                               {'network': '%s' %
                                cfg.CONF.nsx_p.native_metadata_route,
                                'next_hop': new_ip},
                               {'network': subnet['subnet']['cidr'],
                                'next_hop': '0.0.0.0'},
                               {'network': constants.IPv4_ANY,
                                'next_hop': subnet['subnet']['gateway_ip']}]}}}
            self._verify_dhcp_binding(subnet, port_data, update_data,
                                      assert_data)

    def test_dhcp_binding_v6_with_update_port_ip(self):
        # Test if DHCP binding is updated when the IP of the associated
        # compute port is changed.
        with self.subnet(ip_version=6, cidr='101::/64',
                         enable_dhcp=True) as subnet:
            port_data = {'fixed_ips': [{'subnet_id': subnet['subnet']['id'],
                                        'ip_address': '101::3'}]}
            new_ip = '101::4'
            update_data = {'port': {'fixed_ips': [
                {'subnet_id': subnet['subnet']['id'], 'ip_address': new_ip}]}}
            assert_data = {'ip_addresses': [new_ip]}
            self._verify_dhcp_binding_v6(subnet, port_data, update_data,
                                         assert_data)

    def test_dhcp_binding_with_update_port_mac(self):
        # Test if DHCP binding is updated when the Mac of the associated
        # compute port is changed.
        with self.subnet(enable_dhcp=True) as subnet:
            port_data = {'mac_address': '11:22:33:44:55:66'}
            new_mac = '22:33:44:55:66:77'
            update_data = {'port': {'mac_address': new_mac}}
            assert_data = {'mac_address': new_mac,
                           'options': {'option121': {'static_routes': [
                               {'network': '%s' %
                                cfg.CONF.nsx_p.native_metadata_route,
                                'next_hop': '0.0.0.0'},
                               {'network': '%s' %
                                cfg.CONF.nsx_p.native_metadata_route,
                                'next_hop': mock.ANY},
                               {'network': subnet['subnet']['cidr'],
                                'next_hop': '0.0.0.0'},
                               {'network': constants.IPv4_ANY,
                                'next_hop': subnet['subnet']['gateway_ip']}]}}}
            self._verify_dhcp_binding(subnet, port_data, update_data,
                                      assert_data)

    def test_dhcp_binding_with_update_port_mac_ip(self):
        # Test if DHCP binding is updated when the IP and Mac of the associated
        # compute port are changed at the same time.
        with self.subnet(cidr='10.0.0.0/24', enable_dhcp=True) as subnet:
            port_data = {'mac_address': '11:22:33:44:55:66',
                         'fixed_ips': [{'subnet_id': subnet['subnet']['id'],
                                        'ip_address': '10.0.0.3'}]}
            new_mac = '22:33:44:55:66:77'
            new_ip = '10.0.0.4'
            update_data = {'port': {'mac_address': new_mac, 'fixed_ips': [
                {'subnet_id': subnet['subnet']['id'], 'ip_address': new_ip}]}}
            assert_data = {'host_name': 'host-%s' % new_ip.replace('.', '-'),
                           'mac_address': new_mac,
                           'ip_address': new_ip,
                           'options': {'option121': {'static_routes': [
                               {'network': '%s' %
                                cfg.CONF.nsx_p.native_metadata_route,
                                'next_hop': '0.0.0.0'},
                               {'network': '%s' %
                                cfg.CONF.nsx_p.native_metadata_route,
                                'next_hop': new_ip},
                               {'network': subnet['subnet']['cidr'],
                                'next_hop': '0.0.0.0'},
                               {'network': constants.IPv4_ANY,
                                'next_hop': subnet['subnet']['gateway_ip']}]}}}
            self._verify_dhcp_binding(subnet, port_data, update_data,
                                      assert_data)

    def test_update_port_with_update_dhcp_opt(self):
        # Test updating extra-dhcp-opts via port update.
        with self.subnet(cidr='10.0.0.0/24', enable_dhcp=True) as subnet:
            mac_address = '11:22:33:44:55:66'
            ip_addr = '10.0.0.3'
            port_data = {'arg_list': ('extra_dhcp_opts',),
                         'mac_address': mac_address,
                         'fixed_ips': [{'subnet_id': subnet['subnet']['id'],
                                        'ip_address': ip_addr}],
                         'extra_dhcp_opts': [
                              {'opt_name': 'interface-mtu',
                               'opt_value': '9000'}]}
            update_data = {'port': {'extra_dhcp_opts': [
                              {'opt_name': 'interface-mtu',
                               'opt_value': '9002'}]}}
            assert_data = {'mac_address': mac_address,
                           'ip_address': ip_addr,
                           'options': {'option121': {'static_routes': [
                               {'network': '%s' %
                                cfg.CONF.nsx_p.native_metadata_route,
                                'next_hop': '0.0.0.0'},
                               {'network': '%s' %
                                cfg.CONF.nsx_p.native_metadata_route,
                                'next_hop': ip_addr},
                               {'network': subnet['subnet']['cidr'],
                                'next_hop': '0.0.0.0'},
                               {'network': constants.IPv4_ANY,
                                'next_hop': subnet['subnet']['gateway_ip']}]},
                                'others': [{'code': 26, 'values': ['9002']}]}}
            self._verify_dhcp_binding(subnet, port_data, update_data,
                                      assert_data)

    def test_update_port_with_adding_dhcp_opt(self):
        # Test adding extra-dhcp-opts via port update.
        with self.subnet(cidr='10.0.0.0/24', enable_dhcp=True) as subnet:
            mac_address = '11:22:33:44:55:66'
            ip_addr = '10.0.0.3'
            port_data = {'arg_list': ('extra_dhcp_opts',),
                         'mac_address': mac_address,
                         'fixed_ips': [{'subnet_id': subnet['subnet']['id'],
                                        'ip_address': ip_addr}],
                         'extra_dhcp_opts': [
                              {'opt_name': 'nis-domain',
                               'opt_value': 'abc'}]}
            update_data = {'port': {'extra_dhcp_opts': [
                              {'opt_name': 'interface-mtu',
                               'opt_value': '9002'}]}}
            assert_data = {'mac_address': mac_address,
                           'ip_address': ip_addr,
                           'options': {'option121': {'static_routes': [
                               {'network': '%s' %
                                cfg.CONF.nsx_p.native_metadata_route,
                                'next_hop': '0.0.0.0'},
                               {'network': '%s' %
                                cfg.CONF.nsx_p.native_metadata_route,
                                'next_hop': ip_addr},
                               {'network': subnet['subnet']['cidr'],
                                'next_hop': '0.0.0.0'},
                               {'network': constants.IPv4_ANY,
                                'next_hop': subnet['subnet']['gateway_ip']}]},
                                'others': [{'code': 26, 'values': ['9002']},
                                           {'code': 40, 'values': ['abc']}]}}
            self._verify_dhcp_binding(subnet, port_data, update_data,
                                      assert_data)

    def test_update_port_with_deleting_dhcp_opt(self):
        # Test adding extra-dhcp-opts via port update.
        with self.subnet(cidr='10.0.0.0/24', enable_dhcp=True) as subnet:
            mac_address = '11:22:33:44:55:66'
            ip_addr = '10.0.0.3'
            port_data = {'arg_list': ('extra_dhcp_opts',),
                         'mac_address': mac_address,
                         'fixed_ips': [{'subnet_id': subnet['subnet']['id'],
                                        'ip_address': ip_addr}],
                         'extra_dhcp_opts': [
                              {'opt_name': 'interface-mtu',
                               'opt_value': '9002'},
                              {'opt_name': 'nis-domain',
                               'opt_value': 'abc'}]}
            update_data = {'port': {'extra_dhcp_opts': [
                              {'opt_name': 'interface-mtu',
                               'opt_value': None}]}}
            assert_data = {'mac_address': mac_address,
                           'ip_address': ip_addr,
                           'options': {'option121': {'static_routes': [
                               {'network': '%s' %
                                cfg.CONF.nsx_p.native_metadata_route,
                                'next_hop': '0.0.0.0'},
                               {'network': '%s' %
                                cfg.CONF.nsx_p.native_metadata_route,
                                'next_hop': ip_addr},
                               {'network': subnet['subnet']['cidr'],
                                'next_hop': '0.0.0.0'},
                               {'network': constants.IPv4_ANY,
                                'next_hop': subnet['subnet']['gateway_ip']}]},
                                'others': [{'code': 40, 'values': ['abc']}]}}
            self._verify_dhcp_binding(subnet, port_data, update_data,
                                      assert_data)

    def test_dhcp_binding_with_update_port_name(self):
        # Test if DHCP binding is not updated when the name of the associated
        # compute port is changed.
        with mock.patch('vmware_nsxlib.v3.policy.core_resources.'
                        'SegmentDhcpStaticBindingConfigApi.'
                        'create_or_overwrite_v4') as update_dhcp_binding:
            with self.subnet(cidr='10.0.0.0/24', enable_dhcp=True) as subnet:
                device_owner = constants.DEVICE_OWNER_COMPUTE_PREFIX + 'None'
                device_id = uuidutils.generate_uuid()
                with self.port(subnet=subnet, device_owner=device_owner,
                               device_id=device_id, name='abc') as port:
                    data = {'port': {'name': 'xyz'}}
                    update_dhcp_binding.reset_mock()
                    self.plugin.update_port(
                        context.get_admin_context(), port['port']['id'], data)
                    update_dhcp_binding.assert_not_called()

    def test_create_network_with_bad_az_hint(self):
        p = directory.get_plugin()
        ctx = context.get_admin_context()
        data = {'network': {
                'name': 'test-az',
                'tenant_id': self._tenant_id,
                'port_security_enabled': False,
                'admin_state_up': True,
                'shared': False,
                'availability_zone_hints': ['bad_hint']
                }}
        self.assertRaises(n_exc.NeutronException,
                          p.create_network,
                          ctx, data)

    def test_create_network_with_az_hint(self):
        p = directory.get_plugin()
        ctx = context.get_admin_context()

        data = {'network': {
                'name': 'test-az',
                'tenant_id': self._tenant_id,
                'port_security_enabled': False,
                'admin_state_up': True,
                'shared': False,
                'availability_zone_hints': [self._az_name]
                }}

        # network creation should succeed
        net = p.create_network(ctx, data)
        self.assertEqual([self._az_name],
                         net['availability_zone_hints'])
        self.assertEqual([self._az_name],
                         net['availability_zones'])

    def test_create_network_with_no_az_hint(self):
        p = directory.get_plugin()
        ctx = context.get_admin_context()

        data = {'network': {
                'name': 'test-az',
                'tenant_id': self._tenant_id,
                'port_security_enabled': False,
                'admin_state_up': True,
                'shared': False
                }}

        # network creation should succeed
        net = p.create_network(ctx, data)
        self.assertEqual([],
                         net['availability_zone_hints'])
        self.assertEqual([nsx_az.DEFAULT_NAME],
                         net['availability_zones'])

    def test_dhcp_service_with_create_az_network(self):
        # Test if DHCP service is disabled on a network when it is created.
        with self.network(availability_zone_hints=[self._az_name],
                          arg_list=('availability_zone_hints',)) as network:
            self._verify_dhcp_service(network['network']['id'],
                                      network['network']['tenant_id'], False)

    def test_dhcp_binding_with_create_az_port(self):
        # Test if DHCP binding is added when a compute port is created.
        with mock.patch('vmware_nsxlib.v3.policy.core_resources.'
                        'SegmentDhcpStaticBindingConfigApi.'
                        'create_or_overwrite_v4') as create_dhcp_binding:
            with self.network(
                availability_zone_hints=[self._az_name],
                arg_list=('availability_zone_hints',)) as network:
                with self.subnet(enable_dhcp=True, network=network) as subnet:
                    device_owner = constants.DEVICE_OWNER_COMPUTE_PREFIX + 'X'
                    device_id = uuidutils.generate_uuid()
                    with self.port(subnet=subnet, device_owner=device_owner,
                                   device_id=device_id) as port:
                        binding_name = self._bind_name(port)
                        ip = port['port']['fixed_ips'][0]['ip_address']
                        hostname = 'host-%s' % ip.replace('.', '-')
                        options = {'option121': {'static_routes': [
                            {'network': '%s' %
                             self.az_metadata_route,
                             'next_hop': '0.0.0.0'},
                            {'network': '%s' %
                             self.az_metadata_route,
                             'next_hop': ip},
                            {'network': subnet['subnet']['cidr'],
                             'next_hop': '0.0.0.0'},
                            {'network': '0.0.0.0/0',
                             'next_hop': subnet['subnet']['gateway_ip']}]}}
                        create_dhcp_binding.assert_called_once_with(
                            binding_name, subnet['subnet']['network_id'],
                            binding_id=port['port']['id'] + '-ipv4',
                            mac_address=port['port']['mac_address'],
                            ip_address=ip,
                            host_name=hostname,
                            lease_time=cfg.CONF.nsx_p.dhcp_lease_time,
                            options=options,
                            gateway_address=subnet['subnet']['gateway_ip'])

    def test_create_subnet_with_dhcp_port(self):
        with self.subnet(enable_dhcp=True) as subnet:
            # find the dhcp port and verify it has port security disabled
            ports = self.plugin.get_ports(
                context.get_admin_context())
            self.assertEqual(1, len(ports))
            self.assertEqual('network:dhcp', ports[0]['device_owner'])
            self.assertEqual(subnet['subnet']['network_id'],
                             ports[0]['network_id'])
            self.assertEqual(False, ports[0]['port_security_enabled'])

    def test_create_dhcp_subnet_with_rtr_if(self):
        # Test that cannot create a DHCP subnet if a router interface exists
        dummy_port = {'fixed_ips': [{'subnet_id': 'dummy'}]}
        with mock.patch.object(self.plugin, 'get_ports',
                               return_value=[dummy_port]),\
            self.network() as net:
            subnet = self._make_subnet_data(
                network_id=net['network']['id'], cidr='10.0.0.0/24',
                tenant_id=net['network']['tenant_id'])
            self.assertRaises(
                n_exc.InvalidInput, self.plugin.create_subnet,
                context.get_admin_context(), subnet)

    def test_update_dhcp_subnet_with_rtr_if(self):
        # Test that cannot enable a DHCP on a subnet if a router interface
        # exists
        dummy_port = {'fixed_ips': [{'subnet_id': 'dummy'}]}
        with mock.patch.object(self.plugin, 'get_ports',
                               return_value=[dummy_port]),\
            self.network() as net:
            subnet = self._make_subnet_data(
                network_id=net['network']['id'], cidr='10.0.0.0/24',
                tenant_id=net['network']['tenant_id'], enable_dhcp=False)
            neutron_subnet = self.plugin.create_subnet(
                context.get_admin_context(), subnet)
            self.assertRaises(
                n_exc.InvalidInput, self.plugin.update_subnet,
                context.get_admin_context(), neutron_subnet['id'],
                {'subnet': {'enable_dhcp': True}})

    def test_create_subnet_with_dhcp_v6_port(self):
        with self.subnet(enable_dhcp=True, ip_version=6,
                         cidr="2002::/64") as subnet:
            # find the dhcp port and verify it has port security disabled
            ports = self.plugin.get_ports(
                context.get_admin_context())
            self.assertEqual(1, len(ports))
            self.assertEqual('network:dhcp', ports[0]['device_owner'])
            self.assertEqual(subnet['subnet']['network_id'],
                             ports[0]['network_id'])
            self.assertEqual(False, ports[0]['port_security_enabled'])


class NsxPolicyMetadataTestCase(test_plugin.NsxPPluginTestCaseMixin):
    """Test native metadata config when using MP MDProxy"""

    def setUp(self):
        self._orig_dhcp_agent_notification = cfg.CONF.dhcp_agent_notification
        cfg.CONF.set_override('dhcp_agent_notification', False)
        super(NsxPolicyMetadataTestCase, self).setUp()
        self._az_name = 'zone1'
        self._az_metadata_proxy = 'dummy'
        set_az_in_config(self._az_name, metadata_proxy=self._az_metadata_proxy)
        self._initialize_azs()
        self.plugin._init_dhcp_metadata()

        # make sure the plugin does not wait for segment realization
        self.realization_patcher = mock.patch.object(
            self.plugin, '_get_network_nsx_id', side_effect=Exception)
        self.realization_patcher.start()

    def tearDown(self):
        self.realization_patcher.stop()
        cfg.CONF.set_override('dhcp_agent_notification',
                              self._orig_dhcp_agent_notification)
        super(NsxPolicyMetadataTestCase, self).tearDown()

    def test_metadata_proxy_configuration(self):
        # Test if dhcp_agent_notification and metadata_proxy are
        # configured correctly.
        orig_dhcp_agent_notification = cfg.CONF.dhcp_agent_notification
        cfg.CONF.set_override('dhcp_agent_notification', True)
        self.assertRaises(nsx_exc.NsxPluginException,
                          self.plugin._init_dhcp_metadata)
        cfg.CONF.set_override('dhcp_agent_notification',
                              orig_dhcp_agent_notification)
        orig_metadata_proxy_uuid = cfg.CONF.nsx_p.metadata_proxy
        cfg.CONF.set_override('metadata_proxy', '', 'nsx_p')
        self.assertRaises(cfg.RequiredOptError,
                          self.plugin._init_default_config)
        cfg.CONF.set_override('metadata_proxy', orig_metadata_proxy_uuid,
                              'nsx_p')

    def test_metadata_proxy_with_create_network(self):
        # Test if native metadata proxy is enabled on a network when it is
        # created (Using Policy MDproxy).
        self.plugin._availability_zones_data._default_az.use_policy_md = True
        with mock.patch.object(nsx_resources.NsxPolicySegmentApi,
                               'create_or_overwrite') as create:
            with self.network() as network:
                create.assert_called_once_with(
                    mock.ANY,
                    segment_id=network['network']['id'],
                    description=mock.ANY,
                    vlan_ids=mock.ANY,
                    transport_zone_id=mock.ANY,
                    tags=mock.ANY,
                    metadata_proxy_id=test_plugin.NSX_MD_PROXY_ID)

    def test_metadata_proxy_with_create_az_network(self):
        # Test if native metadata proxy is enabled on a network when it is
        # created (Using Plolicy MDproxy).
        azs = self.plugin._availability_zones_data.availability_zones
        azs[self._az_name].use_policy_md = True
        with mock.patch.object(nsx_resources.NsxPolicySegmentApi,
                               'create_or_overwrite') as create:
            with self.network(
                availability_zone_hints=[self._az_name],
                arg_list=('availability_zone_hints',)) as network:
                create.assert_called_once_with(
                    mock.ANY,
                    segment_id=network['network']['id'],
                    description=mock.ANY,
                    vlan_ids=mock.ANY,
                    transport_zone_id=mock.ANY,
                    tags=mock.ANY,
                    metadata_proxy_id='dummy')

    def test_metadata_proxy_with_get_subnets(self):
        # Test if get_subnets() handles advanced-service-provider extension,
        # which is used when processing metadata requests.
        self.plugin._availability_zones_data._default_az.use_policy_md = True
        with self.network() as n1, self.network() as n2:
            with self.subnet(network=n1, enable_dhcp=False) as s1, \
                self.subnet(network=n2, enable_dhcp=False) as s2:
                # Get all the subnets.
                subnets = self._list('subnets')['subnets']
                self.assertEqual(len(subnets), 2)
                self.assertEqual(set([s['id'] for s in subnets]),
                                 set([s1['subnet']['id'], s2['subnet']['id']]))
                lswitch_id = uuidutils.generate_uuid()
                neutron_id = n1['network']['id']
                segment_path = '/infra/segments/%s' % neutron_id
                # Get only the subnets associated with a particular advanced
                # service provider (i.e. logical switch).
                with mock.patch('vmware_nsxlib.v3.policy.NsxPolicyLib.'
                                'search_resource_by_realized_id',
                                return_value=[segment_path]):
                    subnets = self._list('subnets', query_params='%s=%s' %
                                         (as_providers.ADV_SERVICE_PROVIDERS,
                                          lswitch_id))['subnets']
                    self.assertEqual(len(subnets), 1)
                    self.assertEqual(subnets[0]['id'], s1['subnet']['id'])
