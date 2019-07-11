# Copyright (c) 2019 OpenStack Foundation.
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

from vmware_nsx.extensions import api_replay
from vmware_nsx.tests.unit.nsx_p import test_plugin

from neutron_lib.api import attributes
from neutron_lib.plugins import directory
from oslo_config import cfg


class TestApiReplay(test_plugin.NsxPTestL3NatTest):

    def setUp(self, plugin=None, ext_mgr=None, service_plugins=None):
        # enables api_replay_mode for these tests
        cfg.CONF.set_override('api_replay_mode', True)

        super(TestApiReplay, self).setUp()

    def tearDown(self):
        # disables api_replay_mode for these tests
        cfg.CONF.set_override('api_replay_mode', False)

        # remove the extension from the plugin
        directory.get_plugin().supported_extension_aliases.remove(
            api_replay.ALIAS)

        # Revert the attributes map back to normal
        for attr_name in ('ports', 'networks', 'security_groups',
                          'security_group_rules', 'routers', 'policies'):
            attr_info = attributes.RESOURCES[attr_name]
            attr_info['id']['allow_post'] = False

        super(TestApiReplay, self).tearDown()

    def test_create_port_specify_id(self):
        specified_network_id = '555e762b-d7a1-4b44-b09b-2a34ada56c9f'
        specified_port_id = 'e55e762b-d7a1-4b44-b09b-2a34ada56c9f'
        network_res = self._create_network(self.fmt,
                                           'test-network',
                                           True,
                                           arg_list=('id',),
                                           id=specified_network_id)
        network = self.deserialize(self.fmt, network_res)
        self.assertEqual(specified_network_id, network['network']['id'])
        port_res = self._create_port(self.fmt,
                                     network['network']['id'],
                                     arg_list=('id',),
                                     id=specified_port_id)
        port = self.deserialize(self.fmt, port_res)
        self.assertEqual(specified_port_id, port['port']['id'])

    def _create_router(self, fmt, tenant_id, name=None,
                       admin_state_up=None,
                       arg_list=None, **kwargs):
        data = {'router': {'tenant_id': tenant_id}}
        if name:
            data['router']['name'] = name
        if admin_state_up:
            data['router']['admin_state_up'] = admin_state_up
        for arg in (('admin_state_up', 'tenant_id') + (arg_list or ())):
            # Arg must be present and not empty
            if kwargs.get(arg):
                data['router'][arg] = kwargs[arg]
        router_req = self.new_create_request('routers', data, fmt)
        return router_req.get_response(self.ext_api)

    def test_create_update_router(self):
        specified_router_id = '555e762b-d7a1-4b44-b09b-2a34ada56c9f'
        router_res = self._create_router(self.fmt,
                                         'test-tenant',
                                         'test-rtr',
                                         arg_list=('id',),
                                         id=specified_router_id)
        router = self.deserialize(self.fmt, router_res)
        self.assertEqual(specified_router_id, router['router']['id'])

        # This part tests _fixup_res_dict as well
        body = self._update('routers', specified_router_id,
                            {'router': {'name': 'new_name'}})
        body = self._show('routers', specified_router_id)
        self.assertEqual(body['router']['name'], 'new_name')
