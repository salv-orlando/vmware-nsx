# Copyright (c) 2013 OpenStack Foundation.
# All Rights Reserved.
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

from neutron.extensions import agent
from neutron_lib import context
from oslo_config import cfg

from vmware_nsx.tests import unit as vmware
from vmware_nsx.tests.unit.nsx_v3 import test_plugin as test_nsxv3
from vmware_nsx.tests.unit import test_utils


class MacLearningExtensionManager(object):

    def get_resources(self):
        return agent.Agent.get_resources()

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


class MacLearningDBTestCase(test_nsxv3.NsxV3PluginTestCaseMixin):
    fmt = 'json'

    def setUp(self):
        test_utils.override_nsx_ini_full_test()
        cfg.CONF.set_override('api_extensions_path', vmware.NSXEXT_PATH)
        ext_mgr = MacLearningExtensionManager()
        cfg.CONF.set_override('metadata_mode', None, 'NSX')
        super(MacLearningDBTestCase, self).setUp(plugin=vmware.PLUGIN_NAME,
                                                 ext_mgr=ext_mgr)
        self.adminContext = context.get_admin_context()

    def test_create_with_mac_learning(self):
        with self.port(arg_list=('mac_learning_enabled',
                                 'port_security_enabled'),
                       mac_learning_enabled=True,
                       port_security_enabled=False) as port:
            # Validate create operation response
            self.assertEqual(True, port['port']['mac_learning_enabled'])
            # Verify that db operation successfully set mac learning state
            req = self.new_show_request('ports', port['port']['id'], self.fmt)
            sport = self.deserialize(self.fmt, req.get_response(self.api))
            self.assertEqual(True, sport['port']['mac_learning_enabled'])

    def test_create_and_show_port_without_mac_learning(self):
        with self.port() as port:
            req = self.new_show_request('ports', port['port']['id'], self.fmt)
            sport = self.deserialize(self.fmt, req.get_response(self.api))
            self.assertNotIn('mac_learning_enabled', sport['port'])

    def test_update_port_with_mac_learning(self):
        with self.port(arg_list=('mac_learning_enabled',
                                 'port_security_enabled'),
                       mac_learning_enabled=False,
                       port_security_enabled=False) as port:
            data = {'port': {'mac_learning_enabled': True}}
            req = self.new_update_request('ports', data, port['port']['id'])
            res = self.deserialize(self.fmt, req.get_response(self.api))
            self.assertEqual(True, res['port']['mac_learning_enabled'])

    def test_update_preexisting_port_with_mac_learning(self):
        with self.port(arg_list=('port_security_enabled',),
                       port_security_enabled=False) as port:
            req = self.new_show_request('ports', port['port']['id'], self.fmt)
            sport = self.deserialize(self.fmt, req.get_response(self.api))
            self.assertNotIn('mac_learning_enabled', sport['port'])
            data = {'port': {'mac_learning_enabled': True}}
            req = self.new_update_request('ports', data, port['port']['id'])
            # Validate update operation response
            res = self.deserialize(self.fmt, req.get_response(self.api))
            self.assertEqual(True, res['port']['mac_learning_enabled'])
            # Verify that db operation successfully updated mac learning state
            req = self.new_show_request('ports', port['port']['id'], self.fmt)
            sport = self.deserialize(self.fmt, req.get_response(self.api))
            self.assertEqual(True, sport['port']['mac_learning_enabled'])

    def test_list_ports(self):
        # for this test we need to enable overlapping ips
        cfg.CONF.set_default('allow_overlapping_ips', True)
        no_mac_learning_p = (lambda:
                             self.port(arg_list=('mac_learning_enabled',
                                                 'port_security_enabled'),
                                       mac_learning_enabled=True,
                                       port_security_enabled=False))

        with no_mac_learning_p(), no_mac_learning_p(), no_mac_learning_p():
            for port in self._list('ports')['ports']:
                self.assertEqual(True, port['mac_learning_enabled'])

    def test_show_port(self):
        with self.port(arg_list=('mac_learning_enabled',
                                 'port_security_enabled'),
                       mac_learning_enabled=True,
                       port_security_enabled=False) as p:
            port_res = self._show('ports', p['port']['id'])['port']
            self.assertEqual(True, port_res['mac_learning_enabled'])
