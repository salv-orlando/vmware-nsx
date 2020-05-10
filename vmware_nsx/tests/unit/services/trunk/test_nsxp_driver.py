# Copyright (c) 2016 VMware, Inc.
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

from neutron.tests import base

from neutron_lib import context
from oslo_utils import importutils

from vmware_nsx.extensions import projectpluginmap
from vmware_nsx.services.trunk.nsx_p import driver as trunk_driver
from vmware_nsx.tests.unit.nsx_p import test_plugin as test_nsx_p_plugin

PLUGIN_NAME = 'vmware_nsx.plugins.nsx_p.plugin.NsxPolicyPlugin'


class TestNsxpTrunkHandler(test_nsx_p_plugin.NsxPPluginTestCaseMixin,
                           base.BaseTestCase):

    def _get_port_compute_tags_and_net(self, context, port_id):
        return True, 'net_' + port_id[-1:], []

    def setUp(self):
        super(TestNsxpTrunkHandler, self).setUp()
        self.context = context.get_admin_context()
        self.core_plugin = importutils.import_object(PLUGIN_NAME)
        self.handler = trunk_driver.NsxpTrunkHandler(self.core_plugin)
        self.handler._get_port_compute_tags_and_net = mock.Mock(
            side_effect=self._get_port_compute_tags_and_net)
        self.trunk_1 = mock.Mock()
        self.trunk_1.port_id = "parent_port_1"
        self.trunk_1.id = "trunk_1_id"

        self.trunk_2 = mock.Mock()
        self.trunk_2.port_id = "parent_port_2"

        self.sub_port_a = mock.Mock()
        self.sub_port_a.segmentation_id = 40
        self.sub_port_a.trunk_id = "trunk-1"
        self.sub_port_a.port_id = "sub_port_a"
        self.sub_port_a.segmentation_type = 'vlan'

        self.sub_port_b = mock.Mock()
        self.sub_port_b.segmentation_id = 41
        self.sub_port_b.trunk_id = "trunk-2"
        self.sub_port_b.port_id = "sub_port_b"
        self.sub_port_b.segmentation_type = 'vlan'

        self.sub_port_c = mock.Mock()
        self.sub_port_c.segmentation_id = 43
        self.sub_port_c.trunk_id = "trunk-2"
        self.sub_port_c.port_id = "sub_port_c"
        self.sub_port_c.segmentation_type = 'vlan'

    def test_trunk_created(self):
        # Create trunk with no subport
        self.trunk_1.sub_ports = []
        with mock.patch.object(
                self.handler.plugin_driver.nsxpolicy.segment_port,
                'attach') as m_attach:
            self.handler.trunk_created(self.context, self.trunk_1)
            m_attach.assert_called_with(
                'net_1', self.trunk_1.port_id, attachment_type='PARENT',
                tags=[{'tag': self.trunk_1.id,
                       'scope': 'os-neutron-trunk-id'}],
                vif_id=self.trunk_1.port_id)

        # Create trunk with 1 subport
        self.trunk_1.sub_ports = [self.sub_port_a]
        with mock.patch.object(
                self.handler.plugin_driver.nsxpolicy.segment_port,
                'attach') as m_attach:
            self.handler.trunk_created(self.context, self.trunk_1)
            calls = [
                mock.call.m_attach(
                    'net_1', self.trunk_1.port_id, attachment_type='PARENT',
                    tags=[{'tag': self.trunk_1.id,
                           'scope': 'os-neutron-trunk-id'}],
                    vif_id=self.trunk_1.port_id),
                mock.call.m_attach(
                    'net_a', self.sub_port_a.port_id, 'CHILD',
                    self.sub_port_a.port_id,
                    context_id=self.trunk_1.port_id,
                    tags=[{'tag': self.sub_port_a.trunk_id,
                           'scope': 'os-neutron-trunk-id'}],
                    traffic_tag=self.sub_port_a.segmentation_id)]
            m_attach.assert_has_calls(calls, any_order=True)

        # Create trunk with multiple subports
        self.trunk_2.sub_ports = [self.sub_port_b, self.sub_port_c]
        with mock.patch.object(
                self.handler.plugin_driver.nsxpolicy.segment_port,
                'attach') as m_attach:
            self.handler.trunk_created(self.context, self.trunk_2)
            calls = [
                mock.call.m_attach(
                    'net_2', self.trunk_2.port_id, attachment_type='PARENT',
                    tags=[{'tag': self.trunk_2.id,
                           'scope': 'os-neutron-trunk-id'}],
                    vif_id=self.trunk_2.port_id),
                mock.call.m_attach(
                    'net_b', self.sub_port_b.port_id, 'CHILD',
                    self.sub_port_b.port_id,
                    context_id=self.trunk_2.port_id,
                    tags=[{'tag': self.sub_port_b.trunk_id,
                           'scope': 'os-neutron-trunk-id'}],
                    traffic_tag=self.sub_port_b.segmentation_id),
                mock.call.m_attach(
                    'net_c', self.sub_port_c.port_id, 'CHILD',
                    self.sub_port_c.port_id,
                    context_id=self.trunk_2.port_id,
                    tags=[{'tag': self.sub_port_c.trunk_id,
                           'scope': 'os-neutron-trunk-id'}],
                    traffic_tag=self.sub_port_c.segmentation_id)]
            m_attach.assert_has_calls(calls, any_order=True)

    def test_trunk_deleted(self):
        # Delete trunk with no subport
        self.trunk_1.sub_ports = []
        with mock.patch.object(
                self.handler.plugin_driver.nsxpolicy.segment_port,
                'detach') as m_detach:
            self.handler.trunk_deleted(self.context, self.trunk_1)
            m_detach.assert_called_with(
                'net_1', self.trunk_1.port_id, vif_id=self.trunk_1.port_id,
                tags=mock.ANY)

        # Delete trunk with 1 subport
        self.trunk_1.sub_ports = [self.sub_port_a]
        with mock.patch.object(
                self.handler.plugin_driver.nsxpolicy.segment_port,
                'detach') as m_detach:
            self.handler.trunk_deleted(self.context, self.trunk_1)
            calls = [
                mock.call.m_detach(
                    'net_1', self.trunk_1.port_id,
                    vif_id=self.trunk_1.port_id, tags=mock.ANY),
                mock.call.m_detach(
                    'net_a', self.sub_port_a.port_id,
                    vif_id=self.sub_port_a.port_id, tags=mock.ANY)]
            m_detach.assert_has_calls(calls, any_order=True)

        # Delete trunk with multiple subports
        self.trunk_2.sub_ports = [self.sub_port_b, self.sub_port_c]
        with mock.patch.object(
                self.handler.plugin_driver.nsxpolicy.segment_port,
                'detach') as m_detach:
            self.handler.trunk_deleted(self.context, self.trunk_2)
            calls = [
                mock.call.m_detach(
                    'net_2', self.trunk_2.port_id,
                    vif_id=self.trunk_2.port_id, tags=mock.ANY),
                mock.call.m_detach(
                    'net_b', self.sub_port_b.port_id,
                    vif_id=self.sub_port_b.port_id, tags=mock.ANY),
                mock.call.m_detach(
                    'net_c', self.sub_port_c.port_id,
                    vif_id=self.sub_port_c.port_id, tags=mock.ANY)]
            m_detach.assert_has_calls(calls, any_order=True)

    def test_subports_added(self):
        # Update trunk with no subport
        sub_ports = []
        with mock.patch.object(
                self.handler.plugin_driver.nsxpolicy.segment_port,
                'attach') as m_attach:
            self.handler.subports_added(self.context, self.trunk_1, sub_ports)
            m_attach.assert_not_called()

        # Update trunk with 1 subport
        sub_ports = [self.sub_port_a]
        with mock.patch.object(
                self.handler.plugin_driver.nsxpolicy.segment_port,
                'attach') as m_attach:
            self.handler.subports_added(self.context, self.trunk_1, sub_ports)
        m_attach.assert_called_with(
            'net_a', self.sub_port_a.port_id, 'CHILD',
            self.sub_port_a.port_id,
            context_id=self.trunk_1.port_id,
            tags=[{'tag': self.sub_port_a.trunk_id,
                   'scope': 'os-neutron-trunk-id'}],
            traffic_tag=self.sub_port_a.segmentation_id)

        # Update trunk with multiple subports
        sub_ports = [self.sub_port_b, self.sub_port_c]
        with mock.patch.object(
                self.handler.plugin_driver.nsxpolicy.segment_port,
                'attach') as m_attach:
            self.handler.subports_added(self.context, self.trunk_2, sub_ports)
            calls = [
                mock.call.m_attach(
                    'net_b', self.sub_port_b.port_id, 'CHILD',
                    self.sub_port_b.port_id,
                    context_id=self.trunk_2.port_id,
                    tags=[{'tag': self.sub_port_b.trunk_id,
                           'scope': 'os-neutron-trunk-id'}],
                    traffic_tag=self.sub_port_b.segmentation_id),
                mock.call.m_attach(
                    'net_c', self.sub_port_c.port_id, 'CHILD',
                    self.sub_port_c.port_id,
                    context_id=self.trunk_2.port_id,
                    tags=[{'tag': self.sub_port_c.trunk_id,
                           'scope': 'os-neutron-trunk-id'}],
                    traffic_tag=self.sub_port_c.segmentation_id)]
            m_attach.assert_has_calls(calls, any_order=True)

    def test_subports_deleted(self):
        # Update trunk to remove no subport
        sub_ports = []
        with mock.patch.object(
                self.handler.plugin_driver.nsxpolicy.segment_port,
                'detach') as m_detach:
            self.handler.subports_deleted(
                self.context, self.trunk_1, sub_ports)
            m_detach.assert_not_called()

        # Update trunk to remove 1 subport
        sub_ports = [self.sub_port_a]
        with mock.patch.object(
                self.handler.plugin_driver.nsxpolicy.segment_port,
                'detach') as m_detach:
            self.handler.subports_deleted(
                self.context, self.trunk_1, sub_ports)
            m_detach.assert_called_with(
                'net_a', self.sub_port_a.port_id,
                vif_id=self.sub_port_a.port_id, tags=mock.ANY)

        # Update trunk to remove multiple subports
        sub_ports = [self.sub_port_b, self.sub_port_c]
        with mock.patch.object(
                self.handler.plugin_driver.nsxpolicy.segment_port,
                'detach') as m_detach:
            self.handler.subports_deleted(
                self.context, self.trunk_2, sub_ports)
            calls = [
                mock.call.m_detach(
                    'net_b', self.sub_port_b.port_id,
                    vif_id=self.sub_port_b.port_id, tags=mock.ANY),
                mock.call.m_detach(
                    'net_c', self.sub_port_c.port_id,
                    vif_id=self.sub_port_c.port_id, tags=mock.ANY)]
            m_detach.assert_has_calls(calls, any_order=True)


class TestNsxpTrunkDriver(base.BaseTestCase):
    def setUp(self):
        super(TestNsxpTrunkDriver, self).setUp()

    def test_is_loaded(self):
        core_plugin = mock.Mock()
        driver = trunk_driver.NsxpTrunkDriver.create(core_plugin)
        with mock.patch.object(core_plugin, 'plugin_type',
                               return_value=projectpluginmap.NsxPlugins.NSX_P):
            self.assertTrue(driver.is_loaded)

        with mock.patch.object(core_plugin, 'plugin_type',
                               return_value=projectpluginmap.NsxPlugins.NSX_T):
            self.assertFalse(driver.is_loaded)
