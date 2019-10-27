# Copyright 2013 VMware, Inc.
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

from neutron.db import models_v2
from neutron.tests.unit import testlib_api
from neutron_lib import context
from oslo_db import exception as d_exc

from vmware_nsx.db import db as nsx_db


class NsxDBTestCase(testlib_api.SqlTestCase):

    def setUp(self):
        super(NsxDBTestCase, self).setUp()
        self.ctx = context.get_admin_context()

    def _setup_neutron_network_and_port(self, network_id, port_id):
        with self.ctx.session.begin(subtransactions=True):
            self.ctx.session.add(models_v2.Network(id=network_id))
            port = models_v2.Port(id=port_id,
                                  network_id=network_id,
                                  mac_address='foo_mac_address',
                                  admin_state_up=True,
                                  status='ACTIVE',
                                  device_id='',
                                  device_owner='')
            self.ctx.session.add(port)

    def test_add_neutron_nsx_port_mapping_raise_integrity_constraint(self):
        neutron_port_id = 'foo_neutron_port_id'
        nsx_port_id = 'foo_nsx_port_id'
        nsx_switch_id = 'foo_nsx_switch_id'
        self.assertRaises(d_exc.DBError,
                          nsx_db.add_neutron_nsx_port_mapping,
                          self.ctx.session, neutron_port_id,
                          nsx_switch_id, nsx_port_id)