# Copyright 2015 VMware, Inc.
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

import abc

from unittest import mock

from oslo_config import cfg
from oslo_log import _options
from oslo_log import log as logging
from oslo_utils import uuidutils

from neutron.common import config as neutron_config
from neutron.db import servicetype_db  # noqa
from neutron.quota import resource_registry
from neutron.tests import base
from neutron_lib.callbacks import registry
from neutron_lib.plugins import constants

from vmware_nsx._i18n import _
from vmware_nsx.common import config  # noqa
from vmware_nsx.db import nsxv_db
from vmware_nsx.dvs import dvs_utils
from vmware_nsx.shell.admin.plugins.nsxp.resources import utils as nsxp_utils
from vmware_nsx.shell.admin.plugins.nsxv.resources import migration
from vmware_nsx.shell.admin.plugins.nsxv.resources import utils as nsxv_utils
from vmware_nsx.shell.admin.plugins.nsxv3.resources import utils as nsxv3_utils
from vmware_nsx.shell import resources
from vmware_nsx.tests import unit as vmware
from vmware_nsx.tests.unit.nsx_p import test_plugin as test_p_plugin
from vmware_nsx.tests.unit.nsx_v import test_plugin as test_v_plugin
from vmware_nsx.tests.unit.nsx_v3 import test_plugin as test_v3_plugin
from vmware_nsxlib.v3 import client as v3_client
from vmware_nsxlib.v3 import core_resources
from vmware_nsxlib.v3 import resources as nsx_v3_resources
from vmware_nsxlib.v3 import security as nsx_v3_security

LOG = logging.getLogger(__name__)
NSX_INI_PATH = vmware.get_fake_conf('nsx.ini.test')
BASE_CONF_PATH = vmware.get_fake_conf('neutron.conf.test')


class AbstractTestAdminUtils(base.BaseTestCase, metaclass=abc.ABCMeta):

    def setUp(self):
        cfg.CONF.unregister_opts(_options.common_cli_opts)
        cfg.CONF.register_cli_opts(resources.cli_opts)

        super(AbstractTestAdminUtils, self).setUp()

        # remove resource registration conflicts
        resource_registry.unregister_all_resources()

        self.edgeapi = nsxv_utils.NeutronDbClient()
        # Init the neutron config
        neutron_config.init(args=['--config-file', BASE_CONF_PATH,
                                  '--config-file', NSX_INI_PATH])
        self._init_mock_plugin()
        self._init_resource_plugin()
        self.addCleanup(resource_registry.unregister_all_resources)

    def _init_mock_plugin(self):
        mock_query = mock.patch(
            "vmware_nsx.shell.admin.plugins.common.utils.query_yes_no")
        mock_query.start()

    @abc.abstractmethod
    def _get_plugin_name(self):
        pass

    def _init_resource_plugin(self):
        plugin_name = self._get_plugin_name()
        resources.init_resource_plugin(
            plugin_name,
            resources.get_plugin_dir(plugin_name))

    def _test_resource(self, res_name, op, **kwargs):
        errors = self._test_resource_with_errors(res_name, op, **kwargs)
        if len(errors) > 0:
            msg = (_("admin util %(res)s/%(op)s failed with message: "
                     "%(err)s") % {'res': res_name,
                                   'op': op,
                                   'err': errors[0]})
            self.fail(msg=msg)

    def _test_resource_with_errors(self, res_name, op, **kwargs):
        # Must call the internal notify_loop in order to get the errors
        return registry._get_callback_manager()._notify_loop(
            res_name, op, 'nsxadmin', **kwargs)

    def _test_resources(self, res_dict):
        for res in res_dict.keys():
            res_name = res_dict[res].name
            for op in res_dict[res].supported_ops:
                self._test_resource(res_name, op)

    def _test_resources_with_args(self, res_dict, func_args):
        for res in res_dict.keys():
            res_name = res_dict[res].name
            for op in res_dict[res].supported_ops:
                args = {'property': func_args}
                self._test_resource(res_name, op, **args)

    def _create_router(self):
        tenant_id = uuidutils.generate_uuid()
        data = {'router': {'tenant_id': tenant_id}}
        data['router']['name'] = 'dummy'
        data['router']['admin_state_up'] = True
        return self._plugin.create_router(self.edgeapi.context, data)


class TestNsxvAdminUtils(AbstractTestAdminUtils,
                         test_v_plugin.NsxVPluginV2TestCase):

    def _get_plugin_name(self):
        return 'nsxv'

    def _init_mock_plugin(self, *mocks):
        super(TestNsxvAdminUtils, self)._init_mock_plugin()

        # support the dvs manager:
        mock.patch.object(dvs_utils, 'dvs_create_session').start()
        # override metadata get-object
        dummy_lb = {
            'enabled': True,
            'enableServiceInsertion': True,
            'accelerationEnabled': True,
            'virtualServer': [],
            'applicationProfile': [],
            'pool': [],
            'applicationRule': []
        }
        mock.patch('vmware_nsx.plugins.nsx_v.vshield.nsxv_edge_cfg_obj.'
                   'NsxvEdgeCfgObj.get_object',
                   return_value=dummy_lb).start()

        # Tests shouldn't wait for dummy spawn jobs to finish
        mock.patch('vmware_nsx.shell.admin.plugins.nsxv.resources.utils.'
                   'NsxVPluginWrapper.count_spawn_jobs',
                   return_value=0).start()

        self._plugin = nsxv_utils.NsxVPluginWrapper()

        def get_plugin_mock(alias=constants.CORE):
            if alias in (constants.CORE, constants.L3):
                return self._plugin

        mock.patch("neutron_lib.plugins.directory.get_plugin",
                   side_effect=get_plugin_mock).start()

        # Create a router to make sure we have deployed an edge
        self.router = self._create_router()
        self.dist_router = self._create_router(dist=True)
        self.network = self._create_net()

    def tearDown(self):
        if self.router and self.router.get('id'):
            self._plugin.delete_router(
                self.edgeapi.context, self.router['id'])
        if self.dist_router and self.dist_router.get('id'):
            self._plugin.delete_router(
                self.edgeapi.context, self.dist_router['id'])
        if self.network and self.network.get('id'):
            self._plugin.delete_network(
                self.edgeapi.context, self.network['id'])
        super(TestNsxvAdminUtils, self).tearDown()

    def test_nsxv_resources(self):
        self._test_resources(resources.nsxv_resources)

    def _test_edge_nsx_update(self, edge_id, params):
        args = {'property': ["edge-id=%s" % edge_id]}
        args['property'].extend(params)
        self._test_resource('edges', 'nsx-update', **args)

    def _create_router(self, dist=False):
        # Create an exclusive router (with an edge)
        tenant_id = uuidutils.generate_uuid()
        data = {'router': {'tenant_id': tenant_id}}
        data['router']['name'] = 'dummy'
        data['router']['admin_state_up'] = True
        if dist:
            data['router']['distributes'] = True
        else:
            data['router']['router_type'] = 'exclusive'

        return self._plugin.create_router(self.edgeapi.context, data)

    def _create_net(self):
        tenant_id = uuidutils.generate_uuid()
        data = {'network': {'tenant_id': tenant_id,
                            'name': 'dummy',
                            'admin_state_up': True,
                            'shared': False}}
        net = self._plugin.create_network(self.edgeapi.context, data)
        data = {'subnet': {'tenant_id': tenant_id,
                           'name': 'dummy',
                           'admin_state_up': True,
                           'network_id': net['id'],
                           'cidr': '1.1.1.0/16',
                           'enable_dhcp': True,
                           'ip_version': 4,
                           'dns_nameservers': None,
                           'host_routes': None,
                           'allocation_pools': None}}
        self._plugin.create_subnet(self.edgeapi.context, data)
        return net

    def get_edge_id(self):
        bindings = nsxv_db.get_nsxv_router_bindings(
            self.edgeapi.context.session)
        for binding in bindings:
            if binding.edge_id:
                return binding.edge_id
        # use a dummy edge
        return "edge-1"

    def test_edge_nsx_updates(self):
        """Test eges/nsx-update utility with different inputs."""
        edge_id = self.get_edge_id()
        self._test_edge_nsx_update(edge_id, ["appliances=true"])
        self._test_edge_nsx_update(edge_id, ["size=compact"])
        self._test_edge_nsx_update(edge_id, ["hostgroup=update"])
        self._test_edge_nsx_update(edge_id, ["hostgroup=all"])
        self._test_edge_nsx_update(edge_id, ["hostgroup=clean"])
        self._test_edge_nsx_update(edge_id, ["highavailability=True"])
        self._test_edge_nsx_update(edge_id, ["resource=cpu", "limit=100"])
        self._test_edge_nsx_update(edge_id, ["syslog-server=1.1.1.1",
                                             "syslog-proto=tcp",
                                             "log-level=debug"])

    def test_bad_args(self):
        args = {'property': ["xxx"]}
        errors = self._test_resource_with_errors(
            'networks', 'nsx-update', **args)
        self.assertEqual(1, len(errors))

    def test_resources_with_common_args(self):
        """Run all nsxv admin utilities with some common arguments

        Using arguments like edge-id which many apis need
        This improves the test coverage
        """
        edge_id = self.get_edge_id()
        args = ["edge-id=%s" % edge_id,
                "router-id=e5b9b249-0034-4729-8ab6-fe4dacaa3a12",
                "policy-id=1",
                "network_id=net-1",
                "net-id=net-1",
                "network=net-1",
                "port=port-1",
                "security-group-id=sg-1",
                "dvs-id=dvs-1",
                "moref=virtualwire-1",
                "teamingpolicy=LACP_ACTIVE",
                "log-allowed-traffic=true",
                "az-name=default",
                "transit-network=abc",
                "moref=abc",
                ]
        self._test_resources_with_args(
            resources.nsxv_resources, args)

    def test_router_recreate(self):
        # Testing router-recreate separately because it may change the edge-id
        edge_id = self.get_edge_id()
        args = {'property': ["edge-id=%s" % edge_id]}
        self._test_resource('routers', 'nsx-recreate', **args)

    def test_migration_validation(self):
        # check that validation fails
        args = {'property': ["transit-network=1.1.1.0/24"]}
        try:
            migration.validate_config_for_migration(
                'nsx-migrate-v2t', 'validate', None, **args)
        except SystemExit:
            return
        else:
            self.fail()


class TestNsxv3AdminUtils(AbstractTestAdminUtils,
                          test_v3_plugin.NsxV3PluginTestCaseMixin):

    def _patch_object(self, *args, **kwargs):
        patcher = mock.patch.object(*args, **kwargs)
        patcher.start()
        self._patchers.append(patcher)

    def _init_mock_plugin(self):
        test_v3_plugin._mock_nsx_backend_calls()

        # mock resources
        for cls in (nsx_v3_resources.LogicalPort,
                    nsx_v3_resources.LogicalDhcpServer,
                    core_resources.NsxLibLogicalRouter,
                    core_resources.NsxLibSwitchingProfile,
                    v3_client.RESTClient):
            self._patch_object(cls, 'list', return_value={'results': []})
            self._patch_object(cls, 'get',
                               return_value={'id': uuidutils.generate_uuid()})
            self._patch_object(cls, 'update')

        self._patch_object(core_resources.NsxLibSwitchingProfile,
                           'find_by_display_name',
                           return_value=[{'id': uuidutils.generate_uuid()}])
        self._patch_object(nsx_v3_security.NsxLibFirewallSection,
                           'get_excludelist',
                           return_value={'members': [{
                                'target_type': 'LogicalPort',
                                'target_id': 'port_id'}]})

        # Mocks for MP2P migration
        mock.patch("vmware_nsxlib.v3.NsxLib.get_version",
                   return_value='3.1.0').start()
        mock.patch("vmware_nsx.shell.admin.plugins.nsxv3.resources.migration."
                   "ensure_migration_state_ready", return_value=True).start()
        mock.patch("vmware_nsx.shell.admin.plugins.nsxv3.resources.migration."
                   "change_migration_service_status").start()

        cfg.CONF.set_override('nsx_api_managers', ['1.1.1.1'], 'nsx_v3')
        cfg.CONF.set_override('nsx_api_user', ['admin'], 'nsx_v3')
        cfg.CONF.set_override('nsx_api_password', ['dummy'], 'nsx_v3')

        super(TestNsxv3AdminUtils, self)._init_mock_plugin()

        self._plugin = nsxv3_utils.NsxV3PluginWrapper()
        mock_nm_get_plugin = mock.patch(
            "neutron_lib.plugins.directory.get_plugin")
        self.mock_nm_get_plugin = mock_nm_get_plugin.start()
        self.mock_nm_get_plugin.return_value = self._plugin

    def _get_plugin_name(self):
        return 'nsxv3'

    def test_nsxv3_resources(self):
        self._test_resources(resources.nsxv3_resources)

    def test_resources_with_common_args(self):
        """Run all nsxv3 admin utilities with some common arguments

        Using arguments like dhcp_profile_uuid which many apis need
        This improves the test coverage
        """
        args = ["dhcp_profile_uuid=e5b9b249-0034-4729-8ab6-fe4dacaa3a12",
                "metadata_proxy_uuid=e5b9b249-0034-4729-8ab6-fe4dacaa3a12",
                "nsx-id=e5b9b249-0034-4729-8ab6-fe4dacaa3a12",
                "net-id=e5b9b249-0034-4729-8ab6-fe4dacaa3a12",
                "availability-zone=default",
                "server-ip=1.1.1.1",
                "log-allowed-traffic=true",
                "value=10",
                "old-tier0=olduuid",
                "new-tier0=newuuid",
                "project-id=aaa",
                "host-moref=dummy-moref"
                ]
        # Create some neutron objects for the utilities to run on
        self._create_router()
        with self._create_l3_ext_network() as network:
            with self.subnet(network=network) as subnet:
                with self.port(subnet=subnet):
                    # Run all utilities with backend objects
                    self._test_resources_with_args(
                        resources.nsxv3_resources, args)


class TestNsxtvdAdminUtils(AbstractTestAdminUtils):

    def _get_plugin_name(self):
        return 'nsxtvd'

    def test_nsxtv_resources(self):
        self._test_resources(resources.nsxtvd_resources)


class TestNsxpAdminUtils(AbstractTestAdminUtils,
                         test_p_plugin.NsxPPluginTestCaseMixin):

    def _get_plugin_name(self):
        return 'nsxp'

    def _init_mock_plugin(self):
        self._plugin = nsxp_utils.NsxPolicyPluginWrapper()

    def test_nsxp_resources(self):
        self._test_resources(resources.nsxp_resources)

    def test_nsxp_resources_with_objects(self):
        # Create some neutron objects for the utilities to run on
        self._create_router()
        with self.network():
            # Run all utilities with backend objects
            self._test_resources(resources.nsxp_resources)

    def test_resources_with_common_args(self):
        """Run all nsxp admin utilities with some common arguments

        Using arguments some apis need to improves the test coverage
        """
        args = ["realization_interval=1",
                "dhcp-config=dumyuuid",
                "old-tier0=olduuid",
                "new-tier0=newuuid",
                "firewall-match=internal"]
        # Create some neutron objects for the utilities to run on
        self._create_router()
        with self._create_l3_ext_network() as network:
            with self.subnet(network=network, enable_dhcp=False) as subnet:
                with self.port(subnet=subnet):
                    # Run all utilities with backend objects
                    self._test_resources_with_args(
                        resources.nsxp_resources, args)
