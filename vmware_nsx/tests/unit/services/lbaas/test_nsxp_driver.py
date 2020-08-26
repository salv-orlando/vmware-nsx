# Copyright (c) 2019 VMware, Inc.
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

import copy
from unittest import mock

from neutron.tests import base
from neutron_lib import context
from neutron_lib import exceptions as n_exc

from vmware_nsx.services.lbaas import base_mgr
from vmware_nsx.services.lbaas import lb_const
from vmware_nsx.services.lbaas.nsx_p.implementation import healthmonitor_mgr
from vmware_nsx.services.lbaas.nsx_p.implementation import l7policy_mgr
from vmware_nsx.services.lbaas.nsx_p.implementation import l7rule_mgr
from vmware_nsx.services.lbaas.nsx_p.implementation import lb_utils as p_utils
from vmware_nsx.services.lbaas.nsx_p.implementation import listener_mgr
from vmware_nsx.services.lbaas.nsx_p.implementation import loadbalancer_mgr
from vmware_nsx.services.lbaas.nsx_p.implementation import member_mgr
from vmware_nsx.services.lbaas.nsx_p.implementation import pool_mgr
from vmware_nsx.services.lbaas.nsx_v3.implementation import lb_utils
from vmware_nsx.services.lbaas.octavia import octavia_listener
from vmware_nsx.tests.unit.services.lbaas import lb_data_models as lb_models
from vmware_nsx.tests.unit.services.lbaas import lb_translators


# TODO(asarfaty): Use octavia models for those tests
LB_VIP = '10.0.0.10'
LB_ROUTER_ID = 'router-x'
ROUTER_ID = 'neutron-router-x'
LB_ID = 'xxx-xxx'
LB_TENANT_ID = 'yyy-yyy'
LB_SERVICE_ID = LB_ID
LB_NETWORK = {'router:external': False,
              'id': 'xxxxx',
              'name': 'network-1'}
EXT_LB_NETWORK = {'router:external': True,
                  'id': 'public',
                  'name': 'network-2'}
LISTENER_ID = 'listener-x'
HTTP_LISTENER_ID = 'listener-http'
HTTPS_LISTENER_ID = 'listener-https'
APP_PROFILE_ID = 'appp-x'
LB_VS_ID = LISTENER_ID
LB_APP_PROFILE = {
    "resource_type": "LbHttpProfile",
    "description": "my http profile",
    "id": APP_PROFILE_ID,
    "display_name": "httpprofile1",
    "ntlm": False,
    "request_header_size": 1024,
    "http_redirect_to_https": False,
    "idle_timeout": 1800,
    "x_forwarded_for": "INSERT",
}
POOL_ID = 'ppp-qqq'
LB_POOL_ID = POOL_ID
LB_POOL = {
    "display_name": "httppool1",
    "description": "my http pool",
    "id": LB_POOL_ID,
    "algorithm": "ROUND_ROBIN",
}
MEMBER_ID = 'mmm-mmm'
MEMBER_ADDRESS = '10.0.0.200'
LB_MEMBER = {'display_name': 'member1_' + MEMBER_ID,
             'weight': 1, 'ip_address': MEMBER_ADDRESS, 'port': 80,
             'backup_member': False, 'admin_state_up': True}
LB_POOL_WITH_MEMBER = {
    "display_name": "httppool1",
    "description": "my http pool",
    "id": LB_POOL_ID,
    "algorithm": "ROUND_ROBIN",
    "members": [
        {
            "display_name": "http-member1",
            "ip_address": MEMBER_ADDRESS,
            "port": "80",
            "weight": "1",
            "admin_state": "ENABLED"
        }
    ]
}
HM_ID = 'hhh-mmm'
LB_MONITOR_ID = HM_ID
L7POLICY_ID = 'l7policy-xxx'
LB_RULE_ID = 'lb-rule-xx'
L7RULE_ID = 'l7rule-111'
LB_PP_ID = POOL_ID

FAKE_CERT = {'id': 'cert-xyz'}

SERVICE_STATUSES = {
    "virtual_servers": [{
        "virtual_server_id": LB_VS_ID,
        "status": "UP"
    }],
    "service_id": LB_SERVICE_ID,
    "service_status": "UP",
    "pools": [{
        "members": [{
            "port": "80",
            "ip_address": MEMBER_ADDRESS,
            "status": "DOWN"
        }],
        "pool_id": LB_POOL_ID,
        "status": "DOWN"
    }]
}

VS_STATUSES = {
    "results": [{
        "virtual_server_id": LB_VS_ID,
        "status": "UP"
    }]
}


class BaseTestEdgeLbaasV2(base.BaseTestCase):
    def _tested_entity(self):
        return None

    def completor(self, success=True):
        self.last_completor_succees = success
        self.last_completor_called = True

    def reset_completor(self):
        self.last_completor_succees = False
        self.last_completor_called = False

    def setUp(self):
        super(BaseTestEdgeLbaasV2, self).setUp()

        self.reset_completor()
        self.context = context.get_admin_context()
        octavia_objects = {
            'loadbalancer': loadbalancer_mgr.EdgeLoadBalancerManagerFromDict(),
            'listener': listener_mgr.EdgeListenerManagerFromDict(),
            'pool': pool_mgr.EdgePoolManagerFromDict(),
            'member': member_mgr.EdgeMemberManagerFromDict(),
            'healthmonitor':
                healthmonitor_mgr.EdgeHealthMonitorManagerFromDict(),
            'l7policy': l7policy_mgr.EdgeL7PolicyManagerFromDict(),
            'l7rule': l7rule_mgr.EdgeL7RuleManagerFromDict()}

        self.edge_driver = octavia_listener.NSXOctaviaListenerEndpoint(
            **octavia_objects)

        self.lbv2_driver = mock.Mock()
        self.core_plugin = mock.Mock()
        base_mgr.LoadbalancerBaseManager._lbv2_driver = self.lbv2_driver
        base_mgr.LoadbalancerBaseManager._core_plugin = self.core_plugin
        self._patch_lb_plugin(self.lbv2_driver, self._tested_entity)
        self._patch_policy_lb_clients(self.core_plugin)

        self.lb = lb_models.LoadBalancer(LB_ID, LB_TENANT_ID, 'lb1', '',
                                         'some-subnet', 'port-id', LB_VIP)
        self.listener = lb_models.Listener(LISTENER_ID, LB_TENANT_ID,
                                           'listener1', 'Dummy', None, LB_ID,
                                           'HTTP', protocol_port=80,
                                           loadbalancer=self.lb)
        self.https_listener = lb_models.Listener(
            HTTP_LISTENER_ID, LB_TENANT_ID, 'listener2', '', None, LB_ID,
            'HTTPS', protocol_port=443, loadbalancer=self.lb)
        self.terminated_https_listener = lb_models.Listener(
            HTTPS_LISTENER_ID, LB_TENANT_ID, 'listener3', '', None, LB_ID,
            'TERMINATED_HTTPS', protocol_port=443, loadbalancer=self.lb)
        self.pool = lb_models.Pool(POOL_ID, LB_TENANT_ID, 'pool1', '',
                                   None, 'HTTP', 'ROUND_ROBIN',
                                   loadbalancer_id=LB_ID,
                                   listener=self.listener,
                                   listeners=[self.listener],
                                   loadbalancer=self.lb)
        self.sess_persistence = lb_models.SessionPersistence(
            POOL_ID, 'HTTP_COOKIE', 'meh_cookie')
        self.pool_persistency = lb_models.Pool(POOL_ID, LB_TENANT_ID,
                                   'pool1', '', None, 'HTTP',
                                   'ROUND_ROBIN', loadbalancer_id=LB_ID,
                                   listener=self.listener,
                                   listeners=[self.listener],
                                   loadbalancer=self.lb,
                                   session_persistence=self.sess_persistence)
        self.member = lb_models.Member(MEMBER_ID, LB_TENANT_ID, POOL_ID,
                                       MEMBER_ADDRESS, 80, 1, pool=self.pool,
                                       name='member1', admin_state_up=True)
        self.hm = lb_models.HealthMonitor(HM_ID, LB_TENANT_ID, 'PING', 3, 3,
                                          1, pool=self.pool, name='hm1')
        self.hm_http = lb_models.HealthMonitor(HM_ID, LB_TENANT_ID, 'HTTP',
                                               3, 3, 1, pool=self.pool,
                                               http_method='GET',
                                               url_path="/meh", name='hm2')

        self.l7policy = lb_models.L7Policy(L7POLICY_ID, LB_TENANT_ID,
                                           name='policy-test',
                                           description='policy-desc',
                                           listener_id=LISTENER_ID,
                                           action='REDIRECT_TO_POOL',
                                           redirect_pool_id=POOL_ID,
                                           listener=self.listener,
                                           position=1)
        self.l7rule = lb_models.L7Rule(L7RULE_ID, LB_TENANT_ID,
                                       l7policy_id=L7POLICY_ID,
                                       compare_type='EQUAL_TO',
                                       invert=False,
                                       type='HEADER',
                                       key='key1',
                                       value='val1',
                                       policy=self.l7policy)

        # Translate LBaaS objects to dictionaries
        self.lb_dict = lb_translators.lb_loadbalancer_obj_to_dict(
            self.lb)
        self.listener_dict = lb_translators.lb_listener_obj_to_dict(
            self.listener)
        self.https_listener_dict = lb_translators.lb_listener_obj_to_dict(
            self.https_listener)
        self.terminated_https_listener_dict = lb_translators.\
            lb_listener_obj_to_dict(self.terminated_https_listener)
        self.pool_dict = lb_translators.lb_pool_obj_to_dict(
            self.pool)
        self.pool_persistency_dict = lb_translators.lb_pool_obj_to_dict(
            self.pool_persistency)
        self.member_dict = lb_translators.lb_member_obj_to_dict(
            self.member)
        self.hm_dict = lb_translators.lb_hm_obj_to_dict(
            self.hm)
        self.hm_http_dict = lb_translators.lb_hm_obj_to_dict(
            self.hm_http)
        self.l7policy_dict = lb_translators.lb_l7policy_obj_to_dict(
            self.l7policy)
        self.l7rule_dict = lb_translators.lb_l7rule_obj_to_dict(
            self.l7rule)

    def tearDown(self):
        self._unpatch_lb_plugin(self.lbv2_driver, self._tested_entity)
        super(BaseTestEdgeLbaasV2, self).tearDown()

    def _patch_lb_plugin(self, lb_plugin, manager):
        self.real_manager = getattr(lb_plugin, manager)
        lb_manager = mock.patch.object(lb_plugin, manager).start()
        mock.patch.object(lb_manager, 'create').start()
        mock.patch.object(lb_manager, 'update').start()
        mock.patch.object(lb_manager, 'delete').start()
        mock.patch.object(lb_manager, 'successful_completion').start()

    def _patch_policy_lb_clients(self, core_plugin):
        nsxpolicy = mock.patch.object(core_plugin, 'nsxpolicy').start()
        load_balancer = mock.patch.object(nsxpolicy, 'load_balancer').start()
        self.service_client = mock.patch.object(load_balancer,
                                                'lb_service').start()
        self.app_client = mock.patch.object(load_balancer,
                                            'lb_http_profile').start()
        self.vs_client = mock.patch.object(load_balancer,
                                           'virtual_server').start()
        self.pool_client = mock.patch.object(load_balancer,
                                             'lb_pool').start()
        self.monitor_client = mock.patch.object(
            load_balancer, 'lb_monitor_profile_icmp').start()
        self.http_monitor_client = mock.patch.object(
            load_balancer, 'lb_monitor_profile_http').start()
        self.rule_client = mock.patch.object(load_balancer,
                                             'rule').start()
        self.pp_client = mock.patch.object(
            load_balancer, 'lb_source_ip_persistence_profile').start()
        self.pp_cookie_client = mock.patch.object(
            load_balancer, 'lb_cookie_persistence_profile').start()
        self.pp_generic_client = mock.patch.object(
            load_balancer, 'lb_persistence_profile').start()
        self.nsxpolicy = nsxpolicy

    def _unpatch_lb_plugin(self, lb_plugin, manager):
        setattr(lb_plugin, manager, self.real_manager)


class TestEdgeLbaasV2Loadbalancer(BaseTestEdgeLbaasV2):
    def setUp(self):
        super(TestEdgeLbaasV2Loadbalancer, self).setUp()

    @property
    def _tested_entity(self):
        return 'load_balancer'

    def test_create(self):
        self.reset_completor()
        neutron_router = {'id': ROUTER_ID, 'name': 'dummy',
                          'external_gateway_info': {'external_fixed_ips': []}}
        with mock.patch.object(lb_utils, 'get_network_from_subnet',
                               return_value=LB_NETWORK), \
            mock.patch.object(lb_utils, 'get_router_from_network',
                              return_value=ROUTER_ID),\
            mock.patch.object(lb_utils, 'get_tags', return_value=[]),\
            mock.patch.object(self.core_plugin, 'get_router',
                              return_value=neutron_router), \
            mock.patch.object(self.core_plugin, '_find_router_gw_subnets',
                              return_value=[]),\
            mock.patch.object(self.core_plugin,
                              'service_router_has_services',
                              return_value=False) as plugin_has_sr,\
            mock.patch.object(self.service_client, 'get_router_lb_service',
                              return_value=None),\
            mock.patch.object(self.core_plugin.nsxpolicy, 'search_by_tags',
                              return_value={'results': []}),\
            mock.patch.object(self.service_client, 'create_or_overwrite'
                              ) as create_service:

            self.edge_driver.loadbalancer.create(
                self.context, self.lb_dict, self.completor)
            self.assertTrue(self.last_completor_called)
            self.assertTrue(self.last_completor_succees)
            # Service should be created with connectivity path
            create_service.assert_called_once_with(
                mock.ANY, lb_service_id=LB_ID,
                description=self.lb_dict['description'],
                tags=mock.ANY, size='SMALL',
                connectivity_path=mock.ANY)
            # Verify that the tags contain the loadbalancer id
            actual_tags = create_service.mock_calls[0][-1]['tags']
            found_tag = False
            for tag in actual_tags:
                if (tag['scope'] == p_utils.SERVICE_LB_TAG_SCOPE and
                    tag['tag'] == LB_ID):
                    found_tag = True
            self.assertTrue(found_tag)
            plugin_has_sr.assert_called_once_with(mock.ANY, ROUTER_ID)

    def test_create_same_router(self):
        self.reset_completor()
        neutron_router = {'id': ROUTER_ID, 'name': 'dummy',
                          'external_gateway_info': {'external_fixed_ips': []}}
        old_lb_id = 'aaa'
        lb_service = {'id': old_lb_id,
                      'tags': [{'scope': p_utils.SERVICE_LB_TAG_SCOPE,
                                'tag': old_lb_id}]}
        with mock.patch.object(lb_utils, 'get_network_from_subnet',
                               return_value=LB_NETWORK), \
            mock.patch.object(lb_utils, 'get_router_from_network',
                              return_value=ROUTER_ID),\
            mock.patch.object(self.core_plugin, 'get_router',
                              return_value=neutron_router), \
            mock.patch.object(self.core_plugin, '_find_router_gw_subnets',
                              return_value=[]),\
            mock.patch.object(self.core_plugin.nsxpolicy, 'search_by_tags',
                              return_value={'results': [lb_service]}),\
            mock.patch.object(self.core_plugin,
                              'service_router_has_services',
                              return_value=True) as plugin_has_sr,\
            mock.patch.object(self.service_client,
                              'update_customized') as service_update:
            self.edge_driver.loadbalancer.create(
                self.context, self.lb_dict, self.completor)
            self.assertTrue(self.last_completor_called)
            self.assertTrue(self.last_completor_succees)
            plugin_has_sr.assert_not_called()
            service_update.assert_called_once()

    def test_create_same_router_many_fail(self):
        lb_service = {'id': 'first_lb', 'tags': []}
        self.reset_completor()
        neutron_router = {'id': ROUTER_ID, 'name': 'dummy',
                          'external_gateway_info': {'external_fixed_ips': []}}
        with mock.patch.object(lb_utils, 'get_network_from_subnet',
                               return_value=LB_NETWORK), \
            mock.patch.object(lb_utils, 'get_router_from_network',
                              return_value=ROUTER_ID),\
            mock.patch.object(self.core_plugin, 'get_router',
                              return_value=neutron_router), \
            mock.patch.object(self.core_plugin, '_find_router_gw_subnets',
                              return_value=[]),\
            mock.patch.object(self.core_plugin.nsxpolicy, 'search_by_tags',
                              return_value={'results': [lb_service]}),\
            mock.patch.object(self.service_client, 'update_customized',
                              side_effect=n_exc.BadRequest(resource='', msg='')
                              ) as service_update,\
            mock.patch.object(self.service_client, 'get_router_lb_service',
                              return_value=None):
            self.assertRaises(
                n_exc.BadRequest,
                self.edge_driver.loadbalancer.create,
                self.context, self.lb_dict, self.completor)
            self.assertTrue(self.last_completor_called)
            self.assertFalse(self.last_completor_succees)
            service_update.assert_called_once()

    def test_create_external_vip(self):
        self.reset_completor()
        with mock.patch.object(lb_utils, 'get_router_from_network',
                              return_value=None),\
            mock.patch.object(lb_utils, 'get_network_from_subnet',
                              return_value=EXT_LB_NETWORK), \
            mock.patch.object(self.service_client, 'get_router_lb_service',
                              return_value=None),\
            mock.patch.object(self.service_client, 'create_or_overwrite',
                              return_value={'id': LB_SERVICE_ID}
                              ) as create_service:

            self.edge_driver.loadbalancer.create(self.context, self.lb_dict,
                                                 self.completor)
            self.assertTrue(self.last_completor_called)
            self.assertTrue(self.last_completor_succees)
            # Service should be created with no connectivity path
            create_service.assert_called_once_with(
                mock.ANY, lb_service_id=LB_ID,
                description=self.lb_dict['description'],
                tags=mock.ANY, size='SMALL',
                connectivity_path=None)

    def test_create_no_services(self):
        self.reset_completor()
        neutron_router = {'id': ROUTER_ID, 'name': 'dummy',
                          'external_gateway_info': {'external_fixed_ips': []}}
        with mock.patch.object(lb_utils, 'get_network_from_subnet',
                               return_value=LB_NETWORK), \
            mock.patch.object(lb_utils, 'get_router_from_network',
                              return_value=ROUTER_ID),\
            mock.patch.object(self.core_plugin, 'get_router',
                              return_value=neutron_router), \
            mock.patch.object(self.core_plugin, '_find_router_gw_subnets',
                              return_value=[]),\
            mock.patch.object(self.core_plugin, 'service_router_has_services',
                              return_value=False) as plugin_has_sr, \
            mock.patch.object(self.service_client, 'get_router_lb_service',
                              return_value=None),\
            mock.patch.object(self.service_client, 'create_or_overwrite'
                              ) as create_service,\
            mock.patch.object(self.core_plugin.nsxpolicy, 'search_by_tags',
                              return_value={'results': []}),\
            mock.patch.object(self.core_plugin,
                              "create_service_router") as create_sr:
            self.edge_driver.loadbalancer.create(
                self.context, self.lb_dict, self.completor)
            self.assertTrue(self.last_completor_called)
            self.assertTrue(self.last_completor_succees)
            # Service should be created with connectivity path
            create_service.assert_called_once_with(
                mock.ANY, lb_service_id=LB_ID,
                description=self.lb_dict['description'],
                tags=mock.ANY, size='SMALL',
                connectivity_path=mock.ANY)
            plugin_has_sr.assert_called_once_with(mock.ANY, ROUTER_ID)
            create_sr.assert_called_once()

    def test_create_with_port(self):
        self.reset_completor()
        neutron_router = {'id': ROUTER_ID, 'name': 'dummy',
                          'external_gateway_info': {'external_fixed_ips': []}}
        neutron_port = {'id': 'port-id', 'name': 'dummy', 'device_owner': ''}
        with mock.patch.object(lb_utils, 'get_network_from_subnet',
                               return_value=LB_NETWORK), \
            mock.patch.object(lb_utils, 'get_router_from_network',
                              return_value=ROUTER_ID),\
            mock.patch.object(self.core_plugin, 'get_router',
                              return_value=neutron_router), \
            mock.patch.object(self.core_plugin, 'get_port',
                              return_value=neutron_port), \
            mock.patch.object(self.core_plugin, 'update_port'
                              ) as update_port, \
            mock.patch.object(self.core_plugin, '_find_router_gw_subnets',
                              return_value=[]),\
            mock.patch.object(self.core_plugin,
                              'service_router_has_services',
                              return_value=False) as plugin_has_sr,\
            mock.patch.object(self.service_client, 'get_router_lb_service',
                              return_value=None),\
            mock.patch.object(self.service_client, 'create_or_overwrite'
                              ) as create_service:

            self.edge_driver.loadbalancer.create(
                self.context, self.lb_dict, self.completor)
            self.assertTrue(self.last_completor_called)
            self.assertTrue(self.last_completor_succees)
            # Service should be created with connectivity path
            create_service.assert_called_once_with(
                mock.ANY, lb_service_id=LB_ID,
                description=self.lb_dict['description'],
                tags=mock.ANY, size='SMALL',
                connectivity_path=mock.ANY)
            plugin_has_sr.assert_called_once_with(mock.ANY, ROUTER_ID)
            update_port.assert_called_once()

    def test_update(self):
        self.reset_completor()
        new_lb = lb_models.LoadBalancer(LB_ID, 'yyy-yyy', 'lb1-new',
                                        'new-description', 'some-subnet',
                                        'port-id', LB_VIP)
        new_lb_dict = lb_translators.lb_loadbalancer_obj_to_dict(new_lb)
        self.edge_driver.loadbalancer.update(self.context, self.lb_dict,
                                             new_lb_dict, self.completor)
        self.assertTrue(self.last_completor_called)
        self.assertTrue(self.last_completor_succees)

    def test_delete(self):
        self.reset_completor()
        lb_service = {'id': LB_SERVICE_ID}
        with mock.patch.object(lb_utils, 'get_router_from_network',
                               return_value=ROUTER_ID),\
            mock.patch.object(self.service_client, 'update_customized',
                              side_effect=n_exc.BadRequest(resource='', msg='')
                              ) as service_update,\
            mock.patch.object(self.core_plugin.nsxpolicy, 'search_by_tags',
                              return_value={'results': [lb_service]}),\
            mock.patch.object(self.service_client, 'delete'
                              ) as mock_delete_lb_service:

            self.edge_driver.loadbalancer.delete(
                self.context, self.lb_dict, self.completor)

            mock_delete_lb_service.assert_called_with(LB_SERVICE_ID)
            service_update.assert_called_once()
            self.assertTrue(self.last_completor_called)
            self.assertTrue(self.last_completor_succees)

    def test_delete_cascade(self):
        self.reset_completor()
        lb_service = {'id': LB_SERVICE_ID}
        with mock.patch.object(lb_utils, 'get_router_from_network',
                               return_value=ROUTER_ID),\
            mock.patch.object(self.service_client, 'update_customized',
                              side_effect=n_exc.BadRequest(resource='', msg='')
                              ) as service_update,\
            mock.patch.object(self.core_plugin.nsxpolicy, 'search_by_tags',
                              return_value={'results': [lb_service]}),\
            mock.patch.object(self.service_client, 'delete'
                              ) as mock_delete_lb_service:

            self.edge_driver.loadbalancer.delete_cascade(
                self.context, self.lb_dict, self.completor)

            mock_delete_lb_service.assert_called_with(LB_SERVICE_ID)
            service_update.assert_called_once()
            self.assertTrue(self.last_completor_called)
            self.assertTrue(self.last_completor_succees)

    def test_delete_with_router_id(self):
        self.reset_completor()
        lb_service = {'id': LB_SERVICE_ID,
                      'connectivity_path': 'infra/%s' % ROUTER_ID}
        with mock.patch.object(lb_utils, 'get_router_from_network',
                               return_value=None),\
            mock.patch.object(self.service_client, 'update_customized',
                              side_effect=n_exc.BadRequest(resource='', msg='')
                              ) as service_update,\
            mock.patch.object(self.core_plugin.nsxpolicy, 'search_by_tags',
                              return_value={'results': [lb_service]}),\
            mock.patch.object(self.service_client, 'delete'
                              ) as mock_delete_lb_service:

            self.edge_driver.loadbalancer.delete(self.context, self.lb_dict,
                                                 self.completor)

            mock_delete_lb_service.assert_called_with(LB_SERVICE_ID)
            service_update.assert_called_once()
            self.assertTrue(self.last_completor_called)
            self.assertTrue(self.last_completor_succees)

    def test_delete_no_services(self):
        self.reset_completor()
        lb_service = {'id': LB_SERVICE_ID,
                      'connectivity_path': 'infra/%s' % ROUTER_ID}
        with mock.patch.object(lb_utils, 'get_router_from_network',
                               return_value=None),\
            mock.patch.object(self.service_client, 'update_customized',
                              side_effect=n_exc.BadRequest(resource='', msg='')
                              ) as service_update,\
            mock.patch.object(self.core_plugin.nsxpolicy, 'search_by_tags',
                              return_value={'results': [lb_service]}),\
            mock.patch.object(self.core_plugin, 'service_router_has_services',
                              return_value=False), \
            mock.patch.object(self.core_plugin,
                              'delete_service_router') as delete_sr, \
            mock.patch.object(self.service_client, 'delete'
                              ) as mock_delete_lb_service:
            self.edge_driver.loadbalancer.delete(self.context, self.lb_dict,
                                                 self.completor)

            mock_delete_lb_service.assert_called_with(LB_SERVICE_ID)
            delete_sr.assert_called_once_with(ROUTER_ID)
            service_update.assert_called_once()
            self.assertTrue(self.last_completor_called)
            self.assertTrue(self.last_completor_succees)

    def test_delete_with_port(self):
        self.reset_completor()
        lb_service = {'id': LB_SERVICE_ID}
        neutron_port = {'id': 'port-id', 'name': 'dummy',
                        'device_owner': lb_const.VMWARE_LB_VIP_OWNER}
        with mock.patch.object(lb_utils, 'get_router_from_network',
                               return_value=ROUTER_ID),\
            mock.patch.object(self.service_client, 'update_customized',
                              side_effect=n_exc.BadRequest(resource='', msg='')
                              ) as service_update,\
            mock.patch.object(self.core_plugin.nsxpolicy, 'search_by_tags',
                              return_value={'results': [lb_service]}),\
            mock.patch.object(self.core_plugin, 'get_port',
                              return_value=neutron_port), \
            mock.patch.object(self.core_plugin, 'update_port'
                              ) as update_port, \
            mock.patch.object(self.service_client, 'delete'
                              ) as mock_delete_lb_service:
            self.edge_driver.loadbalancer.delete(self.context, self.lb_dict,
                                                 self.completor)

            mock_delete_lb_service.assert_called_with(LB_SERVICE_ID)
            service_update.assert_called_once()
            update_port.assert_called_once()
            self.assertTrue(self.last_completor_called)
            self.assertTrue(self.last_completor_succees)

    def test_add_tags_callback(self):
        callback = p_utils.add_service_tag_callback(LB_ID)

        # Add a tag
        body = {'tags': [{'scope': p_utils.SERVICE_LB_TAG_SCOPE,
                          'tag': 'dummy_id'}]}
        callback(body)
        self.assertEqual(2, len(body['tags']))

        # Tag already there
        callback(body)
        self.assertEqual(2, len(body['tags']))

        # Too many tags
        body['tags'] = []
        for x in range(p_utils.SERVICE_LB_TAG_MAX):
            body['tags'].append({
                'scope': p_utils.SERVICE_LB_TAG_SCOPE,
                'tag': 'dummy_id_%s' % x})
        self.assertRaises(n_exc.BadRequest, callback, body)

        # No tags
        body['tags'] = []
        callback(body)
        self.assertEqual(1, len(body['tags']))

    def test_add_tags_callback_only_first(self):
        callback = p_utils.add_service_tag_callback(LB_ID, only_first=True)

        # No tags
        body = {'tags': []}
        callback(body)
        self.assertEqual(1, len(body['tags']))

        # Tag already there
        self.assertRaises(n_exc.BadRequest, callback, body)

        # Another tag exists
        body['tags'] = [{'scope': p_utils.SERVICE_LB_TAG_SCOPE,
                         'tag': 'dummy'}]
        self.assertRaises(n_exc.BadRequest, callback, body)

    def test_del_tags_callback(self):
        callback = p_utils.remove_service_tag_callback(LB_ID)

        # remove a tag
        body = {'tags': [{'scope': p_utils.SERVICE_LB_TAG_SCOPE,
                          'tag': 'dummy_id'},
                         {'scope': p_utils.SERVICE_LB_TAG_SCOPE,
                          'tag': LB_ID}]}
        callback(body)
        self.assertEqual(1, len(body['tags']))

        # Tag not there there
        callback(body)
        self.assertEqual(1, len(body['tags']))

        # Last one
        body['tags'] = [{'scope': p_utils.SERVICE_LB_TAG_SCOPE,
                         'tag': LB_ID}]
        self.assertRaises(n_exc.BadRequest, callback, body)


class TestEdgeLbaasV2Listener(BaseTestEdgeLbaasV2):
    def setUp(self):
        super(TestEdgeLbaasV2Listener, self).setUp()

    @property
    def _tested_entity(self):
        return 'listener'

    def _create_listener(self, protocol='HTTP'):
        self.reset_completor()
        with mock.patch.object(self.core_plugin, 'get_floatingips'
                               ) as mock_get_floatingips, \
            mock.patch.object(self.core_plugin,
                              'get_waf_profile_path_and_mode',
                              return_value=(None, None)), \
            mock.patch.object(self.core_plugin.nsxpolicy, 'search_by_tags',
                              return_value={'results': [
                                  {'id': LB_SERVICE_ID}]}),\
            mock.patch.object(self.vs_client, 'create_or_overwrite'
                              ) as mock_add_virtual_server:
            mock_get_floatingips.return_value = []
            listener = self.listener_dict
            listener_id = LISTENER_ID
            if protocol == 'HTTPS':
                listener = self.https_listener_dict
                listener_id = HTTP_LISTENER_ID

            self.edge_driver.listener.create(self.context, listener,
                                             self.completor)

            mock_add_virtual_server.assert_called_with(
                application_profile_id=listener_id,
                description=listener['description'],
                lb_service_id=LB_ID,
                ip_address=LB_VIP,
                tags=mock.ANY,
                name=mock.ANY,
                ports=[listener['protocol_port']],
                max_concurrent_connections=None,
                virtual_server_id=listener_id,
                pool_id='',
                lb_persistence_profile_id='')
            self.assertTrue(self.last_completor_called)
            self.assertTrue(self.last_completor_succees)

    def test_create_http_listener(self):
        self._create_listener()

    def test_create_https_listener(self):
        self._create_listener(protocol='HTTPS')

    def test_create_terminated_https(self):
        #TODO(asarfaty): Add test with certificate
        self.reset_completor()
        with mock.patch.object(self.core_plugin, 'get_floatingips'
                               ) as mock_get_floatingips, \
            mock.patch.object(self.core_plugin,
                              'get_waf_profile_path_and_mode',
                              return_value=(None, None)), \
            mock.patch.object(self.core_plugin.nsxpolicy, 'search_by_tags',
                              return_value={'results': [
                                  {'id': LB_SERVICE_ID}]}),\
            mock.patch.object(self.vs_client, 'create_or_overwrite'
                              ) as mock_add_virtual_server:
            mock_get_floatingips.return_value = []

            self.edge_driver.listener.create(
                self.context,
                self.terminated_https_listener_dict,
                self.completor)
            mock_add_virtual_server.assert_called_with(
                application_profile_id=HTTPS_LISTENER_ID,
                description=self.terminated_https_listener_dict['description'],
                lb_service_id=LB_ID,
                ip_address=LB_VIP,
                tags=mock.ANY,
                name=mock.ANY,
                ports=[self.terminated_https_listener_dict['protocol_port']],
                max_concurrent_connections=None,
                virtual_server_id=HTTPS_LISTENER_ID,
                pool_id='',
                lb_persistence_profile_id='')
            self.assertTrue(self.last_completor_called)
            self.assertTrue(self.last_completor_succees)

    def test_create_listener_with_default_pool(self):
        self.reset_completor()
        listener = lb_models.Listener(LISTENER_ID, LB_TENANT_ID,
                                      'listener1', 'Dummy', self.pool.id,
                                      LB_ID, 'HTTP', protocol_port=80,
                                      loadbalancer=self.lb,
                                      default_pool=self.pool)
        listener_dict = lb_translators.lb_listener_obj_to_dict(listener)
        with mock.patch.object(self.core_plugin, 'get_floatingips'
                               ) as mock_get_floatingips, \
            mock.patch.object(self.core_plugin,
                              'get_waf_profile_path_and_mode',
                              return_value=(None, None)), \
            mock.patch.object(self.core_plugin.nsxpolicy, 'search_by_tags',
                              return_value={'results': [
                                  {'id': LB_SERVICE_ID}]}),\
            mock.patch.object(self.vs_client, 'create_or_overwrite'
                              ) as mock_add_virtual_server:
            mock_get_floatingips.return_value = []

            self.edge_driver.listener.create(self.context, listener_dict,
                                             self.completor)

            mock_add_virtual_server.assert_called_with(
                application_profile_id=LISTENER_ID,
                description=listener_dict['description'],
                lb_service_id=LB_ID,
                ip_address=LB_VIP,
                tags=mock.ANY,
                name=mock.ANY,
                ports=[listener_dict['protocol_port']],
                max_concurrent_connections=None,
                virtual_server_id=LISTENER_ID,
                pool_id=POOL_ID)
            self.assertTrue(self.last_completor_called)
            self.assertTrue(self.last_completor_succees)

    def test_create_listener_with_used_default_pool(self):
        self.reset_completor()
        listener = lb_models.Listener(LISTENER_ID, LB_TENANT_ID,
                                      'listener1', 'Dummy', self.pool.id,
                                      LB_ID, 'HTTP', protocol_port=80,
                                      loadbalancer=self.lb,
                                      default_pool=self.pool)
        listener_dict = lb_translators.lb_listener_obj_to_dict(listener)
        with mock.patch.object(self.core_plugin, 'get_floatingips'
                               ) as mock_get_floatingips,\
            mock.patch.object(self.core_plugin,
                              'get_waf_profile_path_and_mode',
                              return_value=(None, None)),\
            mock.patch.object(self.vs_client, 'list',
                              return_value=[{'pool_path': POOL_ID}]):
            mock_get_floatingips.return_value = []

            self.assertRaises(n_exc.BadRequest,
                              self.edge_driver.listener.create,
                              self.context, listener_dict,
                              self.completor)
            self.assertTrue(self.last_completor_called)
            self.assertFalse(self.last_completor_succees)

    def test_create_listener_with_session_persistence(self):
        self.reset_completor()
        listener = lb_models.Listener(LISTENER_ID, LB_TENANT_ID,
                                      'listener1', 'Dummy',
                                      self.pool_persistency.id,
                                      LB_ID, 'HTTP', protocol_port=80,
                                      loadbalancer=self.lb,
                                      default_pool=self.pool_persistency)
        listener_dict = lb_translators.lb_listener_obj_to_dict(listener)
        with mock.patch.object(self.core_plugin, 'get_floatingips'
                               ) as mock_get_floatingips, \
            mock.patch.object(self.core_plugin,
                              'get_waf_profile_path_and_mode',
                              return_value=(None, None)), \
            mock.patch.object(self.vs_client, 'create_or_overwrite'
                              ) as mock_add_virtual_server,\
            mock.patch.object(self.core_plugin.nsxpolicy, 'search_by_tags',
                              return_value={'results': [
                                  {'id': LB_SERVICE_ID}]}),\
            mock.patch.object(self.vs_client, 'get', return_value={}),\
            mock.patch.object(self.edge_driver.listener, '_get_pool_tags'),\
            mock.patch.object(self.pp_cookie_client, 'create_or_overwrite'
                              ) as mock_create_pp:
            mock_get_floatingips.return_value = []

            self.edge_driver.listener.create(self.context, listener_dict,
                                             self.completor)
            mock_add_virtual_server.assert_called_with(
                application_profile_id=LISTENER_ID,
                description=listener_dict['description'],
                lb_service_id=LB_ID,
                ip_address=LB_VIP,
                tags=mock.ANY,
                name=mock.ANY,
                ports=[listener_dict['protocol_port']],
                max_concurrent_connections=None,
                virtual_server_id=LISTENER_ID,
                pool_id=listener_dict['default_pool_id'])
            mock_create_pp.assert_called_once()
            self.assertTrue(self.last_completor_called)
            self.assertTrue(self.last_completor_succees)

    def test_create_listener_with_session_persistence_fail(self):
        self.reset_completor()
        listener = lb_models.Listener(LISTENER_ID, LB_TENANT_ID,
                                      'listener1', 'Dummy',
                                      self.pool_persistency.id,
                                      LB_ID, 'TCP', protocol_port=80,
                                      loadbalancer=self.lb,
                                      default_pool=self.pool_persistency)
        listener_dict = lb_translators.lb_listener_obj_to_dict(listener)
        with mock.patch.object(self.core_plugin,
                               'get_waf_profile_path_and_mode',
                               return_value=(None, None)), \
            mock.patch.object(self.core_plugin, 'get_floatingips'
                              ) as mock_get_floatingips:
            mock_get_floatingips.return_value = []

            self.assertRaises(n_exc.BadRequest,
                              self.edge_driver.listener.create,
                              self.context, listener_dict,
                              self.completor)
            self.assertTrue(self.last_completor_called)
            self.assertFalse(self.last_completor_succees)

    def test_create_listener_lb_no_name(self, protocol='HTTP'):
        self.reset_completor()
        with mock.patch.object(self.core_plugin, 'get_floatingips'
                               ) as mock_get_floatingips, \
            mock.patch.object(self.core_plugin,
                              'get_waf_profile_path_and_mode',
                              return_value=(None, None)), \
            mock.patch.object(self.core_plugin.nsxpolicy, 'search_by_tags',
                              return_value={'results': [
                                  {'id': LB_SERVICE_ID}]}),\
            mock.patch.object(self.vs_client, 'create_or_overwrite'
                              ) as mock_add_virtual_server:
            mock_get_floatingips.return_value = []
            listener = copy.deepcopy(self.listener_dict)
            listener['loadbalancer']['name'] = None
            listener_id = LISTENER_ID

            self.edge_driver.listener.create(self.context, listener,
                                             self.completor)

            mock_add_virtual_server.assert_called_with(
                application_profile_id=listener_id,
                description=listener['description'],
                lb_service_id=LB_ID,
                ip_address=LB_VIP,
                tags=mock.ANY,
                name=mock.ANY,
                ports=[listener['protocol_port']],
                max_concurrent_connections=None,
                virtual_server_id=listener_id,
                pool_id='',
                lb_persistence_profile_id='')
            self.assertTrue(self.last_completor_called)
            self.assertTrue(self.last_completor_succees)

    def test_update(self):
        self.reset_completor()
        new_listener = lb_models.Listener(LISTENER_ID, LB_TENANT_ID,
                                          'listener1-new', 'new-description',
                                          None, LB_ID, protocol_port=80,
                                          loadbalancer=self.lb)
        new_listener_dict = lb_translators.lb_listener_obj_to_dict(
            new_listener)
        with mock.patch.object(self.core_plugin,
                               'get_waf_profile_path_and_mode',
                               return_value=(None, None)), \
            mock.patch.object(self.core_plugin.nsxpolicy, 'search_by_tags',
                              return_value={'results': [
                                  {'id': LB_SERVICE_ID}]}),\
            mock.patch.object(self.core_plugin, 'get_floatingips'
                              ) as mock_get_floatingips:
            mock_get_floatingips.return_value = []

            self.edge_driver.listener.update(self.context, self.listener_dict,
                                             new_listener_dict,
                                             self.completor)
            self.assertTrue(self.last_completor_called)
            self.assertTrue(self.last_completor_succees)

    def test_update_with_default_pool(self):
        self.reset_completor()
        new_listener = lb_models.Listener(LISTENER_ID, LB_TENANT_ID,
                                          'listener1-new', 'new-description',
                                          self.pool, LB_ID, protocol_port=80,
                                          loadbalancer=self.lb,
                                          default_pool=self.pool)
        new_listener_dict = lb_translators.lb_listener_obj_to_dict(
            new_listener)
        with mock.patch.object(self.core_plugin,
                               'get_waf_profile_path_and_mode',
                               return_value=(None, None)), \
            mock.patch.object(self.core_plugin.nsxpolicy, 'search_by_tags',
                              return_value={'results': [
                                  {'id': LB_SERVICE_ID}]}),\
            mock.patch.object(self.core_plugin, 'get_floatingips'
                              ) as mock_get_floatingips:
            mock_get_floatingips.return_value = []

            self.edge_driver.listener.update(self.context, self.listener_dict,
                                             new_listener_dict, self.completor)
            self.assertTrue(self.last_completor_called)
            self.assertTrue(self.last_completor_succees)

    def test_update_with_session_persistence(self):
        self.reset_completor()
        new_listener = lb_models.Listener(LISTENER_ID, LB_TENANT_ID,
                                          'listener1-new', 'new-description',
                                          self.pool_persistency.id,
                                          LB_ID, protocol='HTTP',
                                          protocol_port=80,
                                          loadbalancer=self.lb,
                                          default_pool=self.pool_persistency)
        new_listener_dict = lb_translators.lb_listener_obj_to_dict(
            new_listener)
        with mock.patch.object(self.core_plugin, 'get_floatingips'
                               ) as mock_get_floatingips, \
            mock.patch.object(self.core_plugin,
                              'get_waf_profile_path_and_mode',
                              return_value=(None, None)), \
            mock.patch.object(self.core_plugin.nsxpolicy, 'search_by_tags',
                              return_value={'results': [
                                  {'id': LB_SERVICE_ID}]}),\
            mock.patch.object(self.edge_driver.listener, '_get_pool_tags'),\
            mock.patch.object(self.vs_client, 'get', return_value={}),\
            mock.patch.object(self.vs_client, 'update',
                              return_value={'id': LB_VS_ID}), \
            mock.patch.object(self.pp_cookie_client, 'create_or_overwrite'
                              ) as mock_create_pp:
            mock_get_floatingips.return_value = []

            self.edge_driver.listener.update(self.context, self.listener_dict,
                                             new_listener_dict, self.completor)
            mock_create_pp.assert_called_once()
            self.assertTrue(self.last_completor_called)
            self.assertTrue(self.last_completor_succees)

    def test_update_with_session_persistence_change(self):
        self.reset_completor()
        old_listener = lb_models.Listener(LISTENER_ID, LB_TENANT_ID,
                                          'listener1', 'description',
                                          self.pool_persistency.id,
                                          LB_ID, protocol='HTTP',
                                          protocol_port=80,
                                          loadbalancer=self.lb,
                                          default_pool=self.pool_persistency)
        old_listener_dict = lb_translators.lb_listener_obj_to_dict(
            old_listener)
        sess_persistence = lb_models.SessionPersistence(
            POOL_ID, 'SOURCE_IP')
        pool_persistency = lb_models.Pool('new_pool_id', LB_TENANT_ID,
                                   'pool1', '', None, 'HTTP',
                                   'ROUND_ROBIN', loadbalancer_id=LB_ID,
                                   listener=self.listener,
                                   listeners=[self.listener],
                                   loadbalancer=self.lb,
                                   session_persistence=sess_persistence)
        new_listener = lb_models.Listener(LISTENER_ID, LB_TENANT_ID,
                                          'listener1-new', 'new-description',
                                          pool_persistency.id,
                                          LB_ID, protocol='HTTP',
                                          protocol_port=80,
                                          loadbalancer=self.lb,
                                          default_pool=pool_persistency)
        new_listener_dict = lb_translators.lb_listener_obj_to_dict(
            new_listener)
        with mock.patch.object(self.core_plugin,
                               'get_waf_profile_path_and_mode',
                               return_value=(None, None)), \
            mock.patch.object(self.pp_client, 'create_or_overwrite'
                              ) as mock_create_pp, \
            mock.patch.object(self.pp_generic_client, 'delete'
                              ) as mock_delete_pp, \
            mock.patch.object(self.core_plugin.nsxpolicy, 'search_by_tags',
                              return_value={'results': [
                                  {'id': LB_SERVICE_ID}]}),\
            mock.patch.object(self.core_plugin, 'get_floatingips'
                              ) as mock_get_floatingips, \
            mock.patch.object(self.edge_driver.listener,
                              '_get_pool_tags'
                              ) as mock_get_pool_tags:
            mock_get_pool_tags.return_value = []
            mock_get_floatingips.return_value = []
            self.edge_driver.listener.update(
                self.context, old_listener_dict,
                new_listener_dict, self.completor)
            mock_create_pp.assert_called_once_with(
                name='persistence_pool1_new_p...ol_id',
                persistence_profile_id='new_pool_id_sourceip',
                tags=mock.ANY)
            # No reason to check parameters here, it's
            # all mocked out
            mock_delete_pp.assert_called_once()

    def test_delete(self):
        self.reset_completor()
        with mock.patch.object(self.service_client, 'get'
                               ) as mock_get_lb_service, \
            mock.patch.object(self.app_client, 'delete'
                              ) as mock_delete_app_profile, \
            mock.patch.object(self.vs_client, 'delete'
                              ) as mock_delete_virtual_server:
            mock_get_lb_service.return_value = {
                'id': LB_SERVICE_ID,
                'virtual_server_ids': [LB_VS_ID]}

            self.edge_driver.listener.delete(self.context, self.listener_dict,
                                             self.completor)

            mock_delete_virtual_server.assert_called_with(LB_VS_ID)
            mock_delete_app_profile.assert_called_with(LISTENER_ID)

            self.assertTrue(self.last_completor_called)
            self.assertTrue(self.last_completor_succees)

    def test_delete_cascade(self):
        self.reset_completor()
        with mock.patch.object(self.service_client, 'get'
                               ) as mock_get_lb_service, \
            mock.patch.object(self.app_client, 'delete'
                              ) as mock_delete_app_profile, \
            mock.patch.object(self.vs_client, 'delete'
                              ) as mock_delete_virtual_server:
            mock_get_lb_service.return_value = {
                'id': LB_SERVICE_ID,
                'virtual_server_ids': [LB_VS_ID]}

            self.edge_driver.listener.delete_cascade(
                self.context, self.listener_dict,
                self.completor)

            mock_delete_virtual_server.assert_called_with(LB_VS_ID)
            mock_delete_app_profile.assert_called_with(LISTENER_ID)

            self.assertTrue(self.last_completor_called)
            self.assertTrue(self.last_completor_succees)


class TestEdgeLbaasV2Pool(BaseTestEdgeLbaasV2):
    def setUp(self):
        super(TestEdgeLbaasV2Pool, self).setUp()

    @property
    def _tested_entity(self):
        return 'pool'

    def test_create(self):
        self.reset_completor()
        with mock.patch.object(self.pp_client, 'create_or_overwrite'
                               ) as mock_create_pp, \
            mock.patch.object(self.vs_client, 'update', return_value=None
                              ) as mock_vs_update:
            self.edge_driver.pool.create(self.context, self.pool_dict,
                                         self.completor)
            mock_create_pp.assert_not_called()
            mock_vs_update.assert_called_once_with(
                LB_VS_ID, pool_id=LB_POOL_ID, lb_persistence_profile_id=None)
            self.assertTrue(self.last_completor_called)
            self.assertTrue(self.last_completor_succees)

    def _test_create_with_persistency(self, vs_data, verify_func):
        self.reset_completor()
        with mock.patch.object(self.edge_driver.pool, '_get_pool_tags'),\
            mock.patch.object(self.pp_cookie_client, 'create_or_overwrite'
                              ) as mock_create_pp, \
            mock.patch.object(self.pp_cookie_client, 'update',
                              return_value=None) as mock_update_pp, \
            mock.patch.object(self.vs_client, 'get'
                              ) as mock_vs_get, \
            mock.patch.object(self.vs_client, 'update', return_value=None
                              ) as mock_vs_update:
            mock_vs_get.return_value = vs_data
            self.edge_driver.pool.create(
                self.context, self.pool_persistency_dict, self.completor)

            verify_func(mock_create_pp, mock_update_pp,
                        mock_vs_update)
            self.assertTrue(self.last_completor_called)
            self.assertTrue(self.last_completor_succees)

    def test_create_with_persistency(self):

        def verify_func(mock_create_pp, mock_update_pp,
                        mock_vs_update):
            mock_create_pp.assert_called_once_with(
                cookie_mode='INSERT',
                cookie_name='meh_cookie',
                name=mock.ANY,
                tags=mock.ANY,
                persistence_profile_id="%s_cookie" % LB_PP_ID)
            mock_update_pp.assert_not_called()
            mock_vs_update.assert_called_once_with(
                LB_VS_ID, pool_id=LB_POOL_ID,
                lb_persistence_profile_id="%s_cookie" % LB_PP_ID)
        vs_data = {'id': LB_VS_ID}
        self._test_create_with_persistency(vs_data, verify_func)

    def test_create_with_persistency_existing_profile(self):
        def verify_func(mock_create_pp, mock_update_pp,
                        mock_vs_update):
            mock_create_pp.assert_not_called()
            mock_update_pp.assert_called_once_with(
                LB_PP_ID,
                cookie_mode='INSERT',
                cookie_name='meh_cookie',
                name=mock.ANY,
                tags=mock.ANY)
            mock_vs_update.assert_called_once_with(
                LB_VS_ID, pool_id=LB_POOL_ID,
                lb_persistence_profile_id=LB_PP_ID)

        vs_data = {'id': LB_VS_ID,
                   'lb_persistence_profile_path': LB_PP_ID}
        self._test_create_with_persistency(vs_data, verify_func)

    def test_create_with_persistency_no_listener(self):
        def verify_func(mock_create_pp, mock_update_pp,
                        mock_vs_update):
            mock_create_pp.assert_not_called()
            mock_update_pp.assert_not_called()
            mock_vs_update.assert_not_called()

        vs_data = {'id': LB_VS_ID,
                   'lb_persistence_profile_path': LB_PP_ID}
        self.pool_persistency_dict['listener'] = None
        self.pool_persistency_dict['listeners'] = []
        self._test_create_with_persistency(vs_data, verify_func)

    def test_create_multiple_listeners(self):
        """Verify creation will fail if multiple listeners are set"""
        pool = lb_models.Pool(POOL_ID, LB_TENANT_ID, 'pool1', '',
                              None, 'HTTP', 'ROUND_ROBIN',
                              loadbalancer_id=LB_ID,
                              listeners=[self.listener,
                                         self.https_listener],
                              loadbalancer=self.lb)
        pool_dict = lb_translators.lb_pool_obj_to_dict(pool)
        self.assertRaises(n_exc.BadRequest,
                          self.edge_driver.pool.create,
                          self.context, pool_dict, self.completor)

    def test_update(self):
        self.reset_completor()
        new_pool = lb_models.Pool(POOL_ID, LB_TENANT_ID, 'pool-name', '',
                                  None, 'HTTP', 'LEAST_CONNECTIONS',
                                  listener=self.listener)
        new_pool_dict = lb_translators.lb_pool_obj_to_dict(new_pool)
        self.edge_driver.pool.update(self.context, self.pool_dict,
                                     new_pool_dict,
                                     self.completor)
        self.assertTrue(self.last_completor_called)
        self.assertTrue(self.last_completor_succees)

    def test_update_multiple_listeners(self):
        """Verify update action will fail if multiple listeners are set"""
        self.reset_completor()
        new_pool = lb_models.Pool(POOL_ID, LB_TENANT_ID, 'pool1', '',
                                  None, 'HTTP', 'ROUND_ROBIN',
                                  loadbalancer_id=LB_ID,
                                  listeners=[self.listener,
                                             self.https_listener],
                                  loadbalancer=self.lb)
        new_pool_dict = lb_translators.lb_pool_obj_to_dict(new_pool)
        self.assertRaises(n_exc.BadRequest,
                          self.edge_driver.pool.update,
                          self.context, self.pool_dict, new_pool_dict,
                          self.completor)
        self.assertTrue(self.last_completor_called)
        self.assertFalse(self.last_completor_succees)

    def _test_update_with_persistency(self, vs_data, old_pool, new_pool,
                                      verify_func, cookie=False):
        self.reset_completor()
        old_pool_dict = lb_translators.lb_pool_obj_to_dict(old_pool)
        new_pool_dict = lb_translators.lb_pool_obj_to_dict(new_pool)
        with mock.patch.object(self.edge_driver.pool, '_get_pool_tags'),\
            mock.patch.object(self.pp_client, 'create_or_overwrite'
                              ) as mock_create_pp, \
            mock.patch.object(self.pp_cookie_client, 'create_or_overwrite'
                              ) as mock_create_cookie_pp, \
            mock.patch.object(self.pp_client, 'update', return_value=None
                              ) as mock_update_pp, \
            mock.patch.object(self.pp_cookie_client, 'update',
                              return_value=None) as mock_update_cookie_pp, \
            mock.patch.object(self.pp_generic_client, 'delete',
                              return_value=None) as mock_delete_pp, \
            mock.patch.object(self.vs_client, 'get'
                              ) as mock_vs_get, \
            mock.patch.object(self.vs_client, 'update', return_value=None
                              ) as mock_vs_update:

            mock_vs_get.return_value = vs_data

            self.edge_driver.pool.update(self.context, old_pool_dict,
                                         new_pool_dict, self.completor)

            verify_func(
                mock_create_cookie_pp if cookie else mock_create_pp,
                mock_update_cookie_pp if cookie else mock_update_pp,
                mock_delete_pp,
                mock_vs_update)
            self.assertTrue(self.last_completor_called)
            self.assertTrue(self.last_completor_succees)

    def test_update_with_persistency(self):

        def verify_func(mock_create_pp, mock_update_pp,
                        mock_delete_pp, mock_vs_update):
            mock_create_pp.assert_called_once_with(
                cookie_mode='INSERT',
                cookie_name='meh_cookie',
                name=mock.ANY,
                tags=mock.ANY,
                persistence_profile_id="%s_cookie" % LB_PP_ID)
            mock_update_pp.assert_not_called()
            mock_delete_pp.assert_not_called()
            mock_vs_update.assert_called_once_with(
                LB_VS_ID, pool_id=LB_POOL_ID,
                lb_persistence_profile_id="%s_cookie" % LB_PP_ID)

        vs_data = {'id': LB_VS_ID}
        self._test_update_with_persistency(vs_data, self.pool,
                                           self.pool_persistency, verify_func,
                                           cookie=True)

    def test_update_switch_persistency_type(self):

        def verify_func(mock_create_pp, mock_update_pp,
                        mock_delete_pp, mock_vs_update):
            mock_create_pp.assert_called_once_with(
                name=mock.ANY,
                tags=mock.ANY,
                persistence_profile_id="%s_sourceip" % LB_PP_ID)
            mock_update_pp.assert_not_called()
            mock_delete_pp.assert_called_once()
            mock_vs_update.assert_called_once_with(
                LB_VS_ID, pool_id=LB_POOL_ID,
                lb_persistence_profile_id="%s_sourceip" % LB_PP_ID)

        ip_sess_persistence = lb_models.SessionPersistence(
            POOL_ID, 'SOURCE_IP')
        pool_ip_persistency = lb_models.Pool(
            POOL_ID, LB_TENANT_ID,
            'pool1', '', None, 'HTTP',
            'ROUND_ROBIN', loadbalancer_id=LB_ID,
            listener=self.listener,
            listeners=[self.listener],
            loadbalancer=self.lb,
            session_persistence=ip_sess_persistence)

        vs_data = {'id': LB_VS_ID,
                   'lb_persistence_profile_path': 'meh'}
        self._test_update_with_persistency(vs_data,
                                           self.pool_persistency,
                                           pool_ip_persistency,
                                           verify_func,)

    def test_update_remove_persistency(self):
        def verify_func(mock_create_pp, mock_update_pp,
                        mock_delete_pp, mock_vs_update):
            mock_create_pp.assert_not_called()
            mock_update_pp.assert_not_called()
            mock_delete_pp.assert_called_with(LB_PP_ID)
            mock_vs_update.assert_called_once_with(
                LB_VS_ID, pool_id=LB_POOL_ID, lb_persistence_profile_id=None)

        vs_data = {'id': LB_VS_ID,
                   'lb_persistence_profile_path': LB_PP_ID}
        self._test_update_with_persistency(vs_data, self.pool_persistency,
                                           self.pool, verify_func)

    def test_delete(self):
        self.reset_completor()
        with mock.patch.object(self.vs_client, 'update', return_value=None
                               ) as mock_update_virtual_server, \
            mock.patch.object(self.pool_client, 'delete'
                              ) as mock_delete_pool:
            self.edge_driver.pool.delete(self.context, self.pool_dict,
                                         self.completor)

            mock_update_virtual_server.assert_called_with(
                LB_VS_ID, lb_persistence_profile_id=None, pool_id=None)
            mock_delete_pool.assert_called_with(LB_POOL_ID)
            self.assertTrue(self.last_completor_called)
            self.assertTrue(self.last_completor_succees)

    def test_delete_cascade(self):
        self.reset_completor()
        with mock.patch.object(self.vs_client, 'update', return_value=None
                               ) as mock_update_virtual_server, \
            mock.patch.object(self.pool_client, 'delete'
                              ) as mock_delete_pool:
            self.edge_driver.pool.delete_cascade(
                self.context, self.pool_dict,
                self.completor)

            mock_update_virtual_server.assert_called_with(
                LB_VS_ID, lb_persistence_profile_id=None, pool_id=None)
            mock_delete_pool.assert_called_with(LB_POOL_ID)
            self.assertTrue(self.last_completor_called)
            self.assertTrue(self.last_completor_succees)

    def test_delete_with_persistency(self):
        self.reset_completor()
        with mock.patch.object(self.vs_client, 'get'
                               ) as mock_vs_get, \
            mock.patch.object(self.vs_client, 'update', return_value=None
                              ) as mock_update_virtual_server, \
            mock.patch.object(self.pool_client, 'delete'
                              ) as mock_delete_pool, \
            mock.patch.object(self.pp_generic_client, 'delete',
                              return_value=None) as mock_delete_pp:
            mock_vs_get.return_value = {
                'id': LB_VS_ID,
                'lb_persistence_profile_path': LB_PP_ID}
            self.edge_driver.pool.delete(
                self.context, self.pool_persistency_dict, self.completor)
            mock_delete_pp.assert_called_once_with(LB_PP_ID)
            mock_update_virtual_server.assert_called_once_with(
                LB_VS_ID, lb_persistence_profile_id=None, pool_id=None)
            mock_delete_pool.assert_called_with(LB_POOL_ID)
            self.assertTrue(self.last_completor_called)
            self.assertTrue(self.last_completor_succees)

    def _verify_create(self, cookie_name, cookie_mode,
                       mock_create_pp, mock_update_pp):
        if cookie_name:
            mock_create_pp.assert_called_once_with(
                persistence_profile_id="%s_cookie" % LB_PP_ID,
                cookie_name=cookie_name,
                cookie_mode=cookie_mode,
                name=mock.ANY,
                tags=mock.ANY)
        else:
            mock_create_pp.assert_called_once_with(
                persistence_profile_id="%s_sourceip" % LB_PP_ID,
                name=mock.ANY,
                tags=mock.ANY)
        # Compare tags - kw args are the last item of a mock call tuple
        self.assertCountEqual(mock_create_pp.mock_calls[0][-1]['tags'],
            [{'scope': 'os-lbaas-lb-id', 'tag': 'xxx-xxx'},
                {'scope': 'os-lbaas-lb-name', 'tag': 'lb1'},
                {'scope': 'os-lbaas-listener-id', 'tag': 'listener-x'}])
        mock_update_pp.assert_not_called()

    def _verify_update(self, cookie_name, cookie_mode,
                       mock_create_pp, mock_update_pp):
        if cookie_name:
            mock_update_pp.assert_called_once_with(
                "%s_cookie" % LB_PP_ID,
                cookie_name=cookie_name,
                cookie_mode=cookie_mode,
                name=mock.ANY,
                tags=mock.ANY)
        else:
            mock_update_pp.assert_called_once_with(
                "%s_sourceip" % LB_PP_ID,
                name=mock.ANY,
                tags=mock.ANY)
        # Compare tags - kw args are the last item of a mock call tuple
        self.assertCountEqual(mock_update_pp.mock_calls[0][-1]['tags'],
            [{'scope': 'os-lbaas-lb-id', 'tag': 'xxx-xxx'},
             {'scope': 'os-lbaas-lb-name', 'tag': 'lb1'},
             {'scope': 'os-lbaas-listener-id', 'tag': 'listener-x'}])
        mock_create_pp.assert_not_called()

    def _verify_delete(self, cookie_name, cookie_mode,
                       mock_create_pp, mock_update_pp):
        mock_create_pp.assert_not_called()
        mock_update_pp.assert_not_called()

    def _test_setup_session_persistence(self, session_persistence,
                                        vs_data, verify_func,
                                        cookie_name=None,
                                        cookie_mode=None,
                                        switch_type=False):
        with mock.patch.object(self.pp_client, 'create_or_overwrite'
                               ) as mock_create_pp, \
            mock.patch.object(self.pp_cookie_client, 'create_or_overwrite'
                              ) as mock_create_cookie_pp, \
            mock.patch.object(self.pp_client, 'update', return_value=None,
                              ) as mock_update_pp,\
            mock.patch.object(self.pp_cookie_client, 'update',
                              return_value=None) as mock_update_cookie_pp:

            self.pool.session_persistence = session_persistence
            pool_dict = lb_translators.lb_pool_obj_to_dict(self.pool)
            pp_id, post_func = p_utils.setup_session_persistence(
                self.nsxpolicy, pool_dict, [], switch_type,
                self.listener_dict, vs_data)
            pp_id_suffix = ""
            if session_persistence:
                if session_persistence.type == "SOURCE_IP":
                    pp_id_suffix = "sourceip"
                elif session_persistence.type in ["HTTP_COOKIE", "APP_COOKIE"]:
                    pp_id_suffix = "cookie"
                self.assertEqual("%s_%s" % (LB_PP_ID, pp_id_suffix), pp_id)
            else:
                self.assertIsNone(pp_id)
                self.assertEqual(
                    (self.nsxpolicy, vs_data['lb_persistence_profile_path'],),
                    post_func.args)
            verify_func(cookie_name, cookie_mode,
                        mock_create_cookie_pp if cookie_name
                        else mock_create_pp,
                        mock_update_cookie_pp if cookie_name
                        else mock_update_pp)

    def test_setup_session_persistence_sourceip_new_profile(self):
        sess_persistence = lb_models.SessionPersistence(
            "%s_sourceip" % LB_PP_ID, 'SOURCE_IP')
        self._test_setup_session_persistence(
            sess_persistence, {'id': LB_VS_ID}, self._verify_create)

    def test_setup_session_persistence_httpcookie_new_profile(self):
        sess_persistence = lb_models.SessionPersistence(
            "%s_cookie" % LB_PP_ID, 'HTTP_COOKIE')
        self._test_setup_session_persistence(
            sess_persistence, {'id': LB_VS_ID},
            self._verify_create, 'default_cookie_name', 'INSERT')

    def test_setup_session_persistence_appcookie_new_profile(self):
        sess_persistence = lb_models.SessionPersistence(
            "%s_cookie" % LB_PP_ID, 'APP_COOKIE', 'whatever')
        self._test_setup_session_persistence(
            sess_persistence, {'id': LB_VS_ID},
            self._verify_create, 'whatever', 'REWRITE')

    def test_setup_session_persistence_none_from_existing(self):
        sess_persistence = None
        self._test_setup_session_persistence(
            sess_persistence,
            {'id': LB_VS_ID,
             'lb_persistence_profile_path': "%s_sourceip" % LB_PP_ID},
            self._verify_delete)

    def test_setup_session_persistence_sourceip_from_existing(self):
        sess_persistence = lb_models.SessionPersistence(
            "%s_sourceip" % LB_PP_ID, 'SOURCE_IP')
        self._test_setup_session_persistence(
            sess_persistence,
            {'id': LB_VS_ID,
             'lb_persistence_profile_path': "%s_sourceip" % LB_PP_ID},
            self._verify_update)

    def test_setup_session_persistence_httpcookie_from_existing(self):
        sess_persistence = lb_models.SessionPersistence(
            "%s_cookie" % LB_PP_ID, 'HTTP_COOKIE')
        self._test_setup_session_persistence(
            sess_persistence,
            {'id': LB_VS_ID,
             'lb_persistence_profile_path': '%s_cookie' % LB_PP_ID},
            self._verify_update,
            'default_cookie_name', 'INSERT')

    def test_setup_session_persistence_appcookie_from_existing(self):
        sess_persistence = lb_models.SessionPersistence(
            "%s_cookie" % LB_PP_ID, 'APP_COOKIE', 'whatever')
        self._test_setup_session_persistence(
            sess_persistence,
            {'id': LB_VS_ID,
             'lb_persistence_profile_path': '%s_cookie' % LB_PP_ID},
            self._verify_update,
            'whatever', 'REWRITE')


class TestEdgeLbaasV2Member(BaseTestEdgeLbaasV2):
    def setUp(self):
        super(TestEdgeLbaasV2Member, self).setUp()

    @property
    def _tested_entity(self):
        return 'member'

    def test_create(self):
        self.reset_completor()
        with mock.patch.object(self.lbv2_driver.plugin, 'get_pool_members'
                               ) as mock_get_pool_members, \
            mock.patch.object(lb_utils, 'get_network_from_subnet'
                              ) as mock_get_network, \
            mock.patch.object(lb_utils, 'get_router_from_network'
                              ) as mock_get_router, \
            mock.patch.object(self.service_client, 'get_router_lb_service'
                              ) as mock_get_lb_service, \
            mock.patch.object(self.pool_client, 'get'
                              ) as mock_get_pool, \
            mock.patch.object(self.pool_client,
                              'create_pool_member_and_add_to_pool'
                              ) as mock_update_pool_with_members:
            mock_get_pool_members.return_value = [self.member]
            mock_get_network.return_value = LB_NETWORK
            mock_get_router.return_value = LB_ROUTER_ID
            mock_get_lb_service.return_value = {'id': LB_SERVICE_ID}
            mock_get_pool.return_value = LB_POOL

            self.edge_driver.member.create(
                self.context, self.member_dict, self.completor)
            mock_update_pool_with_members.assert_called_with(
                LB_POOL_ID, MEMBER_ADDRESS,
                port=self.member_dict['protocol_port'],
                display_name=mock.ANY,
                weight=self.member_dict['weight'],
                backup_member=self.member_dict.get('backup', False),
                admin_state='ENABLED')
            self.assertTrue(self.last_completor_called)
            self.assertTrue(self.last_completor_succees)

    def test_create_external_vip(self):
        self.reset_completor()
        lb_service = {'id': LB_SERVICE_ID}
        with mock.patch.object(self.lbv2_driver.plugin, 'get_pool_members'
                               ) as mock_get_pool_members, \
            mock.patch.object(lb_utils, 'get_network_from_subnet'
                              ) as mock_get_network, \
            mock.patch.object(lb_utils, 'get_router_from_network'
                              ) as mock_get_router, \
            mock.patch.object(self.service_client, 'get_router_lb_service'
                              ) as mock_get_lb_service, \
            mock.patch.object(self.core_plugin.nsxpolicy, 'search_by_tags',
                              return_value={'results': [lb_service]}),\
            mock.patch.object(self.core_plugin,
                              'service_router_has_services',
                              return_value=False) as plugin_has_sr,\
            mock.patch.object(self.core_plugin,
                              'service_router_has_loadbalancers',
                              return_value=False),\
            mock.patch.object(self.pool_client, 'get'
                              ) as mock_get_pool, \
            mock.patch.object(self.core_plugin, '_find_router_gw_subnets',
                              return_value=[]),\
            mock.patch.object(self.core_plugin, 'get_floatingips',
                              return_value=[{
                                  'fixed_ip_address': MEMBER_ADDRESS,
                                  'router_id': LB_ROUTER_ID}]),\
            mock.patch.object(self.pool_client,
                              'create_pool_member_and_add_to_pool'
                              ) as mock_update_pool_with_members:
            mock_get_pool_members.return_value = [self.member]
            mock_get_network.return_value = EXT_LB_NETWORK
            mock_get_router.return_value = LB_ROUTER_ID
            mock_get_lb_service.return_value = {'id': LB_SERVICE_ID}
            mock_get_pool.return_value = LB_POOL

            self.edge_driver.member.create(
                self.context, self.member_dict, self.completor)
            mock_update_pool_with_members.assert_called_with(
                LB_POOL_ID, MEMBER_ADDRESS,
                port=self.member_dict['protocol_port'],
                display_name=mock.ANY,
                weight=self.member_dict['weight'],
                backup_member=self.member_dict.get('backup', False),
                admin_state='ENABLED')
            self.assertTrue(self.last_completor_called)
            self.assertTrue(self.last_completor_succees)
            plugin_has_sr.assert_called_once_with(mock.ANY, LB_ROUTER_ID)

    def test_create_external_vip_router_used(self):
        self.reset_completor()
        lb_service = {'id': LB_SERVICE_ID}
        with mock.patch.object(self.lbv2_driver.plugin, 'get_pool_members'
                               ) as mock_get_pool_members, \
            mock.patch.object(lb_utils, 'get_network_from_subnet'
                              ) as mock_get_network, \
            mock.patch.object(lb_utils, 'get_router_from_network'
                              ) as mock_get_router, \
            mock.patch.object(self.service_client, 'get_router_lb_service'
                              ) as mock_get_lb_service, \
            mock.patch.object(self.core_plugin.nsxpolicy, 'search_by_tags',
                              return_value={'results': [lb_service]}),\
            mock.patch.object(self.core_plugin,
                              'service_router_has_loadbalancers',
                              return_value=True),\
            mock.patch.object(self.pool_client, 'get'
                              ) as mock_get_pool, \
            mock.patch.object(self.core_plugin, '_find_router_gw_subnets',
                              return_value=[]),\
            mock.patch.object(self.core_plugin, 'get_floatingips',
                              return_value=[{
                                  'fixed_ip_address': MEMBER_ADDRESS,
                                  'router_id': LB_ROUTER_ID}]):
            mock_get_pool_members.return_value = [self.member]
            mock_get_network.return_value = EXT_LB_NETWORK
            mock_get_router.return_value = LB_ROUTER_ID
            mock_get_lb_service.return_value = {'id': LB_SERVICE_ID}
            mock_get_pool.return_value = LB_POOL

            self.assertRaises(
                n_exc.BadRequest, self.edge_driver.member.create,
                self.context, self.member_dict, self.completor)
            self.assertTrue(self.last_completor_called)
            self.assertFalse(self.last_completor_succees)

    def test_create_external_vip_no_fip(self):
        self.reset_completor()
        lb_service = {'id': LB_SERVICE_ID}
        with mock.patch.object(self.lbv2_driver.plugin, 'get_pool_members'
                               ) as mock_get_pool_members, \
            mock.patch.object(lb_utils, 'get_network_from_subnet'
                              ) as mock_get_network, \
            mock.patch.object(lb_utils, 'get_router_from_network'
                              ) as mock_get_router, \
            mock.patch.object(self.service_client, 'get_router_lb_service'
                              ) as mock_get_lb_service, \
            mock.patch.object(self.core_plugin.nsxpolicy, 'search_by_tags',
                              return_value={'results': [lb_service]}),\
            mock.patch.object(self.core_plugin,
                              'service_router_has_loadbalancers',
                              return_value=True),\
            mock.patch.object(self.pool_client, 'get'
                              ) as mock_get_pool, \
            mock.patch.object(self.core_plugin, '_find_router_gw_subnets',
                              return_value=[]),\
            mock.patch.object(self.core_plugin, 'get_floatingips',
                              return_value=[]):
            mock_get_pool_members.return_value = [self.member]
            mock_get_network.return_value = EXT_LB_NETWORK
            mock_get_router.return_value = LB_ROUTER_ID
            mock_get_lb_service.return_value = {'id': LB_SERVICE_ID}
            mock_get_pool.return_value = LB_POOL

            self.assertRaises(
                n_exc.BadRequest, self.edge_driver.member.create,
                self.context, self.member_dict, self.completor)
            self.assertTrue(self.last_completor_called)
            self.assertFalse(self.last_completor_succees)

    def test_update(self):
        self.reset_completor()
        new_member = lb_models.Member(MEMBER_ID, LB_TENANT_ID, POOL_ID,
                                      MEMBER_ADDRESS, 80, 2, pool=self.pool,
                                      name='member-nnn-nnn')
        new_member_dict = lb_translators.lb_member_obj_to_dict(new_member)
        with mock.patch.object(self.pool_client, 'get'
                               ) as mock_get_pool, \
            mock.patch.object(lb_utils, 'get_network_from_subnet'
                              ) as mock_get_network_from_subnet:
            mock_get_pool.return_value = LB_POOL_WITH_MEMBER
            mock_get_network_from_subnet.return_value = LB_NETWORK

            self.edge_driver.member.update(self.context, self.member_dict,
                                           new_member_dict, self.completor)
            self.assertTrue(self.last_completor_called)
            self.assertTrue(self.last_completor_succees)

    def test_delete(self):
        self.reset_completor()
        with mock.patch.object(self.pool_client, 'get'
                               ) as mock_get_pool, \
            mock.patch.object(lb_utils, 'get_network_from_subnet'
                              ) as mock_get_network_from_subnet, \
            mock.patch.object(self.pool_client, 'remove_pool_member'
                              ) as mock_update_pool_with_members:
            mock_get_pool.return_value = LB_POOL_WITH_MEMBER
            mock_get_network_from_subnet.return_value = LB_NETWORK
            self.edge_driver.member.delete(self.context, self.member_dict,
                                           self.completor)

            mock_update_pool_with_members.assert_called_with(
                LB_POOL_ID, MEMBER_ADDRESS,
                port=self.member_dict['protocol_port'])
            self.assertTrue(self.last_completor_called)
            self.assertTrue(self.last_completor_succees)

    def test_delete_cascade(self):
        self.reset_completor()
        with mock.patch.object(self.pool_client, 'get'
                               ) as mock_get_pool, \
            mock.patch.object(lb_utils, 'get_network_from_subnet'
                              ) as mock_get_network_from_subnet, \
            mock.patch.object(self.pool_client, 'remove_pool_member'
                              ) as mock_update_pool_with_members:
            mock_get_pool.return_value = LB_POOL_WITH_MEMBER
            mock_get_network_from_subnet.return_value = LB_NETWORK
            self.edge_driver.member.delete_cascade(
                self.context, self.member_dict,
                self.completor)

            mock_update_pool_with_members.assert_not_called()
            self.assertFalse(self.last_completor_called)


class TestEdgeLbaasV2HealthMonitor(BaseTestEdgeLbaasV2):
    def setUp(self):
        super(TestEdgeLbaasV2HealthMonitor, self).setUp()

    @property
    def _tested_entity(self):
        return 'health_monitor'

    def test_create(self):
        self.reset_completor()
        with mock.patch.object(self.monitor_client, 'create_or_overwrite'
                               ) as mock_create_monitor, \
            mock.patch.object(self.pool_client, 'add_monitor_to_pool'
                              ) as mock_add_monitor_to_pool:

            self.edge_driver.healthmonitor.create(
                self.context, self.hm_dict, self.completor)
            mock_create_monitor.assert_called_once()
            mock_add_monitor_to_pool.assert_called_with(
                LB_POOL_ID, mock.ANY)
            self.assertTrue(self.last_completor_called)
            self.assertTrue(self.last_completor_succees)

    def test_create_http(self):
        self.reset_completor()
        with mock.patch.object(self.http_monitor_client, 'create_or_overwrite'
                               ) as mock_create_monitor, \
            mock.patch.object(self.pool_client, 'add_monitor_to_pool'
                              ) as mock_add_monitor_to_pool:

            # Verify HTTP-specific monitor parameters are added
            self.edge_driver.healthmonitor.create(
                self.context, self.hm_http_dict, self.completor)
            kw_args = mock_create_monitor.mock_calls[0][2]
            self.assertEqual(self.hm_http.http_method,
                             kw_args.get('request_method'))
            self.assertEqual(self.hm_http.url_path,
                             kw_args.get('request_url'))
            mock_add_monitor_to_pool.assert_called_with(
                LB_POOL_ID, mock.ANY)
            self.assertTrue(self.last_completor_called)
            self.assertTrue(self.last_completor_succees)

    def test_create_without_pool(self):
        self.reset_completor()
        hm = lb_models.HealthMonitor(HM_ID, LB_TENANT_ID, 'PING', 3, 3,
                                     1, pool=None, name='hm1')
        hm_dict = lb_translators.lb_hm_obj_to_dict(hm)
        with mock.patch.object(self.monitor_client, 'create_or_overwrite'
                               ) as mock_create_monitor, \
            mock.patch.object(self.pool_client, 'add_monitor_to_pool'
                              ) as mock_add_monitor_to_pool:
            self.assertRaises(
                n_exc.BadRequest,
                self.edge_driver.healthmonitor.create,
                self.context, hm_dict, self.completor)
            mock_create_monitor.assert_called_once()
            mock_add_monitor_to_pool.assert_not_called()
            self.assertTrue(self.last_completor_called)
            self.assertFalse(self.last_completor_succees)

    def test_update(self):
        self.reset_completor()
        with mock.patch.object(self.monitor_client, 'update'
                               ) as mock_update_monitor:
            new_hm = lb_models.HealthMonitor(
                HM_ID, LB_TENANT_ID, 'PING', 5, 5,
                5, pool=self.pool, name='new_name')
            new_hm_dict = lb_translators.lb_hm_obj_to_dict(new_hm)
            self.edge_driver.healthmonitor.update(
                self.context, self.hm_dict, new_hm_dict, self.completor)
            mock_update_monitor.assert_called_with(
                LB_MONITOR_ID, name=mock.ANY,
                fall_count=5, interval=5, timeout=5)
            self.assertTrue(self.last_completor_called)
            self.assertTrue(self.last_completor_succees)

    def test_delete(self):
        self.reset_completor()
        with mock.patch.object(self.pool_client, 'remove_monitor_from_pool'
                               ) as mock_remove_monitor_from_pool, \
            mock.patch.object(self.monitor_client, 'delete'
                              ) as mock_delete_monitor:
            self.edge_driver.healthmonitor.delete(
                self.context, self.hm_dict, self.completor)

            mock_remove_monitor_from_pool.assert_called_with(
                LB_POOL_ID, mock.ANY)
            mock_delete_monitor.assert_called_with(LB_MONITOR_ID)
            self.assertTrue(self.last_completor_called)
            self.assertTrue(self.last_completor_succees)

    def test_delete_cascade(self):
        self.reset_completor()
        with mock.patch.object(self.pool_client, 'remove_monitor_from_pool'
                               ) as mock_remove_monitor_from_pool, \
            mock.patch.object(self.monitor_client, 'delete'
                              ) as mock_delete_monitor:
            self.edge_driver.healthmonitor.delete_cascade(
                self.context, self.hm_dict, self.completor)

            mock_remove_monitor_from_pool.assert_called_with(
                LB_POOL_ID, mock.ANY)
            mock_delete_monitor.assert_called_with(LB_MONITOR_ID)
            self.assertTrue(self.last_completor_called)
            self.assertTrue(self.last_completor_succees)


class TestEdgeLbaasV2L7Policy(BaseTestEdgeLbaasV2):
    def setUp(self):
        super(TestEdgeLbaasV2L7Policy, self).setUp()

    @property
    def _tested_entity(self):
        return 'l7policy'

    def test_create(self):
        self.reset_completor()
        with mock.patch.object(self.vs_client, 'get'
                               ) as mock_get_virtual_server, \
            mock.patch.object(self.vs_client, 'add_lb_rule'
                              ) as mock_update_virtual_server:
            mock_get_virtual_server.return_value = {'id': LB_VS_ID}

            self.edge_driver.l7policy.create(
                self.context, self.l7policy_dict, self.completor)

            mock_update_virtual_server.assert_called_once()
            self.assertTrue(self.last_completor_called)
            self.assertTrue(self.last_completor_succees)

    def test_update(self):
        self.reset_completor()
        new_l7policy = lb_models.L7Policy(L7POLICY_ID, LB_TENANT_ID,
                                          name='new-policy',
                                          listener_id=LISTENER_ID,
                                          action='REJECT',
                                          listener=self.listener,
                                          position=2)
        new_policy_dict = lb_translators.lb_l7policy_obj_to_dict(new_l7policy)
        vs_with_rules = {
            'id': LB_VS_ID,
            'rule_ids': [LB_RULE_ID, 'abc', 'xyz']
        }
        with mock.patch.object(self.vs_client, 'get'
                               ) as mock_get_virtual_server, \
            mock.patch.object(self.vs_client, 'update_lb_rule'
                              ) as mock_update_virtual_server:
            mock_get_virtual_server.return_value = vs_with_rules
            self.edge_driver.l7policy.update(self.context, self.l7policy_dict,
                                             new_policy_dict, self.completor)

            mock_update_virtual_server.assert_called_once()
            self.assertTrue(self.last_completor_called)
            self.assertTrue(self.last_completor_succees)

    def test_delete(self):
        self.reset_completor()
        with mock.patch.object(self.vs_client, 'remove_lb_rule'
                               ) as mock_vs_remove_rule:
            self.edge_driver.l7policy.delete(
                self.context, self.l7policy_dict, self.completor)
            mock_vs_remove_rule.assert_called_with(LB_VS_ID, mock.ANY,
                                                   check_name_suffix=True)
            self.assertTrue(self.last_completor_called)
            self.assertTrue(self.last_completor_succees)

    def test_delete_cascade(self):
        self.reset_completor()
        with mock.patch.object(self.vs_client, 'remove_lb_rule'
                               ) as mock_vs_remove_rule:
            self.edge_driver.l7policy.delete_cascade(
                self.context, self.l7policy_dict, self.completor)
            mock_vs_remove_rule.assert_called_with(LB_VS_ID, mock.ANY,
                                                   check_name_suffix=True)
            self.assertTrue(self.last_completor_called)
            self.assertTrue(self.last_completor_succees)


class TestEdgeLbaasV2L7Rule(BaseTestEdgeLbaasV2):
    def setUp(self):
        super(TestEdgeLbaasV2L7Rule, self).setUp()

    @property
    def _tested_entity(self):
        return 'l7rule'

    def test_create(self):
        self.reset_completor()
        self.l7policy.rules = [self.l7rule]
        with mock.patch.object(self.vs_client, 'update_lb_rule'
                               ) as mock_update_virtual_server:
            self.edge_driver.l7rule.create(
                self.context, self.l7rule_dict, self.completor)
            mock_update_virtual_server.assert_called_once()
            self.assertTrue(self.last_completor_called)
            self.assertTrue(self.last_completor_succees)

    def test_update(self):
        self.reset_completor()
        new_l7rule = lb_models.L7Rule(L7RULE_ID, LB_TENANT_ID,
                                      l7policy_id=L7POLICY_ID,
                                      compare_type='STARTS_WITH',
                                      invert=True,
                                      type='COOKIE',
                                      key='cookie1',
                                      value='xxxxx',
                                      policy=self.l7policy)
        new_rule_dict = lb_translators.lb_l7rule_obj_to_dict(new_l7rule)
        self.l7policy.rules = [new_l7rule]
        with mock.patch.object(self.vs_client, 'update_lb_rule'
                               ) as mock_update_virtual_server:
            self.edge_driver.l7rule.update(self.context, self.l7rule_dict,
                                           new_rule_dict, self.completor)
            mock_update_virtual_server.assert_called_once()
            self.assertTrue(self.last_completor_called)
            self.assertTrue(self.last_completor_succees)

    def test_delete(self):
        self.reset_completor()
        self.l7policy.rules = [self.l7rule]
        with mock.patch.object(self.vs_client, 'update_lb_rule'
                               ) as mock_update_virtual_server:
            self.edge_driver.l7rule.delete(
                self.context, self.l7rule_dict, self.completor)
            mock_update_virtual_server.assert_called_once()
            self.assertTrue(self.last_completor_called)
            self.assertTrue(self.last_completor_succees)

    def test_delete_cascade(self):
        self.reset_completor()
        self.l7policy.rules = [self.l7rule]
        with mock.patch.object(self.vs_client, 'update_lb_rule'
                               ) as mock_update_virtual_server:
            self.edge_driver.l7rule.delete_cascade(
                self.context, self.l7rule_dict, self.completor)
            mock_update_virtual_server.assert_not_called()
            self.assertFalse(self.last_completor_called)
