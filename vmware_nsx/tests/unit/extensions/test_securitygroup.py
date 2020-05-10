# Copyright (c) 2015 VMware, Inc.
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
from unittest import mock

from neutron.tests.unit.extensions import test_securitygroup as test_ext_sg

from vmware_nsx.tests.unit.nsx_v3 import test_plugin as test_nsxv3
from vmware_nsxlib.v3 import exceptions as nsxlib_exc

from webob import exc


# Pool of fake ns-groups uuids
NSG_IDS = ['11111111-1111-1111-1111-111111111111',
           '22222222-2222-2222-2222-222222222222',
           '33333333-3333-3333-3333-333333333333',
           '44444444-4444-4444-4444-444444444444',
           '55555555-5555-5555-5555-555555555555']


def _mock_create_and_list_nsgroups(test_method):
    nsgroups = []

    def _create_nsgroup_mock(name, desc, tags, membership_criteria=None):
        nsgroup = {'id': NSG_IDS[len(nsgroups)],
                   'display_name': name,
                   'description': desc,
                   'tags': tags}
        nsgroups.append(nsgroup)
        return nsgroup

    def wrap(*args, **kwargs):
        with mock.patch(
            'vmware_nsxlib.v3.security.NsxLibNsGroup.create'
        ) as create_nsgroup_mock:
            create_nsgroup_mock.side_effect = _create_nsgroup_mock
            with mock.patch(
                "vmware_nsxlib.v3.security.NsxLibNsGroup.list"
            ) as list_nsgroups_mock:
                list_nsgroups_mock.side_effect = lambda: nsgroups
                test_method(*args, **kwargs)
    return wrap


class TestSecurityGroups(test_nsxv3.NsxV3PluginTestCaseMixin,
                         test_ext_sg.TestSecurityGroups):

    def test_create_security_group_rule_icmp_with_type_and_code(self):
        name = 'webservers'
        description = 'my webservers'
        with self.security_group(name, description) as sg:
            security_group_id = sg['security_group']['id']
            direction = "ingress"
            remote_ip_prefix = "10.0.0.0/24"
            protocol = "icmp"
            # port_range_min (ICMP type) is greater than port_range_max
            # (ICMP code) in order to confirm min <= max port check is
            # not called for ICMP.
            port_range_min = 14
            port_range_max = None
            keys = [('remote_ip_prefix', remote_ip_prefix),
                    ('security_group_id', security_group_id),
                    ('direction', direction),
                    ('protocol', protocol),
                    ('port_range_min', port_range_min),
                    ('port_range_max', port_range_max)]
            with self.security_group_rule(security_group_id, direction,
                                          protocol, port_range_min,
                                          port_range_max,
                                          remote_ip_prefix) as rule:
                for k, v, in keys:
                    self.assertEqual(rule['security_group_rule'][k], v)

    def test_create_security_group_with_manager_error(self):
        '''Reboot in multi-cluster environment may cause temporary 404 in
        firewall section APIs. We should return 503 and not 404 to the user
        '''

        name = 'webservers'
        description = 'my webservers'
        fail = False

        with mock.patch("vmware_nsxlib.v3.security.NsxLibFirewallSection."
                        "create_section_rules",
                        side_effect=nsxlib_exc.ResourceNotFound):
            try:
                with self.security_group(name, description):
                    # This should not succeed
                    # (assertRaises would not work with generators)
                    self.assertTrue(fail)

            except exc.HTTPClientError:
                pass
