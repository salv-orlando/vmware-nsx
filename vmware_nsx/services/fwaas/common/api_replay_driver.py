# Copyright 2019 VMware, Inc.
# All Rights Reserved
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

from neutron_fwaas.db.firewall.v2 import firewall_db_v2
from neutron_fwaas.services.firewall.service_drivers.agents import agents
from neutron_lib import constants as nl_constants


class ApiReplayFirewallPluginDb(firewall_db_v2.FirewallPluginDb):
    """Override FWaaS agent DB actions to use given objects IDs"""
    def create_firewall_rule(self, context, firewall_rule):
        fwr = firewall_rule
        src_port_min, src_port_max = self._get_min_max_ports_from_range(
            fwr['source_port'])
        dst_port_min, dst_port_max = self._get_min_max_ports_from_range(
            fwr['destination_port'])
        with context.session.begin(subtransactions=True):
            fwr_db = firewall_db_v2.FirewallRuleV2(
                # Use given ID for api_replay support
                id=fwr.get('id'),
                tenant_id=fwr['tenant_id'],
                name=fwr['name'],
                description=fwr['description'],
                protocol=fwr['protocol'],
                ip_version=fwr['ip_version'],
                source_ip_address=fwr['source_ip_address'],
                destination_ip_address=fwr['destination_ip_address'],
                source_port_range_min=src_port_min,
                source_port_range_max=src_port_max,
                destination_port_range_min=dst_port_min,
                destination_port_range_max=dst_port_max,
                action=fwr['action'],
                enabled=fwr['enabled'],
                shared=fwr['shared'])
            context.session.add(fwr_db)
        return self._make_firewall_rule_dict(fwr_db)

    def create_firewall_policy(self, context, firewall_policy):
        """This method is manipulated to allow the creation of additional
        default firewall policy, and do not automatically ensure one exists
        """
        fwp = firewall_policy
        with context.session.begin(subtransactions=True):
            # Use given ID for api_replay support
            fwp_db = firewall_db_v2.FirewallPolicy(
                id=fwp.get('id'),
                tenant_id=fwp['tenant_id'],
                name=fwp['name'],
                description=fwp['description'],
                audited=fwp['audited'],
                shared=fwp['shared'])
            context.session.add(fwp_db)
            self._set_rules_for_policy(context, fwp_db, fwp)
        return self._make_firewall_policy_dict(fwp_db)

    def create_firewall_group(self, context, firewall_group,
                              default_fwg=False):
        """This method is manipulated to allow the creation of additional
        default firewall group, and do not automatically ensure one exists
        """
        fwg = firewall_group
        tenant_id = fwg['tenant_id']
        if firewall_group.get('status') is None:
            fwg['status'] = nl_constants.CREATED

        with context.session.begin(subtransactions=True):
            # Use given ID for api_replay support
            fwg_db = firewall_db_v2.FirewallGroup(
                id=fwg.get('id'),
                tenant_id=tenant_id,
                name=fwg['name'],
                description=fwg['description'],
                status=fwg['status'],
                ingress_firewall_policy_id=fwg['ingress_firewall_policy_id'],
                egress_firewall_policy_id=fwg['egress_firewall_policy_id'],
                admin_state_up=fwg['admin_state_up'],
                shared=fwg['shared'])
            context.session.add(fwg_db)
            self._set_ports_for_firewall_group(context, fwg_db, fwg)
        return self._make_firewall_group_dict(fwg_db)


class ApiReplayFirewallAgentDriver(agents.FirewallAgentDriver):
    """FWaaS V2 agent driver for api-replay allowing POST with id."""
    def __init__(self, *args, **kwargs):
        super(ApiReplayFirewallAgentDriver, self).__init__(*args, **kwargs)
        self.firewall_db = ApiReplayFirewallPluginDb()
