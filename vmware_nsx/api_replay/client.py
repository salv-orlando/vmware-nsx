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

import copy
from datetime import datetime
import logging
import socket
import sys

from barbicanclient.v1 import client as barbican
from keystoneauth1 import identity
from keystoneauth1 import session
from neutronclient.common import exceptions as n_exc
from neutronclient.v2_0 import client
from octaviaclient.api.v2 import octavia
from oslo_config import cfg
import oslo_messaging as messaging
from oslo_messaging.rpc import dispatcher
from oslo_serialization import jsonutils
from oslo_utils import encodeutils

from neutron.common import config as neutron_config
from neutron_lib import constants as nl_constants
from octavia_lib.api.drivers import driver_lib

from vmware_nsx.api_replay import utils
from vmware_nsx.common import nsxv_constants
from vmware_nsx.services.lbaas.octavia import constants as d_const

LOG = logging.getLogger(__name__)
LOG.setLevel(logging.INFO)

# For internal testing only
use_old_keystone_on_dest = False


class ApiReplayClient(utils.PrepareObjectForMigration):

    def __init__(self,
                 source_os_username, source_os_user_domain_id,
                 source_os_tenant_name, source_os_tenant_domain_id,
                 source_os_password, source_os_auth_url,
                 dest_os_username, dest_os_user_domain_id,
                 dest_os_tenant_name, dest_os_tenant_domain_id,
                 dest_os_password, dest_os_auth_url, dest_os_endpoint_url,
                 enable_barbican,
                 dest_plugin, use_old_keystone,
                 octavia_os_username, octavia_os_user_domain_id,
                 octavia_os_tenant_name, octavia_os_tenant_domain_id,
                 octavia_os_password, octavia_os_auth_url,
                 neutron_conf, ext_net_map, net_vni_map, int_vni_map,
                 vif_ids_map, logfile, max_retry, cert_file):

        # Init config and logging
        if neutron_conf:
            neutron_config.init(args=['--config-file', neutron_conf])

        if logfile:
            f_handler = logging.FileHandler(logfile)
            f_formatter = logging.Formatter(
                '%(asctime)s %(levelname)s %(message)s')
            f_handler.setFormatter(f_formatter)
            LOG.addHandler(f_handler)

        self.max_retry = max_retry

        # connect to both clients
        if use_old_keystone:
            # Since we are not sure what keystone version will be used on the
            # source setup, we add an option to use the v2 client
            self.source_neutron = client.Client(
                username=source_os_username,
                tenant_name=source_os_tenant_name,
                password=source_os_password,
                auth_url=source_os_auth_url)
        else:
            self.source_neutron = self.connect_to_client(
                username=source_os_username,
                user_domain_id=source_os_user_domain_id,
                tenant_name=source_os_tenant_name,
                tenant_domain_id=source_os_tenant_domain_id,
                password=source_os_password,
                auth_url=source_os_auth_url,
                cert_file=cert_file)

        if use_old_keystone_on_dest:
            self.dest_neutron = client.Client(
                username=dest_os_username,
                tenant_name=dest_os_tenant_name,
                password=dest_os_password,
                auth_url=dest_os_auth_url)
        elif dest_os_endpoint_url and not dest_os_password:
            self.dest_neutron = self.connect_to_local_client(
                endpoint_url=dest_os_endpoint_url)
        else:
            self.dest_neutron = self.connect_to_client(
                username=dest_os_username,
                user_domain_id=dest_os_user_domain_id,
                tenant_name=dest_os_tenant_name,
                tenant_domain_id=dest_os_tenant_domain_id,
                password=dest_os_password,
                auth_url=dest_os_auth_url,
                cert_file=cert_file,
                endpoint_url=dest_os_endpoint_url)

        if octavia_os_auth_url:
            self.octavia = self.connect_to_octavia(
                username=octavia_os_username,
                user_domain_id=octavia_os_user_domain_id,
                tenant_name=octavia_os_tenant_name,
                tenant_domain_id=octavia_os_tenant_domain_id,
                password=octavia_os_password,
                auth_url=octavia_os_auth_url,
                cert_file=cert_file)
            if enable_barbican:
                self.barbican = self.connect_to_barbican(
                    username=octavia_os_username,
                    user_domain_id=octavia_os_user_domain_id,
                    tenant_name=octavia_os_tenant_name,
                    tenant_domain_id=octavia_os_tenant_domain_id,
                    password=octavia_os_password,
                    auth_url=octavia_os_auth_url,
                    cert_file=cert_file)
            else:
                self.barbican = None
        else:
            self.octavia = None
            self.barbican = None

        self.dest_plugin = dest_plugin

        if ext_net_map:
            with open(ext_net_map, 'r') as myfile:
                data = myfile.read()
            self.ext_net_map = jsonutils.loads(data)
        else:
            self.ext_net_map = None

        if net_vni_map:
            with open(net_vni_map, 'r') as myfile:
                data = myfile.read()
            self.net_vni_map = jsonutils.loads(data)
        else:
            self.net_vni_map = None

        if int_vni_map:
            with open(int_vni_map, 'r') as myfile:
                data = myfile.read()
            self.int_vni_map = jsonutils.loads(data)
        else:
            self.int_vni_map = None

        if vif_ids_map:
            with open(vif_ids_map, 'r') as myfile:
                data = myfile.read()
            self.vif_ids_map = jsonutils.loads(data)
        else:
            self.vif_ids_map = None

        self.n_errors = 0
        self.errors = []

        LOG.info("Starting NSX migration to %s.", self.dest_plugin)
        # Migrate all the objects
        self.migrate_quotas()
        self.migrate_security_groups()
        self.migrate_qos_policies()
        routers_routes, routers_gw_info = self.migrate_routers()
        source_networks = self.source_neutron.list_networks()['networks']
        self.migrate_networks_subnets_ports(routers_gw_info, source_networks)
        self.migrate_floatingips()
        self.migrate_routers_routes(routers_routes)
        self.migrate_fwaas()
        if self.octavia:
            self.migrate_octavia(source_networks)

        if self.n_errors:
            LOG.error("NSX migration is Done with %s errors:", self.n_errors)
            for err in self.errors:
                LOG.error(err)
            sys.exit(self.n_errors)
        else:
            LOG.info("NSX migration is Done with no errors")

    def _log_elapsed(self, start_ts, text, debug=True):
        if debug:
            func = LOG.debug
        else:
            func = LOG.info
        elapsed = datetime.now() - start_ts
        func("%s. Time taken: %s", text, elapsed)

    def _get_session(self, username, user_domain_id,
                     tenant_name, tenant_domain_id,
                     password, auth_url, cert_file):
        auth = identity.Password(username=username,
                                 user_domain_id=user_domain_id,
                                 password=password,
                                 project_name=tenant_name,
                                 project_domain_id=tenant_domain_id,
                                 auth_url=auth_url)
        return session.Session(auth=auth, verify=cert_file)

    def connect_to_client(self, username, user_domain_id,
                          tenant_name, tenant_domain_id,
                          password, auth_url, cert_file,
                          endpoint_url=None):
        sess = self._get_session(username, user_domain_id,
                                 tenant_name, tenant_domain_id,
                                 password, auth_url, cert_file)
        neutron = client.Client(session=sess,
                                endpoint_override=endpoint_url)
        return neutron

    def connect_to_local_client(self, endpoint_url):
        neutron = client.Client(endpoint_url=endpoint_url,
                                insecure=True,
                                auth_strategy='noauth')
        return neutron

    def connect_to_octavia(self, username, user_domain_id,
                           tenant_name, tenant_domain_id,
                           password, auth_url, cert_file):
        sess = self._get_session(username, user_domain_id,
                                 tenant_name, tenant_domain_id,
                                 password, auth_url, cert_file)
        endpoint = sess.get_endpoint(service_type='load-balancer')
        client_obj = octavia.OctaviaAPI(
            session=sess,
            service_type='load-balancer',
            endpoint=endpoint,
        )
        return client_obj

    def connect_to_barbican(self, username, user_domain_id,
                            tenant_name, tenant_domain_id,
                            password, auth_url, cert_file):
        sess = self._get_session(username, user_domain_id,
                                 tenant_name, tenant_domain_id,
                                 password, auth_url, cert_file)
        endpoint = sess.get_endpoint(service_type='key-manager')
        client_br = barbican.Client(
            session=sess,
            service_type='key-manager',
            endpoint=endpoint,
        )
        return client_br

    def find_subnet_by_id(self, subnet_id, subnets):
        for subnet in subnets:
            if subnet['id'] == subnet_id:
                return subnet

    def get_ports_on_network(self, network_id, ports):
        """Returns all the ports on a given network_id."""
        ports_on_network = []
        for port in ports:
            if port['network_id'] == network_id:
                ports_on_network.append(port)
        return ports_on_network

    def have_id(self, id, groups):
        """If the sg_id is in groups return true else false."""
        for group in groups:
            if id == group['id']:
                return group

        return False

    def add_error(self, msg):
        self.n_errors = self.n_errors + 1
        LOG.error(msg)
        self.errors.append(msg)

    def migrate_quotas(self):
        outer_start = datetime.now()
        source_quotas = self.source_neutron.list_quotas()['quotas']
        dest_quotas = self.dest_neutron.list_quotas()['quotas']

        total_num = len(source_quotas)
        LOG.info("Migrating %s neutron quotas", total_num)
        for count, quota in enumerate(source_quotas, 1):
            inner_start = datetime.now()
            dest_quota = self.have_id(quota['project_id'], dest_quotas)
            if dest_quota is False:
                body = self.prepare_quota(quota)
                try:
                    new_quota = (self.dest_neutron.update_quota(
                        quota['project_id'], {'quota': body}))
                    LOG.info("created quota %(count)s/%(total)s: %(q)s",
                             {'count': count, 'total': total_num,
                              'q': new_quota})
                    self._log_elapsed(
                        inner_start,
                        "Migrate quota for tenant %s" % quota['tenant_id'])
                except Exception as e:
                    self.add_error("Failed to create quota %(q)s: %(e)s" %
                                   {'q': quota, 'e': e})
        self._log_elapsed(outer_start, "Quota migration", debug=False)

    def migrate_qos_rule(self, dest_policy, source_rule):
        """Add the QoS rule from the source to the QoS policy

        If there is already a rule of that type, skip it since
        the QoS policy can have only one rule of each type
        """
        #TODO(asarfaty) also take rule direction into account once
        #ingress support is upstream
        start = datetime.now()
        rule_type = source_rule.get('type')
        dest_rules = dest_policy.get('rules')
        if dest_rules:
            for dest_rule in dest_rules:
                if dest_rule['type'] == rule_type:
                    return
        pol_id = dest_policy['id']
        tenant_id = dest_policy.get('tenant_id')
        body = self.prepare_qos_rule(source_rule, tenant_id=tenant_id)
        try:
            rule = None
            if rule_type == 'bandwidth_limit':
                rule = self.dest_neutron.create_bandwidth_limit_rule(
                    pol_id, body={'bandwidth_limit_rule': body})
            elif rule_type == 'dscp_marking':
                rule = self.dest_neutron.create_dscp_marking_rule(
                    pol_id, body={'dscp_marking_rule': body})
            else:
                LOG.info("QoS rule type %(rule)s is not supported for policy "
                         "%(pol)s",
                         {'rule': rule_type, 'pol': pol_id})
            if rule:
                LOG.info("created QoS policy %s rule %s", pol_id, rule)
                self._log_elapsed(
                    start, "Migrate QoS rule for policy %s" % pol_id)
        except Exception as e:
            self.add_error("Failed to create QoS rule %(rule)s for policy "
                           "%(pol)s: %(e)s" % {'rule': body, 'pol': pol_id,
                                               'e': e})

    def migrate_qos_policies(self):
        """Migrates QoS policies from source to dest neutron."""
        # first fetch the QoS policies from both the
        # source and destination neutron server
        start = datetime.now()
        try:
            dest_qos_pols = self.dest_neutron.list_qos_policies()['policies']
        except n_exc.NotFound:
            # QoS disabled on dest
            LOG.info("QoS is disabled on destination: ignoring QoS policies")
            self.dest_qos_support = False
            return
        self.dest_qos_support = True
        try:
            source_qos_pols = self.source_neutron.list_qos_policies()[
                'policies']
        except n_exc.NotFound:
            # QoS disabled on source
            return

        for pol in source_qos_pols:
            inner_start = datetime.now()
            dest_pol = self.have_id(pol['id'], dest_qos_pols)
            # If the policy already exists on the dest_neutron
            if dest_pol:
                # make sure all the QoS policy rules are there and
                # create them if not
                for qos_rule in pol['rules']:
                    self.migrate_qos_rule(dest_pol, qos_rule)

            # dest server doesn't have the group so we create it here.
            else:
                qos_rules = pol.pop('rules')
                try:
                    body = self.prepare_qos_policy(pol)
                    new_pol = self.dest_neutron.create_qos_policy(
                        body={'policy': body})
                    self.check_and_apply_tags(
                        self.dest_neutron, 'qos/policies',
                        pol['id'], pol)
                except Exception as e:
                    self.add_error("Failed to create QoS policy %(pol)s: "
                                   "%(e)s" % {'pol': pol['id'], 'e': e})
                    continue
                else:
                    LOG.info("Created QoS policy %s", new_pol)
                    for qos_rule in qos_rules:
                        self.migrate_qos_rule(new_pol['policy'], qos_rule)
            self._log_elapsed(inner_start, "Migrate QoS policy %s" % pol['id'])
        self._log_elapsed(start, "Migrate QoS policies", debug=False)

    def migrate_security_groups(self):
        """Migrates security groups from source to dest neutron."""
        # first fetch the security groups from both the
        # source and dest neutron server
        start = datetime.now()
        source_sec_groups = self.source_neutron.list_security_groups()
        dest_sec_groups = self.dest_neutron.list_security_groups()

        source_sec_groups = source_sec_groups['security_groups']
        dest_sec_groups = dest_sec_groups['security_groups']

        total_num = len(source_sec_groups)
        LOG.info("Migrating %s security groups", total_num)
        rules_dict = {}
        for count, sg in enumerate(source_sec_groups, 1):
            sg_start = datetime.now()
            dest_sec_group = self.have_id(sg['id'], dest_sec_groups)
            # If the security group already exists on the dest_neutron
            if dest_sec_group:
                # make sure all the security group rules are there and
                # create them if not
                for sg_rule in sg['security_group_rules']:
                    if(self.have_id(sg_rule['id'],
                                    dest_sec_group['security_group_rules'])
                       is False):
                        try:
                            rule_start = datetime.now()
                            body = self.prepare_security_group_rule(sg_rule)
                            self.dest_neutron.create_security_group_rule(
                                {'security_group_rule': body})
                            LOG.info("Created security group rule for SG "
                                     "%s: %s", sg.get('id'), sg_rule.get('id'))
                            self._log_elapsed(
                                rule_start,
                                "Migrate security group rule %s" %
                                sg_rule.get('id'))
                        except n_exc.Conflict:
                            # NOTE(arosen): when you create a default
                            # security group it is automatically populated
                            # with some rules. When we go to create the rules
                            # that already exist because of a match an error
                            # is raised here but that's okay.
                            pass

            # dest server doesn't have the group so we create it here.
            else:
                sg_rules = sg.pop('security_group_rules')
                try:
                    body = self.prepare_security_group(sg)
                    new_sg = self.dest_neutron.create_security_group(
                        {'security_group': body})
                    self.check_and_apply_tags(
                        self.dest_neutron, 'security-groups',
                        sg['id'], sg)
                    LOG.info("Created security-group %(count)s/%(total)s: "
                             "%(sg)s",
                             {'count': count, 'total': total_num,
                              'sg': new_sg})
                except Exception as e:
                    self.add_error("Failed to create security group (%(sg)s): "
                                   "%(e)s" % {'sg': sg, 'e': e})
                    # Don't bother going to rules
                    continue

                # Use bulk rules creation for the rules of the SG
                if not sg_rules:
                    continue
                # SG rules must be grouped per tenant
                rules = {}
                for sg_rule in sg_rules:
                    # skip the default rules that were already created
                    skip = False
                    created_rules = new_sg['security_group'].get(
                        'security_group_rules', [])
                    for rule in created_rules:
                        if (rule['direction'] == sg_rule['direction'] and
                            rule['ethertype'] == sg_rule['ethertype'] and
                            rule['remote_group_id'] ==
                                sg_rule['remote_group_id'] and
                            not rule['protocol']):
                            skip = True
                            break
                    if not skip:
                        body = self.prepare_security_group_rule(sg_rule)
                        tenant_id = sg_rule.get('tenant_id', 'default')
                        tenant_rules = rules.get(tenant_id, [])
                        tenant_rules.append({'security_group_rule': body})
                        rules[tenant_id] = tenant_rules
                # save rules to create once all the sgs are created
                if rules:
                    rules_dict[sg['id']] = rules
            self._log_elapsed(
                sg_start, "Migrate security group %s" % sg['id'])

        # Create the rules after all security groups are created to allow
        # dependencies in remote_group_id
        for sg_id, sg_rules in rules_dict.items():
            try:
                rule_start = datetime.now()
                for tenant_id, tenant_rules in sg_rules.items():
                    rules = self.dest_neutron.create_security_group_rule(
                        {'security_group_rules': tenant_rules})
                    LOG.info("Created %d security group rules for "
                             "SG %s and tenant %s: %s",
                            len(rules), sg_id, tenant_id,
                            ",".join([rule.get('id') for rule in
                                    rules.get('security_group_rules', [])]))
                self._log_elapsed(
                    rule_start,
                    "Migrate security group rules for group %s" % sg_id)
            except Exception as e:
                self.add_error("Failed to create security group %s "
                               "rules: %s" % (sg_id, e))
        self._log_elapsed(start, "Migrate security groups", debug=False)

    def get_dest_availablity_zones(self, resource):
        azs = self.dest_neutron.list_availability_zones()['availability_zones']
        az_names = [az['name'] for az in azs if az['resource'] == resource]
        return az_names

    def migrate_routers(self):
        """Migrates routers from source to dest neutron.

        Also return a dictionary of the routes that should be added to
        each router. Static routes must be added later, after the router
        ports are set.
        And return a dictionary of external gateway info per router
        """
        start = datetime.now()
        try:
            source_routers = self.source_neutron.list_routers()['routers']
        except Exception:
            # L3 might be disabled in the source
            source_routers = []

        dest_routers = self.dest_neutron.list_routers()['routers']
        dest_azs = self.get_dest_availablity_zones('router')
        update_routes = {}
        gw_info = {}

        total_num = len(source_routers)
        LOG.info("Migrating %s routers", total_num)
        for count, router in enumerate(source_routers, 1):
            inner_start = datetime.now()
            if router.get('routes'):
                update_routes[router['id']] = router['routes']

            if router.get('external_gateway_info'):
                gw_info[router['id']] = router['external_gateway_info']

            # Ignore internal NSXV objects
            if router['project_id'] == nsxv_constants.INTERNAL_TENANT_ID:
                LOG.info("Skip router %s: Internal NSX-V router",
                         router['id'])
                continue

            # If its a distributed router, we may also need to create its
            # internal network
            if self.int_vni_map and router['id'] in self.int_vni_map:
                net_name = ("Internal network for router %s migration" %
                            router['id'])
                net_body = {'tenant_id': nsxv_constants.INTERNAL_TENANT_ID,
                            'id': router['id'],
                            'name': net_name,
                            'vni': self.int_vni_map[router['id']]}
                try:
                    self.dest_neutron.create_network({'network': net_body})
                except Exception as e:
                    self.add_error("Failed to create internal network for "
                                   "router %(rtr)s: %(e)s" %
                                   {'rtr': router['id'], 'e': e})
            dest_router = self.have_id(router['id'], dest_routers)
            if dest_router is False:
                body = self.prepare_router(router, dest_azs=dest_azs)
                try:
                    new_router = (self.dest_neutron.create_router(
                        {'router': body}))
                    self.check_and_apply_tags(
                        self.dest_neutron, 'routers',
                        router['id'], router)
                    LOG.info("created router %(count)s/%(total)s: %(rtr)s",
                             {'count': count, 'total': total_num,
                              'rtr': new_router})
                except Exception as e:
                    self.add_error("Failed to create router %(rtr)s: %(e)s" %
                                   {'rtr': router, 'e': e})
            self._log_elapsed(
                inner_start, "Migrate router %s" % router['id'])
        self._log_elapsed(start, "Migrate routers", debug=False)
        return update_routes, gw_info

    def migrate_routers_routes(self, routers_routes):
        """Add static routes to the created routers."""
        start = datetime.now()

        total_num = len(routers_routes)
        LOG.info("Migrating %s routers routes", total_num)
        for count, (router_id, routes) in enumerate(
            routers_routes.items(), 1):
            inner_start = datetime.now()
            try:
                self.dest_neutron.update_router(router_id,
                    {'router': {'routes': routes}})
                LOG.info("Added routes to router %(rtr)s "
                         "%(count)s/%(total)s: %(routes)s",
                         {'count': count, 'total': total_num,
                          'rtr': router_id, 'routes': routes})
            except Exception as e:
                self.add_error("Failed to add routes %(routes)s to router "
                               "%(rtr)s: %(e)s" %
                               {'routes': routes, 'rtr': router_id, 'e': e})
            self._log_elapsed(
                inner_start, "Migrate routes for router %s" % router_id)
        self._log_elapsed(start, "Migrate Routers' routes", debug=False)

    def migrate_subnetpools(self):
        start = datetime.now()
        subnetpools_map = {}
        try:
            source_subnetpools = self.source_neutron.list_subnetpools()[
                'subnetpools']
        except Exception:
            # pools not supported on source
            return subnetpools_map
        dest_subnetpools = self.dest_neutron.list_subnetpools()[
            'subnetpools']

        for pool in source_subnetpools:
            # a default subnetpool (per ip-version) should be unique.
            # so do not create one if already exists
            if pool['is_default']:
                for dpool in dest_subnetpools:
                    if (dpool['is_default'] and
                        dpool['ip_version'] == pool['ip_version']):
                        subnetpools_map[pool['id']] = dpool['id']
                        break
            else:
                old_id = pool['id']
                body = self.prepare_subnetpool(pool)
                if 'default_quota' in body and body['default_quota'] is None:
                    del body['default_quota']

                try:
                    new_id = self.dest_neutron.create_subnetpool(
                        {'subnetpool': body})['subnetpool']['id']
                    subnetpools_map[old_id] = new_id
                    # refresh the list of existing subnetpools
                    dest_subnetpools = self.dest_neutron.list_subnetpools()[
                        'subnetpools']
                except Exception as e:
                    self.add_error("Failed to create subnetpool %(pool)s: "
                                   "%(e)s" % {'pool': pool, 'e': e})
        self._log_elapsed(start, "Migrate subnet pools", debug=False)
        return subnetpools_map

    def migrate_networks_subnets_ports(self, routers_gw_info,
                                       source_networks=None):
        """Migrates networks/ports/router-uplinks from src to dest neutron."""
        start = datetime.now()
        source_ports = self.source_neutron.list_ports()['ports']
        source_subnets = self.source_neutron.list_subnets()['subnets']
        if not source_networks:
            source_networks = self.source_neutron.list_networks()['networks']
        dest_networks = self.dest_neutron.list_networks()['networks']
        dest_ports = self.dest_neutron.list_ports()['ports']
        dest_subnets = self.dest_neutron.list_subnets()['subnets']

        remove_qos = False
        if not self.dest_qos_support:
            remove_qos = True

        # Find out if the destination already has a default public network
        dest_default_public_net = False
        for dest_net in dest_networks:
            if dest_net.get('is_default') and dest_net.get('router:external'):
                dest_default_public_net = True

        subnetpools_map = self.migrate_subnetpools()
        dest_azs = self.get_dest_availablity_zones('network')

        total_num = len(source_networks)

        # Reorder the source networks as we need to migrate the external first
        # This is mandatory as vlan networks cannot be added to a router with
        # no GW
        external = []
        internal = []
        for network in source_networks:
            if network.get('router:external'):
                external.append(network)
            else:
                internal.append(network)
        source_networks = external + internal

        LOG.info("Migrating %(nets)s networks, %(subnets)s subnets and "
                 "%(ports)s ports",
                 {'nets': total_num, 'subnets': len(source_subnets),
                  'ports': len(source_ports)})
        for count, network in enumerate(source_networks, 1):
            start_net = datetime.now()
            external_net = network.get('router:external')
            body = self.prepare_network(
                network, remove_qos=remove_qos,
                dest_default_public_net=dest_default_public_net,
                dest_azs=dest_azs, ext_net_map=self.ext_net_map,
                net_vni_map=self.net_vni_map)

            # only create network if the dest server doesn't have it
            if self.have_id(network['id'], dest_networks):
                LOG.info("Skip network %s: Already exists on the destination",
                         network['id'])
                continue

            # Ignore internal NSXV objects
            # TODO(asarfaty) - temporarily migrate those as well
            # if network['project_id'] == nsxv_constants.INTERNAL_TENANT_ID:
            #     LOG.info("Skip network %s: Internal NSX-V network",
            #              network['id'])
            #     continue

            try:
                created_net = self.dest_neutron.create_network(
                    {'network': body})['network']
                self.check_and_apply_tags(
                    self.dest_neutron, 'networks', network['id'], network)

                LOG.info("Created network %(count)s/%(total)s: %(net)s",
                         {'count': count, 'total': total_num,
                          'net': created_net})
            except Exception as e:
                self.add_error("Failed to create network: %s : %s" % (body, e))
                continue

            subnets_map = {}
            dhcp_subnets = []
            count_dhcp_subnet = 0
            for subnet_id in network['subnets']:
                start_subnet = datetime.now()
                # only create subnet if the dest server doesn't have it
                if self.have_id(subnet_id, dest_subnets):
                    LOG.info("Skip network %s: Already exists on the "
                             "destination", network['id'])
                    continue
                subnet = self.find_subnet_by_id(subnet_id, source_subnets)
                body = self.prepare_subnet(subnet)

                # specify the network_id that we just created above
                body['network_id'] = network['id']
                # translate the old subnetpool id to the new one
                if body.get('subnetpool_id'):
                    body['subnetpool_id'] = subnetpools_map.get(
                        body['subnetpool_id'])

                # Handle DHCP enabled subnets
                enable_dhcp = False
                sub_host_routes = None
                if body['enable_dhcp']:
                    count_dhcp_subnet = count_dhcp_subnet + 1
                    # disable dhcp on subnet: we will enable it after creating
                    # all the ports to avoid ip collisions
                    body['enable_dhcp'] = False
                    if count_dhcp_subnet > 1:
                        # Do not allow dhcp on the subnet if there is already
                        # another subnet with DHCP as the v3 plugins supports
                        # only one
                        LOG.warning("Disabling DHCP for subnet on net %s: "
                                    "The plugin doesn't support multiple "
                                    "subnets with DHCP", network['id'])
                        enable_dhcp = False
                    elif external_net:
                        # Do not allow dhcp on the external subnet
                        LOG.warning("Disabling DHCP for subnet on net %s: "
                                    "The plugin doesn't support dhcp on "
                                    "external networks", network['id'])
                        enable_dhcp = False
                    else:
                        enable_dhcp = True
                        if body.get('host_routes'):
                            # Should be added when dhcp is enabled
                            sub_host_routes = body.pop('host_routes')
                try:
                    created_subnet = self.dest_neutron.create_subnet(
                        {'subnet': body})['subnet']
                    self.check_and_apply_tags(
                        self.dest_neutron, 'subnets',
                        subnet['id'], subnet)
                    LOG.info("Created subnet: %s", created_subnet['id'])
                    subnets_map[subnet_id] = created_subnet['id']
                    if enable_dhcp:
                        dhcp_subnets.append({'id': created_subnet['id'],
                                             'host_routes': sub_host_routes})
                except n_exc.BadRequest as e:
                    self.add_error("Failed to create subnet: %(subnet)s: "
                                   "%(e)s" % {'subnet': subnet, 'e': e})
                self._log_elapsed(start_subnet,
                                  "Migrate Subnet %s" % subnet['id'])

            # create the ports on the network
            self._log_elapsed(start_net, "Migrate Network %s" % network['id'])
            ports = self.get_ports_on_network(network['id'], source_ports)
            for port in ports:
                start_port = datetime.now()
                # Ignore internal NSXV objects
                if port['project_id'] == nsxv_constants.INTERNAL_TENANT_ID:
                    LOG.info("Skip port %s: Internal NSX-V port",
                             port['id'])
                    continue

                body = self.prepare_port(port, remove_qos=remove_qos,
                                         vif_ids_map=self.vif_ids_map)

                # specify the network_id that we just created above
                port['network_id'] = network['id']

                subnet_id = None
                if port.get('fixed_ips'):
                    old_subnet_id = port['fixed_ips'][0]['subnet_id']
                    subnet_id = subnets_map.get(old_subnet_id)
                # remove the old subnet id field from fixed_ips dict
                for fixed_ips in body['fixed_ips']:
                    del fixed_ips['subnet_id']

                # only create port if the dest server doesn't have it
                if self.have_id(port['id'], dest_ports) is False:
                    if port['device_owner'] == 'network:router_gateway':
                        router_id = port['device_id']
                        enable_snat = True
                        if router_id in routers_gw_info:
                            # keep the original snat status of the router
                            enable_snat = routers_gw_info[router_id].get(
                                'enable_snat', True)
                        rtr_body = {
                            "external_gateway_info":
                                {"network_id": port['network_id'],
                                 "enable_snat": enable_snat,
                                 # keep the original GW IP
                                 "external_fixed_ips": port.get('fixed_ips')}}
                        try:
                            self.dest_neutron.update_router(
                                router_id, {'router': rtr_body})
                            LOG.info("Uplinked router %(rtr)s to external "
                                     "network %(net)s",
                                     {'rtr': router_id,
                                      'net': port['network_id']})

                        except Exception as e:
                            self.add_error("Failed to add router gateway with "
                                           "port (%(port)s): %(e)s" %
                                           {'port': port, 'e': e})
                        continue

                    # Let the neutron dhcp-agent recreate this on its own
                    if port['device_owner'] == 'network:dhcp':
                        continue

                    # ignore these as we create them ourselves later
                    if port['device_owner'] == 'network:floatingip':
                        continue

                    if (port['device_owner'] == 'network:router_interface' and
                        subnet_id):
                        try:
                            # uplink router_interface ports by creating the
                            # port, and attaching it to the router
                            router_id = port['device_id']
                            del body['device_owner']
                            del body['device_id']
                            created_port = self.dest_neutron.create_port(
                                {'port': body})['port']
                            self.check_and_apply_tags(
                                self.dest_neutron, 'ports',
                                port['id'], port)
                            LOG.info("Created interface port %(port)s (subnet "
                                     "%(subnet)s, ip %(ip)s, mac %(mac)s)",
                                     {'port': created_port['id'],
                                      'subnet': subnet_id,
                                      'ip': created_port['fixed_ips'][0][
                                            'ip_address'],
                                      'mac': created_port['mac_address']})
                            self.dest_neutron.add_interface_router(
                                router_id,
                                {'port_id': created_port['id']})
                            LOG.info("Uplinked router %(rtr)s to network "
                                     "%(net)s",
                                     {'rtr': router_id, 'net': network['id']})
                        except Exception as e:
                            # NOTE(arosen): this occurs here if you run the
                            # script multiple times as we don't track this.
                            # Note(asarfaty): also if the same network in
                            # source is attached to 2 routers, which the v3
                            # plugins does not support.
                            self.add_error("Failed to add router interface "
                                           "port (%(port)s): %(e)s" %
                                           {'port': port, 'e': e})
                        continue

                    try:
                        created_port = self.dest_neutron.create_port(
                            {'port': body})['port']
                        self.check_and_apply_tags(
                            self.dest_neutron, 'ports',
                            port['id'], port)
                    except Exception as e:
                        # NOTE(arosen): this occurs here if you run the
                        # script multiple times as we don't track this.
                        self.add_error("Failed to create port (%(port)s) : "
                                       "%(e)s" % {'port': port, 'e': e})
                    else:
                        ip_addr = None
                        if created_port.get('fixed_ips'):
                            ip_addr = created_port['fixed_ips'][0].get(
                                'ip_address')
                        LOG.info("Created port %(port)s (subnet "
                                 "%(subnet)s, ip %(ip)s, mac %(mac)s)",
                                 {'port': created_port['id'],
                                  'subnet': subnet_id,
                                  'ip': ip_addr,
                                  'mac': created_port['mac_address']})
                self._log_elapsed(
                    start_port,
                    "Migrate port %s" % port['id'])

            # Enable dhcp on the relevant subnets, and re-add host routes:
            for subnet in dhcp_subnets:
                start_subnet_dhcp = datetime.now()
                try:
                    data = {'enable_dhcp': True}
                    if subnet['host_routes']:
                        data['host_routes'] = subnet['host_routes']
                    self.dest_neutron.update_subnet(subnet['id'],
                                                    {'subnet': data})
                except Exception as e:
                    self.add_error("Failed to enable DHCP on subnet "
                                   "%(subnet)s: %(e)s" %
                                   {'subnet': subnet['id'], 'e': e})
                self._log_elapsed(
                    start_subnet_dhcp,
                    "Enabling DHCP on Subnet %s" % subnet['id'])
        self._log_elapsed(start, "Migrate Networks, Subnets and Ports",
                          debug=False)

    def migrate_floatingips(self):
        """Migrates floatingips from source to dest neutron."""
        start = datetime.now()
        try:
            source_fips = self.source_neutron.list_floatingips()['floatingips']
        except Exception:
            # L3 might be disabled in the source
            source_fips = []

        total_num = len(source_fips)
        for count, source_fip in enumerate(source_fips, 1):
            start_fip = datetime.now()
            body = self.prepare_floatingip(source_fip)
            try:
                fip = self.dest_neutron.create_floatingip({'floatingip': body})
                self.check_and_apply_tags(
                    self.dest_neutron, 'floatingips',
                    source_fip['id'], source_fip)
                LOG.info("Created floatingip %(count)s/%(total)s : %(fip)s",
                         {'count': count, 'total': total_num, 'fip': fip})
            except Exception as e:
                self.add_error("Failed to create floating ip (%(fip)s) : "
                               "%(e)s" % {'fip': source_fip, 'e': e})
            self._log_elapsed(
                start_fip, "Migrate Floating IP %s" % source_fip['id'])
        self._log_elapsed(start, "Migrate Floating IPs %s", debug=False)

    def _plural_res_type(self, resource_type):
        if resource_type.endswith('y'):
            return "%sies" % resource_type[:-1]
        return "%ss" % resource_type

    def _migrate_fwaas_resource(self, resource_type, source_objects,
                                dest_objects, prepare_method, create_method):
        total_num = len(source_objects)
        LOG.info("Migrating %s %s", total_num,
                 self._plural_res_type(resource_type))
        for count, source_obj in enumerate(source_objects, 1):
            # Check if the object already exists
            start_fwaas = datetime.now()
            if self.have_id(source_obj['id'], dest_objects):
                LOG.info("Skipping %s %s as it already exists on the "
                         "destination server", resource_type, source_obj['id'])
                continue
            if (source_obj.get('status') and
                source_obj['status'] not in [nl_constants.ACTIVE,
                                             nl_constants.INACTIVE]):
                LOG.info("Skipping %s %s %s",
                         source_obj['status'], resource_type, source_obj['id'])
                continue

            body = prepare_method(source_obj)
            try:
                new_obj = create_method({resource_type: body})
                LOG.info("Created %(resource)s %(count)s/%(total)s : %(obj)s",
                         {'resource': resource_type, 'count': count,
                          'total': total_num, 'obj': new_obj})
            except Exception as e:
                self.add_error("Failed to create %(resource)s (%(obj)s) : "
                               "%(e)s" %
                               {'resource': resource_type, 'obj': source_obj,
                               'e': e})
            self._log_elapsed(
                start_fwaas, "Migrate FWaaS resource %s" % source_obj['id'])

    def migrate_fwaas(self):
        """Migrates FWaaS V2 objects from source to dest neutron."""
        start = datetime.now()
        try:
            # Reading existing source resources. Note that the firewall groups
            # should be read first, to make sure default objects were created.
            source_groups = self.source_neutron.\
                list_fwaas_firewall_groups()['firewall_groups']
            source_polices = self.source_neutron.\
                list_fwaas_firewall_policies()['firewall_policies']
            source_rules = self.source_neutron.\
                list_fwaas_firewall_rules()['firewall_rules']
        except Exception as e:
            # FWaaS might be disabled in the source
            LOG.info("FWaaS V2 was not found on the source server: %s", e)
            return

        try:
            dest_groups = self.dest_neutron.\
                list_fwaas_firewall_groups()['firewall_groups']
            dest_polices = self.dest_neutron.\
                list_fwaas_firewall_policies()['firewall_policies']
            dest_rules = self.dest_neutron.\
                list_fwaas_firewall_rules()['firewall_rules']
        except Exception as e:
            # FWaaS might be disabled in the destination
            LOG.warning("Skipping FWaaS V2 migration. FWaaS V2 was not found "
                        "on the destination server: %s", e)
            return

        # Migrate all FWaaS objects:
        start_rules = datetime.now()
        self._migrate_fwaas_resource(
            'firewall_rule', source_rules, dest_rules,
            self.prepare_fwaas_rule,
            self.dest_neutron.create_fwaas_firewall_rule)
        self._log_elapsed(start_rules, "Migrate FWaaS rules", debug=False)
        start_pol = datetime.now()
        self._migrate_fwaas_resource(
            'firewall_policy', source_polices, dest_polices,
            self.prepare_fwaas_policy,
            self.dest_neutron.create_fwaas_firewall_policy)
        self._log_elapsed(start_pol, "Migrate FWaaS policies", debug=False)
        start_group = datetime.now()
        self._migrate_fwaas_resource(
            'firewall_group', source_groups, dest_groups,
            self.prepare_fwaas_group,
            self.dest_neutron.create_fwaas_firewall_group)
        self._log_elapsed(start_group, "Migrate FWaaS groups", debug=False)
        self._log_elapsed(start, "Migrate FWaas V2", debug=False)
        LOG.info("FWaaS V2 migration done")

    def _delete_octavia_lb(self, body):
        kw = {'loadbalancer': body}
        self.octavia_rpc_client.call({}, 'loadbalancer_delete_cascade', **kw)

    def _create_lb_certificate(self, listener_dict):
        # Extract Octavia certificate data into a dict which is readable by
        # the listener_mgr

        def get_certificate(cert_data):
            if cert_data.certificate:
                return encodeutils.to_utf8(
                    cert_data.certificate.payload)
            return None

        def get_private_key(cert_data):
            if cert_data.private_key:
                return encodeutils.to_utf8(
                    cert_data.private_key.payload)
            return None

        def get_private_key_passphrase(cert_data):
            if cert_data.private_key_passphrase:
                return encodeutils.to_utf8(
                    cert_data.private_key_passphrase.payload)
            return None

        if listener_dict.get('default_tls_container_ref') and self.barbican:
            cert_data = self.barbican.containers.get(
                container_ref=listener_dict['default_tls_container_ref'])
            return {'ref': listener_dict['default_tls_container_ref'],
                    'certificate': get_certificate(cert_data),
                    'private_key': get_private_key(cert_data),
                    'passphrase': get_private_key_passphrase(cert_data)}

    def _migrate_octavia_lb(self, lb, orig_map, count, total_num):
        # Creating all loadbalancers resources on the new nsx driver
        # using RPC calls to the plugin listener.
        # Create the loadbalancer:
        start_lb = datetime.now()
        lb_body = self.prepare_lb_loadbalancer(lb)
        kw = {'loadbalancer': lb_body}
        if not self.octavia_rpc_client.call({}, 'loadbalancer_create', **kw):
            self.add_error("Failed to create loadbalancer (%s)" % lb_body)
            self._delete_octavia_lb(lb_body)
            return

        lb_id = lb['id']
        lb_body_for_deletion = copy.deepcopy(lb_body)
        lb_body_for_deletion['listeners'] = []
        lb_body_for_deletion['pools'] = []
        LOG.debug("Migrating load balancer: %s", lb_id)

        listeners_map = {}
        for listener_dict in lb.get('listeners', []):
            start_listener = datetime.now()
            listener_id = listener_dict['id']
            LOG.debug("Migrating listener: %s", listener_id)
            listener = orig_map['listeners'][listener_id]
            cert = self._create_lb_certificate(listener)
            body = self.prepare_lb_listener(listener, lb_body)
            body['loadbalancer'] = lb_body
            body['loadbalancer_id'] = lb_id
            kw = {'listener': body, 'cert': cert}
            if not self.octavia_rpc_client.call({}, 'listener_create', **kw):
                self.add_error("Failed to create loadbalancer %(lb)s listener "
                               "(%(list)s)" % {'list': listener, 'lb': lb_id})
                self._delete_octavia_lb(lb_body_for_deletion)
                return
            listeners_map[listener_id] = body
            lb_body_for_deletion['listeners'].append(body)
            self._log_elapsed(
                start_listener, "Migrate Listener %s" % listener_id)

        for pool_dict in lb.get('pools', []):
            start_pool = datetime.now()
            pool_id = pool_dict['id']
            LOG.debug("Migrating pool: %s", pool_id)
            pool = orig_map['pools'][pool_id]
            pool_body = self.prepare_lb_pool(pool, lb_body)
            # Update listeners in pool
            if pool.get('listeners'):
                listener_id = pool['listeners'][0]['id']
                pool_body['listener_id'] = listener_id
                pool_body['listener'] = listeners_map.get(listener_id)
            kw = {'pool': pool_body}
            if not self.octavia_rpc_client.call({}, 'pool_create', **kw):
                self.add_error("Failed to create loadbalancer %(lb)s pool "
                               "(%(pool)s)" % {'pool': pool, 'lb': lb_id})
                self._delete_octavia_lb(lb_body_for_deletion)
                return
            lb_body_for_deletion['pools'].append(pool)

            # Add members to this pool
            pool_members = self.octavia.member_list(pool_id)['members']
            for member in pool_members:
                body = self.prepare_lb_member(member, lb_body)
                if not member['subnet_id']:
                    # Add the loadbalancer subnet
                    body['subnet_id'] = lb_body['vip_subnet_id']

                body['pool'] = pool_body
                kw = {'member': body}
                if not self.octavia_rpc_client.call({}, 'member_create', **kw):
                    self.add_error("Failed to create pool %(pool)s member "
                                   "(%(member)s)" %
                                   {'member': member, 'pool': pool_id})
                    self._delete_octavia_lb(lb_body_for_deletion)
                    return

            # Add pool health monitor
            if pool.get('healthmonitor_id'):
                hm_id = pool['healthmonitor_id']
                hm = orig_map['hms'][hm_id]
                body = self.prepare_lb_hm(hm)
                body['pool'] = pool_body
                # Update pool id in hm
                kw = {'healthmonitor': body}
                if not self.octavia_rpc_client.call(
                        {}, 'healthmonitor_create', **kw):
                    self.add_error("Failed to create pool %(pool)s "
                                   "healthmonitor (%(hm)s)" %
                                   {'hm': hm, 'pool': pool_id})
                    self._delete_octavia_lb(lb_body_for_deletion)
                    return
                lb_body_for_deletion['pools'][-1]['healthmonitor'] = body
            self._log_elapsed(start_pool, "Migrate LB Pool %s" % pool_id)

        # Add listeners L7 policies
        for listener_id in listeners_map.keys():
            listener = orig_map['listeners'][listener_id]
            for l7pol_dict in listener.get('l7policies', []):
                start_l7pol = datetime.now()
                l7_pol_id = l7pol_dict['id']
                LOG.debug("Migrating L7 policy %s for listener %s",
                          l7_pol_id, listener_id)
                l7pol = orig_map['l7pols'][l7_pol_id]
                pol_body = self.prepare_lb_l7policy(l7pol)

                # Add the rules of this policy
                source_l7rules = self.octavia.l7rule_list(
                    l7_pol_id)['rules']
                for rule in source_l7rules:
                    rule_body = self.prepare_lb_l7rule(rule)
                    pol_body['rules'].append(rule_body)

                kw = {'l7policy': pol_body}
                if not self.octavia_rpc_client.call(
                        {}, 'l7policy_create', **kw):
                    self.add_error("Failed to create l7policy "
                                   "(%(l7pol)s)" % {'l7pol': l7pol})
                    self._delete_octavia_lb(lb_body_for_deletion)
                    return
                self._log_elapsed(
                    start_l7pol, "Migrate L7 LB policy %s" % l7_pol_id)
        self._log_elapsed(start_lb, "Migrate Load Balancer %s" % lb_id)
        LOG.info("Created loadbalancer %s/%s: %s", count, total_num, lb_id)

    def _map_orig_objects_of_type(self, source_objects):
        result = {}
        for obj in source_objects:
            result[obj['id']] = obj
        return result

    def _map_orig_lb_objects(self, source_listeners, source_pools,
                             source_hms, source_l7pols):
        result = {
            'listeners': self._map_orig_objects_of_type(source_listeners),
            'pools': self._map_orig_objects_of_type(source_pools),
            'hms': self._map_orig_objects_of_type(source_hms),
            'l7pols': self._map_orig_objects_of_type(source_l7pols),
        }
        return result

    def migrate_octavia(self, source_networks):
        """Migrates Octavia NSX objects to the new neutron driver.
        The Octavia process & DB will remain unchanged.
        Using RPC connection to connect directly with the new plugin driver.
        """
        # Read all existing octavia resources
        start = datetime.now()
        try:
            loadbalancers = self.octavia.load_balancer_list()['loadbalancers']
            listeners = self.octavia.listener_list()['listeners']
            pools = self.octavia.pool_list()['pools']
            hms = self.octavia.health_monitor_list()['healthmonitors']
            l7pols = self.octavia.l7policy_list()['l7policies']
        except Exception as e:
            # Octavia might be disabled in the source
            LOG.info("Octavia was not found on the server: %s", e)
            return

        # Init the RPC connection for sending messages to the octavia driver
        topic = d_const.OCTAVIA_TO_DRIVER_MIGRATION_TOPIC
        transport = messaging.get_rpc_transport(cfg.CONF)
        target = messaging.Target(topic=topic, exchange="common",
                                  namespace='control', fanout=False,
                                  version='1.0')
        self.octavia_rpc_client = messaging.RPCClient(transport, target)

        # Initialize RPC listener for getting status updates from the driver
        # so that the resource status will not change in the octavia DB
        topic = d_const.DRIVER_TO_OCTAVIA_MIGRATION_TOPIC
        server = socket.gethostname()
        target = messaging.Target(topic=topic, server=server,
                                  exchange="common", fanout=False)

        class MigrationOctaviaDriverEndpoint(driver_lib.DriverLibrary):
            target = messaging.Target(namespace="control", version='1.0')

            def update_loadbalancer_status(self, **kw):
                # Do nothing
                pass

            def update_listener_statistics(self, **kw):
                # Do nothing
                pass

            def get_active_loadbalancers(self, **kw):
                # Do nothing
                pass

        endpoints = [MigrationOctaviaDriverEndpoint]
        access_policy = dispatcher.DefaultRPCAccessPolicy
        self.octavia_rpc_server = messaging.get_rpc_server(
            transport, target, endpoints, executor='threading',
            access_policy=access_policy)
        self.octavia_rpc_server.start()

        orig_map = self._map_orig_lb_objects(listeners, pools,
                                             hms, l7pols)
        total_num = len(loadbalancers)
        LOG.info("Migrating %d loadbalancer(s)", total_num)
        # In order to avoid failures in NSX-T, migrate the external LB first.
        # Otherwise neutron might create a new LBS and try to attach it to
        # a T1 GW where another LBS is already attached'
        network_dict = {network['id']: network for network in source_networks}
        external_lb = []
        internal_lb = []
        for lb in loadbalancers:
            network_id = lb.get('vip_network_id')
            if not network_id:
                LOG.warning("Load balancer %s does not have vip_network_id."
                            "Considering it as LB on internal network",
                            lb['id'])
                internal_lb.append(lb)
                continue
            network = network_dict.get(network_id)
            if not network:
                self.add_error(
                    "Load balancer %s is configured on network %s, "
                    "whichs seem to not exist in neutron" %
                    (lb['id'], network_id))
                continue
            if network['router:external']:
                external_lb.append(lb)
            else:
                internal_lb.append(lb)

        LOG.info("Migrating %d loadbalancers on external networks and then "
                 "%d loadbalancers on internal networks",
                 len(external_lb), len(internal_lb))
        for lb_list in [external_lb, internal_lb]:
            for count, lb in enumerate(lb_list, 1):
                if lb['provisioning_status'] == 'ACTIVE':
                    self._migrate_octavia_lb(lb, orig_map, count, total_num)
                else:
                    LOG.info("Skipping %s loadbalancer %s",
                            lb['provisioning_status'], lb['id'])
        self._log_elapsed(start, "Migrate Octavia LBs", debug=False)
