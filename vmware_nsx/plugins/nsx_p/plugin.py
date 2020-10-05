# Copyright 2018 VMware, Inc.
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

import time

import netaddr

from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_log import log
from oslo_utils import excutils
from oslo_utils import uuidutils

from neutron.common import ipv6_utils
from neutron.db import agents_db
from neutron.db import l3_db
from neutron.db.models import l3 as l3_db_models
from neutron.db.models import securitygroup as securitygroup_model
from neutron.db import models_v2
from neutron.extensions import securitygroup as ext_sg
from neutron.quota import resource_registry
from neutron_lib.api.definitions import address_scope
from neutron_lib.api.definitions import agent as agent_apidef
from neutron_lib.api.definitions import allowedaddresspairs as addr_apidef
from neutron_lib.api.definitions import availability_zone as az_apidef
from neutron_lib.api.definitions import dhcpagentscheduler
from neutron_lib.api.definitions import external_net
from neutron_lib.api.definitions import extra_dhcp_opt as ext_edo
from neutron_lib.api.definitions import extraroute
from neutron_lib.api.definitions import l3 as l3_apidef
from neutron_lib.api.definitions import network_availability_zone
from neutron_lib.api.definitions import port_security as psec
from neutron_lib.api.definitions import portbindings as pbin_apidef
from neutron_lib.api.definitions import provider_net as pnet_apidef
from neutron_lib.api.definitions import router_availability_zone
from neutron_lib.api.definitions import vlantransparent as vlan_apidef
from neutron_lib.api import extensions
from neutron_lib.api import validators
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants as const
from neutron_lib import context as n_context
from neutron_lib.db import api as db_api
from neutron_lib.db import resource_extend
from neutron_lib.db import utils as db_utils
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import constants as plugin_const
from neutron_lib.plugins import directory
from neutron_lib.services.qos import constants as qos_consts

from vmware_nsx._i18n import _
from vmware_nsx.common import config  # noqa
from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.common import l3_rpc_agent_api
from vmware_nsx.common import locking
from vmware_nsx.common import managers
from vmware_nsx.common import utils
from vmware_nsx.db import db as nsx_db
from vmware_nsx.extensions import api_replay
from vmware_nsx.extensions import maclearning as mac_ext
from vmware_nsx.extensions import projectpluginmap
from vmware_nsx.extensions import providersecuritygroup as provider_sg
from vmware_nsx.extensions import secgroup_rule_local_ip_prefix as sg_prefix
from vmware_nsx.extensions import securitygrouplogging as sg_logging
from vmware_nsx.plugins.common_v3 import plugin as nsx_plugin_common
from vmware_nsx.plugins.common_v3 import utils as v3_utils
from vmware_nsx.plugins.nsx_p import availability_zones as nsxp_az
from vmware_nsx.plugins.nsx_p import utils as plugin_utils
from vmware_nsx.services.fwaas.common import utils as fwaas_utils
from vmware_nsx.services.fwaas.nsx_p import fwaas_callbacks_v2
from vmware_nsx.services.lbaas import lb_const
from vmware_nsx.services.lbaas.nsx_p.implementation import healthmonitor_mgr
from vmware_nsx.services.lbaas.nsx_p.implementation import l7policy_mgr
from vmware_nsx.services.lbaas.nsx_p.implementation import l7rule_mgr
from vmware_nsx.services.lbaas.nsx_p.implementation import lb_utils
from vmware_nsx.services.lbaas.nsx_p.implementation import listener_mgr
from vmware_nsx.services.lbaas.nsx_p.implementation import loadbalancer_mgr
from vmware_nsx.services.lbaas.nsx_p.implementation import member_mgr
from vmware_nsx.services.lbaas.nsx_p.implementation import pool_mgr
from vmware_nsx.services.lbaas.octavia import constants as oct_const
from vmware_nsx.services.lbaas.octavia import octavia_listener
from vmware_nsx.services.qos.common import utils as qos_com_utils
from vmware_nsx.services.qos.nsx_v3 import driver as qos_driver
from vmware_nsx.services.qos.nsx_v3 import pol_utils as qos_utils
from vmware_nsx.services.trunk.nsx_p import driver as trunk_driver

from vmware_nsxlib.v3 import exceptions as nsx_lib_exc
from vmware_nsxlib.v3 import nsx_constants as nsxlib_consts
from vmware_nsxlib.v3.policy import constants as policy_constants
from vmware_nsxlib.v3.policy import core_defs as policy_defs
from vmware_nsxlib.v3.policy import transaction as policy_trans
from vmware_nsxlib.v3.policy import utils as p_utils
from vmware_nsxlib.v3 import utils as nsxlib_utils

LOG = log.getLogger(__name__)
NSX_P_SECURITY_GROUP_TAG = 'os-security-group'
NSX_P_GLOBAL_DOMAIN_ID = policy_constants.DEFAULT_DOMAIN
NSX_P_DEFAULT_GROUP = 'os_default_group'
NSX_P_DEFAULT_GROUP_DESC = 'Default Group for the openstack plugin'
NSX_P_DEFAULT_SECTION = 'os_default_section'
NSX_P_DEFAULT_SECTION_DESC = ('This section is handled by OpenStack to '
                              'contain default rules on security-groups.')
NSX_P_DEFAULT_SECTION_CATEGORY = policy_constants.CATEGORY_APPLICATION
NSX_P_REGULAR_SECTION_CATEGORY = policy_constants.CATEGORY_ENVIRONMENT
NSX_P_PROVIDER_SECTION_CATEGORY = policy_constants.CATEGORY_INFRASTRUCTURE
NSX_P_PORT_RESOURCE_TYPE = 'os-neutron-port-id'
NSX_P_EXCLUDE_LIST_GROUP = 'neutron_excluded_ports_group'
NSX_P_EXCLUDE_LIST_TAG = 'Exclude-Port'

SPOOFGUARD_PROFILE_ID = 'neutron-spoofguard-profile'
NO_SPOOFGUARD_PROFILE_ID = policy_defs.SpoofguardProfileDef.DEFAULT_PROFILE
MAC_DISCOVERY_PROFILE_ID = 'neutron-mac-discovery-profile'
NO_MAC_DISCOVERY_PROFILE_ID = (
    policy_defs.MacDiscoveryProfileDef.DEFAULT_PROFILE)
NO_SEG_SECURITY_PROFILE_ID = 'neutron-no-segment-security-profile'
SEG_SECURITY_PROFILE_ID = (
    policy_defs.SegmentSecurityProfileDef.DEFAULT_PROFILE)
SLAAC_NDRA_PROFILE_ID = 'neutron-slaac-profile'
NO_SLAAC_NDRA_PROFILE_ID = 'neutron-no-slaac-profile'
STATELESS_DHCP_NDRA_PROFILE_ID = 'neutron-stateless-dhcp-profile'
STATEFUL_DHCP_NDRA_PROFILE_ID = 'neutron-stateful-dhcp-profile'

IPV6_RA_SERVICE = 'neutron-ipv6-ra'
IPV6_ROUTER_ADV_RULE_NAME = 'all-ipv6'

# Priorities for NAT rules: (FIP specific rules should come before GW rules)
NAT_RULE_PRIORITY_FIP = 2000
NAT_RULE_PRIORITY_GW = 3000

NSX_P_CLIENT_SSL_PROFILE = 'neutron-client-ssl-profile'

# Cache for mapping between network ids in neutron and NSX (MP)
NET_NEUTRON_2_NSX_ID_CACHE = {}
NET_NSX_2_NEUTRON_ID_CACHE = {}


@resource_extend.has_resource_extenders
class NsxPolicyPlugin(nsx_plugin_common.NsxPluginV3Base):

    __native_bulk_support = True
    __native_pagination_support = True
    __native_sorting_support = True

    supported_extension_aliases = [addr_apidef.ALIAS,
                                   address_scope.ALIAS,
                                   "quotas",
                                   pbin_apidef.ALIAS,
                                   ext_edo.ALIAS,
                                   agent_apidef.ALIAS,
                                   dhcpagentscheduler.ALIAS,
                                   "ext-gw-mode",
                                   "security-group",
                                   sg_prefix.ALIAS,
                                   psec.ALIAS,
                                   pnet_apidef.ALIAS,
                                   external_net.ALIAS,
                                   extraroute.ALIAS,
                                   l3_apidef.ALIAS,
                                   az_apidef.ALIAS,
                                   network_availability_zone.ALIAS,
                                   router_availability_zone.ALIAS,
                                   "subnet_allocation",
                                   sg_logging.ALIAS,
                                   provider_sg.ALIAS,
                                   "port-security-groups-filtering",
                                   mac_ext.ALIAS,
                                   "advanced-service-providers"]

    @resource_registry.tracked_resources(
        network=models_v2.Network,
        port=models_v2.Port,
        subnet=models_v2.Subnet,
        subnetpool=models_v2.SubnetPool,
        security_group=securitygroup_model.SecurityGroup,
        security_group_rule=securitygroup_model.SecurityGroupRule,
        router=l3_db_models.Router,
        floatingip=l3_db_models.FloatingIP)
    def __init__(self):
        self.fwaas_callbacks = None
        self.init_is_complete = False
        self._is_sub_plugin = False
        self.octavia_listener = None
        self.octavia_stats_collector = None
        nsxlib_utils.set_is_attr_callback(validators.is_attr_set)
        self._extend_fault_map()
        extension_drivers = cfg.CONF.nsx_extension_drivers
        self._extension_manager = managers.ExtensionManager(
            extension_drivers=extension_drivers)
        self.cfg_group = 'nsx_p'  # group name for nsx_p section in nsx.ini
        self.init_availability_zones()

        self.nsxpolicy = v3_utils.get_nsxpolicy_wrapper()
        # NOTE: This is needed for passthrough APIs, should be removed when
        # policy has full support
        self.nsxlib = self.nsxpolicy.get_nsxlib_passthrough()

        super(NsxPolicyPlugin, self).__init__()

        # Bind the dummy L3 notifications
        self.l3_rpc_notifier = l3_rpc_agent_api.L3NotifyAPI()
        LOG.info("Starting NsxPolicyPlugin")
        self._extension_manager.initialize()
        self.supported_extension_aliases.extend(
            self._extension_manager.extension_aliases())

        # Support transparent VLANS only if the global configuration flag
        # vlan_transparent is True
        if cfg.CONF.vlan_transparent:
            self.supported_extension_aliases.append(vlan_apidef.ALIAS)

        # Support api-reply for migration environments to the policy plugin
        if cfg.CONF.api_replay_mode:
            self.supported_extension_aliases.append(api_replay.ALIAS)

        nsxlib_utils.set_inject_headers_callback(v3_utils.inject_headers)
        self._validate_nsx_policy_version()
        self._validate_config()

        self._init_default_config()
        self._prepare_default_rules()
        self._init_profiles()
        self._prepare_exclude_list()
        self._init_dhcp_metadata()

        # Init QoS
        qos_driver.register(qos_utils.PolicyQosNotificationsHandler())

        # Register NSXP trunk driver to support trunk extensions
        self.trunk_driver = trunk_driver.NsxpTrunkDriver.create(self)

        registry.subscribe(self.spawn_complete,
                           resources.PROCESS,
                           events.AFTER_SPAWN)

        # subscribe the init complete method last, so it will be called only
        # if init was successful
        registry.subscribe(self.init_complete,
                           resources.PROCESS,
                           events.AFTER_INIT)

    def _validate_config(self):
        if cfg.CONF.ipam_driver != 'internal':
            msg = _("External IPAM drivers not supported with nsxp plugin")
            LOG.error(msg)
            raise n_exc.InvalidInput(error_message=msg)

    def _enable_ipv6_routing(self):
        # Ipv6 is disabled by default in NSX and should be enabled
        if self.nsxpolicy.feature_supported(
            nsxlib_consts.FEATURE_NSX_POLICY_GLOBAL_CONFIG):
            self.nsxpolicy.global_config.enable_ipv6()
            return

        if cfg.CONF.nsx_p.allow_passthrough:
            self.nsxlib.global_routing.enable_ipv6()
        else:
            LOG.warning("Unable to switch on Ipv6 forwarding. Ipv6 "
                        "connectivity might be broken.")

    def _init_default_config(self):

        self._enable_ipv6_routing()

        # Validate other mandatory configuration
        if not cfg.CONF.nsx_p.dhcp_profile:
            raise cfg.RequiredOptError("dhcp_profile",
                                       group=cfg.OptGroup('nsx_p'))

        if not cfg.CONF.nsx_p.metadata_proxy:
            raise cfg.RequiredOptError("metadata_proxy",
                                       group=cfg.OptGroup('nsx_p'))

        # If using tags to find the objects, make sure tag scope is configured
        if (cfg.CONF.nsx_p.init_objects_by_tags and
            not cfg.CONF.nsx_p.search_objects_scope):
            raise cfg.RequiredOptError("search_objects_scope",
                                       group=cfg.OptGroup('nsx_p'))

        # Init AZ resources
        search_scope = (cfg.CONF.nsx_p.search_objects_scope
                        if cfg.CONF.nsx_p.init_objects_by_tags else None)
        for az in self.get_azs_list():
            az.translate_configured_names_to_uuids(
                self.nsxpolicy, nsxlib=self.nsxlib, search_scope=search_scope)
            az.validate_availability_zone(self.nsxpolicy, nsxlib=self.nsxlib)

        # WAF is currently not supported by the NSX
        self._waf_profile_uuid = None

        try:
            self.nsxpolicy.mixed_service.get(IPV6_RA_SERVICE)
        except nsx_lib_exc.ResourceNotFound:
            # create or override ipv6 RA service
            unicast_ra = self.nsxpolicy.icmp_service.build_entry(
                'unicast RA', IPV6_RA_SERVICE, 'unicast',
                version=6, icmp_type=134)
            multicast_ra = self.nsxpolicy.icmp_service.build_entry(
                'multicast RA', IPV6_RA_SERVICE, 'multicast',
                version=6, icmp_type=151)

            try:
                self.nsxpolicy.mixed_service.create_or_overwrite(
                    IPV6_RA_SERVICE, IPV6_RA_SERVICE,
                    entries=[unicast_ra, multicast_ra])
            except nsx_lib_exc.StaleRevision as e:
                # This means that another controller is also creating this
                LOG.info("Failed to configure mixed_service: %s", e)
            except nsx_lib_exc.ManagerError:
                msg = _("Failed to configure RA service for IPv6 connectivity")
                LOG.error(msg)
                raise nsx_exc.NsxPluginException(err_msg=msg)

    def _init_backend_resource(self, resource_api, name_or_id,
                               search_scope=None):
        resource_type = resource_api.entry_def.resource_type()
        if not name_or_id:
            return None
        try:
            # Check if the configured value is the ID
            resource_api.get(name_or_id, silent=True)
            return name_or_id
        except nsx_lib_exc.ResourceNotFound:
            # Search by tags
            if search_scope:
                resource_id = self.nsxpolicy.get_id_by_resource_and_tag(
                    resource_type,
                    search_scope,
                    name_or_id)
                if resource_id:
                    return resource_id

            # Check if the configured value is the name
            resource = resource_api.get_by_name(name_or_id)
            if resource:
                return resource['id']

        msg = (_("Could not find %(type)s %(id)s") % {
            'type': resource_type, 'id': name_or_id})
        raise nsx_exc.NsxPluginException(err_msg=msg)

    def get_waf_profile_path_and_mode(self):
        # WAF is currently not supported by the NSX
        return None, None

    def _init_dhcp_metadata(self):
        if cfg.CONF.dhcp_agent_notification:
            msg = _("Need to disable dhcp_agent_notification when "
                    "native DHCP & Metadata is enabled")
            raise nsx_exc.NsxPluginException(err_msg=msg)

        default_az = self.get_default_az()
        if default_az.use_policy_dhcp:
            self.use_policy_dhcp = True
            LOG.info("The policy plugin will use policy based DHCP v4/6")
        else:
            self._init_native_dhcp()
            self.use_policy_dhcp = False
            LOG.info("The policy plugin will use MP based DHCP v4")

        self._init_native_metadata()

    def init_availability_zones(self):
        self._availability_zones_data = nsxp_az.NsxPAvailabilityZones()

    def _validate_nsx_policy_version(self):
        self._nsx_version = self.nsxpolicy.get_version()
        LOG.info("NSX Version: %s", self._nsx_version)
        if (not self.nsxpolicy.feature_supported(
                nsxlib_consts.FEATURE_NSX_POLICY_NETWORKING) or
            not utils.is_nsx_version_2_5_0(self._nsx_version)):
            msg = (_("The NSX Policy plugin requires version 2.5 "
                     "(current version %(ver)s)") % {'ver': self._nsx_version})
            raise nsx_exc.NsxPluginException(err_msg=msg)

    def _init_profiles(self):
        """Find/Create segment profiles this plugin will use"""
        # Spoofguard profile (find it or create)
        try:
            self.nsxpolicy.spoofguard_profile.get(SPOOFGUARD_PROFILE_ID,
                                                  silent=True)
        except nsx_lib_exc.ResourceNotFound:
            try:
                self.nsxpolicy.spoofguard_profile.create_or_overwrite(
                    SPOOFGUARD_PROFILE_ID,
                    profile_id=SPOOFGUARD_PROFILE_ID,
                    address_binding_whitelist=True,
                    tags=self.nsxpolicy.build_v3_api_version_tag())
            except nsx_lib_exc.StaleRevision as e:
                # This means that another controller is also creating this
                LOG.info("Failed to configure spoofguard_profile: %s", e)

        # No Port security spoofguard profile
        # (default NSX profile. just verify it exists)
        try:
            self.nsxpolicy.spoofguard_profile.get(NO_SPOOFGUARD_PROFILE_ID,
                                                  silent=True)
        except nsx_lib_exc.ResourceNotFound:
            msg = (_("Cannot find spoofguard profile %s") %
                   NO_SPOOFGUARD_PROFILE_ID)
            raise nsx_exc.NsxPluginException(err_msg=msg)

        # Mac discovery profile (find it or create)
        try:
            self.nsxpolicy.mac_discovery_profile.get(
                MAC_DISCOVERY_PROFILE_ID, silent=True)
        except nsx_lib_exc.ResourceNotFound:
            try:
                self.nsxpolicy.mac_discovery_profile.create_or_overwrite(
                    MAC_DISCOVERY_PROFILE_ID,
                    profile_id=MAC_DISCOVERY_PROFILE_ID,
                    mac_change_enabled=True,
                    mac_learning_enabled=True,
                    tags=self.nsxpolicy.build_v3_api_version_tag())
            except nsx_lib_exc.StaleRevision as e:
                # This means that another controller is also creating this
                LOG.info("Failed to configure mac_discovery_profile: %s", e)

        # No Mac discovery profile profile
        # (default NSX profile. just verify it exists)
        try:
            self.nsxpolicy.mac_discovery_profile.get(
                NO_MAC_DISCOVERY_PROFILE_ID, silent=True)
        except nsx_lib_exc.ResourceNotFound:
            msg = (_("Cannot find MAC discovery profile %s") %
                   NO_MAC_DISCOVERY_PROFILE_ID)
            raise nsx_exc.NsxPluginException(err_msg=msg)

        # No Port security segment-security profile (find it or create)
        try:
            self.nsxpolicy.segment_security_profile.get(
                NO_SEG_SECURITY_PROFILE_ID, silent=True)
        except nsx_lib_exc.ResourceNotFound:
            try:
                self.nsxpolicy.segment_security_profile.create_or_overwrite(
                    NO_SEG_SECURITY_PROFILE_ID,
                    profile_id=NO_SEG_SECURITY_PROFILE_ID,
                    bpdu_filter_enable=False,
                    dhcp_client_block_enabled=False,
                    dhcp_client_block_v6_enabled=False,
                    dhcp_server_block_enabled=False,
                    dhcp_server_block_v6_enabled=False,
                    non_ip_traffic_block_enabled=False,
                    ra_guard_enabled=False,
                    rate_limits_enabled=False,
                    tags=self.nsxpolicy.build_v3_api_version_tag())
            except nsx_lib_exc.StaleRevision as e:
                # This means that another controller is also creating this
                LOG.info("Failed to configure segment_security_profile: %s", e)

        # Port security segment-security profile
        # (default NSX profile. just verify it exists)
        try:
            self.nsxpolicy.segment_security_profile.get(
                SEG_SECURITY_PROFILE_ID, silent=True)
        except nsx_lib_exc.ResourceNotFound:
            msg = (_("Cannot find segment security profile %s") %
                   SEG_SECURITY_PROFILE_ID)
            raise nsx_exc.NsxPluginException(err_msg=msg)

        # Find or create all neutron NDRA profiles
        ndra_profiles = {
            SLAAC_NDRA_PROFILE_ID: policy_constants.IPV6_RA_MODE_SLAAC_RA,
            STATELESS_DHCP_NDRA_PROFILE_ID:
                policy_constants.IPV6_RA_MODE_SLAAC_DHCP,
            STATEFUL_DHCP_NDRA_PROFILE_ID: policy_constants.IPV6_RA_MODE_DHCP,
            NO_SLAAC_NDRA_PROFILE_ID: policy_constants.IPV6_RA_MODE_DISABLED
        }

        for profile in ndra_profiles:
            try:
                self.nsxpolicy.ipv6_ndra_profile.get(profile, silent=True)
            except nsx_lib_exc.ResourceNotFound:
                try:
                    self.nsxpolicy.ipv6_ndra_profile.create_or_overwrite(
                        profile,
                        profile_id=profile,
                        ra_mode=ndra_profiles[profile],
                        tags=self.nsxpolicy.build_v3_api_version_tag())
                except nsx_lib_exc.StaleRevision as e:
                    # This means that another controller is also creating this
                    LOG.info("Failed to configure ipv6_ndra_profile %s: %s",
                             profile, e)

        self.client_ssl_profile = None

        LOG.debug("Initializing NSX-P Load Balancer default profiles")
        try:
            self._init_lb_profiles()
        except Exception as e:
            msg = (_("Unable to initialize NSX-P lb profiles: "
                     "Reason: %(reason)s") % {'reason': str(e)})
            raise nsx_exc.NsxPluginException(err_msg=msg)

    @staticmethod
    def plugin_type():
        return projectpluginmap.NsxPlugins.NSX_P

    @staticmethod
    def is_tvd_plugin():
        return False

    def _init_fwaas(self, with_rpc):
        if self.fwaas_callbacks:
            # already initialized
            return

        if fwaas_utils.is_fwaas_v2_plugin_enabled():
            LOG.info("NSXp FWaaS v2 plugin enabled")
            self.fwaas_callbacks = fwaas_callbacks_v2.NsxpFwaasCallbacksV2(
                with_rpc)

    def _get_octavia_stats_getter(self):
        return listener_mgr.stats_getter

    def _get_octavia_status_getter(self):
        return loadbalancer_mgr.status_getter

    def _init_lb_profiles(self):
        ssl_profile_client = self.nsxpolicy.load_balancer.client_ssl_profile
        with locking.LockManager.get_lock('nsxp_lb_profiles_init'):
            try:
                ssl_profile_client.get(NSX_P_CLIENT_SSL_PROFILE)
            except nsx_lib_exc.ResourceNotFound:
                try:
                    ssl_profile_client.create_or_overwrite(
                        NSX_P_CLIENT_SSL_PROFILE,
                        client_ssl_profile_id=NSX_P_CLIENT_SSL_PROFILE,
                        description='Neutron LB Client SSL Profile',
                        tags=self.nsxpolicy.build_v3_api_version_tag())
                except nsx_lib_exc.StaleRevision as e:
                    # This means that another controller is also creating this
                    LOG.info("Failed to configure LB client_ssl_profile: %s",
                             e)
            self.client_ssl_profile = NSX_P_CLIENT_SSL_PROFILE

    def spawn_complete(self, resource, event, trigger, payload=None):
        # Init the FWaaS support with RPC listeners for the original process
        self._init_fwaas(with_rpc=True)

        self._init_octavia()
        self.octavia_stats_collector = (
            octavia_listener.NSXOctaviaStatisticsCollector(
                self,
                self._get_octavia_stats_getter(),
                self._get_octavia_status_getter()))

    def _init_octavia(self):
        octavia_objects = self._get_octavia_objects()
        self.octavia_listener = octavia_listener.NSXOctaviaListener(
            **octavia_objects)

    def _get_octavia_objects(self):
        return {
            'loadbalancer': loadbalancer_mgr.EdgeLoadBalancerManagerFromDict(),
            'listener': listener_mgr.EdgeListenerManagerFromDict(),
            'pool': pool_mgr.EdgePoolManagerFromDict(),
            'member': member_mgr.EdgeMemberManagerFromDict(),
            'healthmonitor':
                healthmonitor_mgr.EdgeHealthMonitorManagerFromDict(),
            'l7policy': l7policy_mgr.EdgeL7PolicyManagerFromDict(),
            'l7rule': l7rule_mgr.EdgeL7RuleManagerFromDict()}

    def init_complete(self, resource, event, trigger, payload=None):
        with locking.LockManager.get_lock('plugin-init-complete'):
            if self.init_is_complete:
                # Should be called only once per worker
                return

            # reinitialize the cluster upon fork for api workers to ensure
            # each process has its own keepalive loops + state
            self.nsxpolicy.reinitialize_cluster(resource, event, trigger,
                                                payload=payload)

            # Init the FWaaS support without RPC listeners
            # for the spawn workers
            self._init_fwaas(with_rpc=False)

            # Init octavia listener and endpoints
            self._init_octavia()

            self.init_is_complete = True

    def _setup_rpc(self):
        self.endpoints = [agents_db.AgentExtRpcCallback()]

    def _net_nsx_name(self, network):
        return utils.get_name_and_uuid(network['name'] or 'network',
                                       network['id'])

    def _create_network_on_backend(self, context, net_data,
                                   transparent_vlan,
                                   provider_data, az):
        net_data['id'] = net_data.get('id') or uuidutils.generate_uuid()

        # update the network name to indicate the neutron id too.
        net_name = self._net_nsx_name(net_data)
        tags = self.nsxpolicy.build_v3_tags_payload(
            net_data, resource_type='os-neutron-net-id',
            project_name=context.tenant_name)

        admin_state = net_data.get('admin_state_up', True)
        LOG.debug('create_network: %(net_name)s, %(physical_net)s, '
                  '%(tags)s, %(admin_state)s, %(vlan_id)s',
                  {'net_name': net_name,
                   'physical_net': provider_data['physical_net'],
                   'tags': tags,
                   'admin_state': admin_state,
                   'vlan_id': provider_data['vlan_id']})
        if transparent_vlan:
            # all vlan tags are allowed for guest vlan
            vlan_ids = ["0-%s" % const.MAX_VLAN_TAG]
        elif provider_data['vlan_id']:
            vlan_ids = [provider_data['vlan_id']]
        else:
            vlan_ids = None

        kwargs = {
            'segment_id': net_data['id'],
            'description': net_data.get('description'),
            'vlan_ids': vlan_ids,
            'transport_zone_id': provider_data['physical_net'],
            'tags': tags}

        if (not admin_state and
            self.nsxpolicy.feature_supported(
                nsxlib_consts.FEATURE_NSX_POLICY_ADMIN_STATE)):
            kwargs['admin_state'] = admin_state

        if az.use_policy_md:
            kwargs['metadata_proxy_id'] = az._native_md_proxy_uuid

        self.nsxpolicy.segment.create_or_overwrite(
            net_name, **kwargs)

        if (not admin_state and cfg.CONF.nsx_p.allow_passthrough and
            not self.nsxpolicy.feature_supported(
                nsxlib_consts.FEATURE_NSX_POLICY_ADMIN_STATE)):
            # This api uses the passthrough api
            self.nsxpolicy.segment.set_admin_state(
                net_data['id'], admin_state)

    def _tier0_validator(self, tier0_uuid):
        # Fail if the tier0 uuid was not found on the NSX
        try:
            self.nsxpolicy.tier0.get(tier0_uuid)
        except Exception:
            msg = (_("Cannot create external network as Tier0 %s was not "
                     "found") % tier0_uuid)
            raise n_exc.InvalidInput(error_message=msg)

    def _get_nsx_net_tz_id(self, nsx_net):
        return nsx_net['transport_zone_path'].split('/')[-1]

    def _allow_ens_networks(self):
        return True

    def _ens_qos_supported(self):
        return self.nsxpolicy.feature_supported(
            nsxlib_consts.FEATURE_ENS_WITH_QOS)

    def _assert_on_resource_admin_state_down(self, resource_data):
        """Network & port admin state is only supported with passthrough api"""
        if (not cfg.CONF.nsx_p.allow_passthrough and
            resource_data.get("admin_state_up") is False):
            err_msg = (_("admin_state_up=False is not supported when "
                         "passthrough is disabled"))
            LOG.warning(err_msg)
            raise n_exc.InvalidInput(error_message=err_msg)

    def create_network(self, context, network):
        net_data = network['network']
        external = net_data.get(external_net.EXTERNAL)
        is_external_net = validators.is_attr_set(external) and external
        tenant_id = net_data['tenant_id']

        # validate the availability zone, and get the AZ object
        az = self._validate_obj_az_on_creation(context, net_data, 'network')

        self._ensure_default_security_group(context, tenant_id)

        vlt = False
        if extensions.is_extension_supported(self, 'vlan-transparent'):
            vlt = vlan_apidef.get_vlan_transparent(net_data)

        self._validate_create_network(context, net_data)
        self._assert_on_resource_admin_state_down(net_data)

        if is_external_net:
            is_provider_net, net_type, physical_net, vlan_id = (
                self._validate_external_net_create(
                    net_data, az._default_tier0_router,
                    self._tier0_validator))
            provider_data = {'is_provider_net': is_provider_net,
                             'net_type': net_type,
                             'physical_net': physical_net,
                             'vlan_id': vlan_id}
            is_backend_network = False
        else:
            provider_data = self._validate_provider_create(
                context, net_data, az,
                self.nsxpolicy.transport_zone,
                self.nsxpolicy.segment,
                transparent_vlan=vlt)

            if (provider_data['is_provider_net'] and
                provider_data['net_type'] ==
                utils.NsxV3NetworkTypes.NSX_NETWORK):
                is_backend_network = False
            else:
                is_backend_network = True

        # Create the neutron network
        with db_api.CONTEXT_WRITER.using(context):
            # Create network in Neutron
            created_net = super(NsxPolicyPlugin, self).create_network(
                context, network)
            net_id = created_net['id']
            if extensions.is_extension_supported(self, 'vlan-transparent'):
                super(NsxPolicyPlugin, self).update_network(
                    context, net_id,
                    {'network': {'vlan_transparent': vlt}})
            self._extension_manager.process_create_network(
                context, net_data, created_net)
            if psec.PORTSECURITY not in net_data:
                net_data[psec.PORTSECURITY] = True
            self._process_network_port_security_create(
                context, net_data, created_net)
            self._process_l3_create(context, created_net, net_data)
            self._add_az_to_net(context, net_id, net_data)

            if provider_data['is_provider_net']:
                # Save provider network fields, needed by get_network()
                net_bindings = [nsx_db.add_network_binding(
                    context.session, net_id,
                    provider_data['net_type'],
                    provider_data['physical_net'],
                    provider_data['vlan_id'])]
                self._extend_network_dict_provider(context, created_net,
                                                   bindings=net_bindings)

        # Create the backend NSX network
        if is_backend_network:
            try:
                self._create_network_on_backend(
                    context, created_net, vlt, provider_data, az)
            except Exception as e:
                LOG.exception("Failed to create NSX network network: %s", e)
                with excutils.save_and_reraise_exception():
                    super(NsxPolicyPlugin, self).delete_network(
                        context, net_id)

        # this extra lookup is necessary to get the
        # latest db model for the extension functions
        net_model = self._get_network(context, net_id)
        resource_extend.apply_funcs('networks', created_net, net_model)

        # MD Proxy is currently supported by the passthrough api only
        if (is_backend_network and not az.use_policy_md and
            cfg.CONF.nsx_p.allow_passthrough):

            # The new segment was not realized yet. Waiting for a bit.
            time.sleep(cfg.CONF.nsx_p.realization_wait_sec)
            nsx_net_id = self._get_network_nsx_id(context, net_id)
            if not nsx_net_id:
                msg = ("Unable to obtain backend network id for metadata "
                       "proxy creation for network %s" % net_id)
                LOG.error(msg)
                raise nsx_exc.NsxPluginException(err_msg=msg)

            try:
                self._create_net_mp_mdproxy_port(
                    context, created_net, az, nsx_net_id)
            except Exception as e:
                msg = ("Failed to complete network creation. error: %s" % e)
                LOG.exception(msg)
                self.delete_network(context, net_id)
                raise nsx_exc.NsxPluginException(err_msg=msg)

        # Update the QoS policy (will affect only future compute ports)
        qos_com_utils.set_qos_policy_on_new_net(
            context, net_data, created_net)
        if net_data.get(qos_consts.QOS_POLICY_ID):
            LOG.info("QoS Policy %(qos)s will be applied to future compute "
                     "ports of network %(net)s",
                     {'qos': net_data[qos_consts.QOS_POLICY_ID],
                      'net': created_net['id']})

        return created_net

    def delete_network(self, context, network_id):
        is_external_net = self._network_is_external(context, network_id)

        if not is_external_net:
            # First disable DHCP & delete its port
            if self.use_policy_dhcp:
                lock = 'nsxp_network_' + network_id
                with locking.LockManager.get_lock(lock):
                    network = self._get_network(context, network_id)
                    if not self._has_active_port(context, network_id):
                        self._disable_network_dhcp(context, network)
            elif cfg.CONF.nsx_p.allow_passthrough:
                self._delete_network_disable_dhcp(context, network_id)

        is_nsx_net = self._network_is_nsx_net(context, network_id)

        # Call DB operation for delete network as it will perform
        # checks on active ports
        self._retry_delete_network(context, network_id)

        # Delete MD proxy port. This is relevant only if the plugin used
        # MP MD proxy when this network is created.
        # If not - the port will not be found, and it is ok.
        # Note(asarfaty): In the future this code can be removed.
        # TODO(asarfaty): For migrated networks when the DB was not cleaned up
        # This may actually delete a port the policy now control
        if (not is_external_net and not is_nsx_net and
            cfg.CONF.nsx_p.allow_passthrough):
            self._delete_nsx_port_by_network(network_id)

        # Delete the network segment from the backend
        if not is_external_net and not is_nsx_net:
            try:
                self.nsxpolicy.segment.delete(network_id)
                # In case of migrated network, a dhcp server config with
                # the same id should also be deleted
                self.nsxpolicy.dhcp_server_config.delete(network_id)
            except nsx_lib_exc.ResourceNotFound:
                # If the resource was not found on the backend do not worry
                # about it. The conditions has already been logged, so there
                # is no need to do further logging
                pass
            except nsx_lib_exc.ManagerError as e:
                # If there is a failure in deleting the resource, fail the
                # neutron operation even though the neutron object was already
                # deleted. This way the user will be aware of zombie resources
                # that may fail future actions.
                msg = (_("Backend segment deletion for neutron network %(id)s "
                         "failed. The object was however removed from the "
                         "Neutron database: %(e)s") %
                       {'id': network_id, 'e': e})
                raise nsx_exc.NsxPluginException(err_msg=msg)

        # Remove from caches
        if network_id in NET_NEUTRON_2_NSX_ID_CACHE:
            nsx_id = NET_NEUTRON_2_NSX_ID_CACHE[network_id]
            del NET_NEUTRON_2_NSX_ID_CACHE[network_id]
            if nsx_id in NET_NSX_2_NEUTRON_ID_CACHE:
                del NET_NSX_2_NEUTRON_ID_CACHE[nsx_id]

    def update_network(self, context, network_id, network):
        original_net = super(NsxPolicyPlugin, self).get_network(
            context, network_id)
        net_data = network['network']

        # Validate the updated parameters
        self._validate_update_network(context, network_id, original_net,
                                      net_data)
        self._assert_on_resource_admin_state_down(net_data)

        # Neutron does not support changing provider network values
        utils.raise_if_updates_provider_attributes(net_data)
        extern_net = self._network_is_external(context, network_id)
        is_nsx_net = self._network_is_nsx_net(context, network_id)

        # Update the neutron network
        updated_net = super(NsxPolicyPlugin, self).update_network(
            context, network_id, network)
        self._extension_manager.process_update_network(context, net_data,
                                                       updated_net)
        if psec.PORTSECURITY in net_data:
            self._process_network_port_security_update(
                context, net_data, updated_net)
        self._process_l3_update(context, updated_net, network['network'])
        self._extend_network_dict_provider(context, updated_net)

        if qos_consts.QOS_POLICY_ID in net_data:
            # attach the policy to the network in neutron DB
            #(will affect only future compute ports)
            qos_com_utils.update_network_policy_binding(
                context, network_id, net_data[qos_consts.QOS_POLICY_ID])
            updated_net[qos_consts.QOS_POLICY_ID] = net_data[
                qos_consts.QOS_POLICY_ID]
            if net_data[qos_consts.QOS_POLICY_ID]:
                LOG.info("QoS Policy %(qos)s will be applied to future "
                         "compute ports of network %(net)s",
                         {'qos': net_data[qos_consts.QOS_POLICY_ID],
                          'net': network_id})

        # Update the backend segment
        if (not extern_net and not is_nsx_net and
            ('name' in net_data or 'description' in net_data or
             'admin_state_up' in net_data)):
            net_name = utils.get_name_and_uuid(
                updated_net['name'] or 'network', network_id)

            kwargs = {'name': net_name,
                      'description': updated_net.get('description', '')}

            if 'admin_state_up' in net_data:
                if (self.nsxpolicy.feature_supported(
                        nsxlib_consts.FEATURE_NSX_POLICY_ADMIN_STATE)):
                    kwargs['admin_state'] = net_data['admin_state_up']
                elif cfg.CONF.nsx_p.allow_passthrough:
                    # Update admin state using the passthrough api
                    self.nsxpolicy.segment.set_admin_state(
                        network_id, net_data['admin_state_up'])

            try:
                self.nsxpolicy.segment.update(network_id, **kwargs)

            except nsx_lib_exc.ManagerError:
                LOG.exception("Unable to update NSX backend, rolling "
                              "back changes on neutron")
                with excutils.save_and_reraise_exception():
                    # remove the AZ from the network before rollback because
                    # it is read only, and breaks the rollback
                    if 'availability_zone_hints' in original_net:
                        del original_net['availability_zone_hints']
                    super(NsxPolicyPlugin, self).update_network(
                        context, network_id, {'network': original_net})

        return updated_net

    def _get_subnets_nd_profile(self, subnets, additional_profile=None):
        profiles = []
        if additional_profile:
            profiles.append(additional_profile)
        for sub in subnets:
            profiles.append(self._get_subnet_ndra_profile(sub))
        # If there is 1 stateful/stateless DHCP subnet (cannot have both)
        # use this profile
        if STATEFUL_DHCP_NDRA_PROFILE_ID in profiles:
            return STATEFUL_DHCP_NDRA_PROFILE_ID
        if STATELESS_DHCP_NDRA_PROFILE_ID in profiles:
            return STATELESS_DHCP_NDRA_PROFILE_ID
        if SLAAC_NDRA_PROFILE_ID in profiles:
            # if there is slaac subnet and no DHCP subnet use SLAAC
            return SLAAC_NDRA_PROFILE_ID

        return NO_SLAAC_NDRA_PROFILE_ID

    def _update_slaac_on_router(self, context, router_id,
                                subnet, router_subnets, delete=False):
        # TODO(annak): redesign when policy supports downlink-level
        # ndra profile attachment

        # This code is optimised to deal with concurrency challenges
        # (which can not be always solved by lock because the plugin
        # can run on different hosts).
        # We prefer to make another backend call for attaching the
        # profile even if it is already attached, than rely on DB
        # to have an accurate picture of existing subnets.

        # This method assumes that all the v6 subnets have the same
        # ipv6_address_mode.
        # Otherwise, earlier validation would already fail.

        if subnet.get('ip_version') == 4:
            # This subnet will not affect the ND profile
            return

        # Fetch other overlay interface networks
        # (VLAN advertising is attached on interface level)
        ipv6_overlay_subnets = [s for s in router_subnets
                                if s['id'] != subnet['id'] and
                                s.get('ip_version') == 6 and
                                s.get('enable_dhcp') and
                                self._is_overlay_network(context,
                                                         s['network_id'])]
        if delete:
            # 'subnet' was already removed from the router_subnets list before
            # calling this method
            if ipv6_overlay_subnets:
                # If there is another ipv6 overlay - select the profile by its
                # address mode
                profile_id = self._get_subnets_nd_profile(ipv6_overlay_subnets)
            else:
                # this was the last ipv6 subnet connected -
                # need to disable slaac on router
                profile_id = NO_SLAAC_NDRA_PROFILE_ID
        else:
            profile_id = self._get_subnet_ndra_profile(subnet)
            # Check the other subnets too
            if (ipv6_overlay_subnets and
                profile_id in [NO_SLAAC_NDRA_PROFILE_ID,
                               SLAAC_NDRA_PROFILE_ID]):
                profile_id = self._get_subnets_nd_profile(
                    ipv6_overlay_subnets, additional_profile=profile_id)

        self.nsxpolicy.tier1.update(router_id, ipv6_ndra_profile_id=profile_id)

    def _validate_net_dhcp_edge_cluster(self, context, network, az):
        """Validate that the dhcp server edge cluster match the one of
           the network TZ
        """
        if not self.nsxlib:
            # Cannot validate the TZ because the fabric apis are available
            # only via the nsxlib
            return

        net_tz = self._get_net_tz(context, network['id'])
        dhcp_ec_path = self.nsxpolicy.dhcp_server_config.get(
            az._policy_dhcp_server_config).get('edge_cluster_path')
        ec_id = p_utils.path_to_id(dhcp_ec_path)

        try:
            ec_tzs = plugin_utils.get_edge_cluster_tzs(
                self.nsxpolicy, self.nsxlib, ec_id)
        except nsx_lib_exc.ResourceNotFound as e:
            # Do not fail neutron action init if this code fails
            LOG.warning("Failed to get edge cluster %s transport zones: %s",
                        ec_id, e)
            return

        if net_tz not in ec_tzs:
            msg = (_('Network TZ %(tz)s does not match DHCP server '
                     'edge cluster %(ec)s') %
                   {'tz': net_tz, 'ec': ec_id})
            LOG.error(msg)
            raise n_exc.InvalidInput(error_message=msg)

    def _create_subnet_dhcp_port(self, context, az, network, subnet):
        port = self._get_net_dhcp_port(context, network['id'])
        if port:
            # If the port already exist (with another subnet) - update it with
            # the additional ip
            port['fixed_ips'].append({'subnet_id': subnet['id']})
            super(NsxPolicyPlugin, self).update_port(
                context, port['id'],
                {'port': {'fixed_ips': port['fixed_ips']}})
            return

        port_data = {
            "name": "",
            "admin_state_up": True,
            "device_id": network['id'],
            "device_owner": const.DEVICE_OWNER_DHCP,
            "network_id": network['id'],
            "tenant_id": network['tenant_id'],
            "mac_address": const.ATTR_NOT_SPECIFIED,
            "fixed_ips": [{'subnet_id': subnet['id']}],
            psec.PORTSECURITY: False
        }
        # Create the DHCP port (on neutron only) and update its port security
        port = {'port': port_data}
        neutron_port = super(NsxPolicyPlugin, self).create_port(context, port)
        is_ens_tz_port = self._is_ens_tz_port(context, port_data)
        self._create_port_preprocess_security(context, port, port_data,
                                              neutron_port, is_ens_tz_port)
        self._process_portbindings_create_and_update(
            context, port_data, neutron_port)

    def _delete_subnet_dhcp_port(self, context, net_id, subnet_id=None):
        dhcp_port = self._get_net_dhcp_port(context, net_id)
        if dhcp_port:
            if subnet_id:
                # deleting just this subnets dhcp
                if len(dhcp_port['fixed_ips']) > 1:
                    new_fixed_ips = [ip for ip in dhcp_port['fixed_ips']
                                     if ip['subnet_id'] != subnet_id]
                    super(NsxPolicyPlugin, self).update_port(
                        context, dhcp_port['id'],
                        {'port': {'fixed_ips': new_fixed_ips}})
                    return
            # Delete the port itself
            self.delete_port(context, dhcp_port['id'],
                             force_delete_dhcp=True)

    def _get_net_dhcp_port(self, context, net_id):
        filters = {
            'network_id': [net_id],
            'device_owner': [const.DEVICE_OWNER_DHCP]
        }
        dhcp_ports = self.get_ports(context, filters=filters)
        return dhcp_ports[0] if dhcp_ports else None

    def _get_sunbet_dhcp_server_ip(self, context, net_id, dhcp_subnet_id):
        dhcp_port = self._get_net_dhcp_port(context, net_id)
        if dhcp_port:
            dhcp_server_ips = [fip['ip_address']
                               for fip in dhcp_port['fixed_ips']
                               if fip['subnet_id'] == dhcp_subnet_id]
            if dhcp_server_ips:
                return dhcp_server_ips[0]

    def _is_dhcp_network(self, context, net_id):
        dhcp_port = self._get_net_dhcp_port(context, net_id)
        return bool(dhcp_port)

    def _get_segment_subnets(self, context, net_id, net_az=None,
                             interface_subnets=None,
                             deleted_dhcp_subnets=None):
        """Get an updated list of segmentSubnet objects to put on the segment
        Including router interface subnets (for overlay networks) &
        DHCP subnets (if using policy v4/v6  DHCP)
        """
        dhcp_subnets = []
        if self.use_policy_dhcp:
            # Find networks DHCP enabled subnets
            with db_api.CONTEXT_READER.using(context):
                network = self._get_network(context, net_id)
            for subnet in network.subnets:
                if(subnet.enable_dhcp and
                   (subnet.ip_version == 4 or
                    subnet.ipv6_address_mode != const.IPV6_SLAAC)):
                    if (deleted_dhcp_subnets and
                        subnet.id in deleted_dhcp_subnets):
                        # Skip this one as it is being deleted
                        continue
                    dhcp_subnets.append(self.get_subnet(context, subnet.id))
                    if len(dhcp_subnets) == 2:
                        # A network an have at most 2 DHCP subnets
                        break

        router_subnets = []
        if interface_subnets:
            router_subnets = interface_subnets
        else:
            # Get networks overlay router interfaces
            if self._is_overlay_network(context, net_id):
                router_ids = self._get_network_router_ids(
                    context.elevated(), net_id)
                if router_ids:
                    router_id = router_ids[0]
                    router_subnets = self._load_router_subnet_cidrs_from_db(
                        context.elevated(), router_id)

        seg_subnets = []

        dhcp_subnet_ids = []
        for dhcp_subnet in dhcp_subnets:
            dhcp_subnet_id = dhcp_subnet['id']
            dhcp_subnet_ids.append(dhcp_subnet_id)
            gw_addr = self._get_gateway_addr_from_subnet(dhcp_subnet)
            dhcp_server_ip = self._get_sunbet_dhcp_server_ip(
                context, net_id, dhcp_subnet_id)
            dhcp_config = None
            if dhcp_server_ip:
                cidr_prefix = int(dhcp_subnet['cidr'].split('/')[1])
                dns_nameservers = dhcp_subnet['dns_nameservers']
                if not net_az:
                    net_az = self.get_network_az_by_net_id(context, net_id)
                if (not dns_nameservers or
                    not validators.is_attr_set(dns_nameservers)):
                    # Use pre-configured dns server
                    dns_nameservers = net_az.nameservers
                is_ipv6 = bool(dhcp_subnet.get('ip_version') == 6)
                server_ip = "%s/%s" % (dhcp_server_ip, cidr_prefix)
                kwargs = {'server_address': server_ip,
                          'dns_servers': dns_nameservers}
                if is_ipv6:
                    network = self._get_network(context, net_id)
                    kwargs['domain_names'] = [
                        v3_utils.get_network_dns_domain(net_az, network)]
                    dhcp_config = policy_defs.SegmentDhcpConfigV6(**kwargs)
                else:
                    dhcp_config = policy_defs.SegmentDhcpConfigV4(**kwargs)

            seg_subnet = policy_defs.Subnet(gateway_address=gw_addr,
                                            dhcp_config=dhcp_config)
            seg_subnets.append(seg_subnet)

        for rtr_subnet in router_subnets:
            if rtr_subnet['id'] in dhcp_subnet_ids:
                # Do not add the same subnet twice
                continue
            if rtr_subnet['network_id'] == net_id:
                gw_addr = self._get_gateway_addr_from_subnet(rtr_subnet)
                seg_subnets.append(
                    policy_defs.Subnet(gateway_address=gw_addr,
                                       dhcp_config=None))

        return seg_subnets

    def _enable_subnet_dhcp(self, context, network, subnet, az):
        # Allocate a neutron port for the DHCP server
        self._create_subnet_dhcp_port(context, az, network, subnet)

        # Update the DHCP server on the segment
        net_id = network['id']
        segment_id = self._get_network_nsx_segment_id(context, net_id)

        seg_subnets = self._get_segment_subnets(context, net_id, net_az=az)
        dhcp_config = self._get_segment_dhcp_server_config(segment_id, az)
        # Update dhcp server config on the segment
        self.nsxpolicy.segment.update(
            segment_id=segment_id,
            dhcp_server_config_id=dhcp_config,
            subnets=seg_subnets)

    def _get_net_dhcp_subnets(self, context, net_id):
        net_dhcp_subnets = []
        net_obj = self._get_network(context, net_id)
        for subnet in net_obj.subnets:
            if(subnet.enable_dhcp and
               (subnet.ip_version == 4 or
                subnet.ipv6_address_mode != const.IPV6_SLAAC)):
                # This is a DHCP subnet
                net_dhcp_subnets.append(subnet.id)
        return net_dhcp_subnets

    def _disable_network_dhcp(self, context, network, subnet_id=None):
        net_id = network['id']
        net_dhcp_subnets = self._get_net_dhcp_subnets(context, net_id)
        segment_id = self._get_network_nsx_segment_id(context, net_id)

        if subnet_id and len(net_dhcp_subnets) > 1:
            # remove dhcp only from this subnet
            seg_subnets = self._get_segment_subnets(
                context, net_id, deleted_dhcp_subnets=[subnet_id])
            self.nsxpolicy.segment.update(
                segment_id,
                subnets=seg_subnets)
            self._delete_subnet_dhcp_port(context, net_id, subnet_id=subnet_id)
        else:
            # Remove dhcp server config completely from the segment
            seg_subnets = self._get_segment_subnets(
                context, net_id, deleted_dhcp_subnets=net_dhcp_subnets)
            self.nsxpolicy.segment.update(
                segment_id=segment_id,
                subnets=seg_subnets,
                dhcp_server_config_id=None)

            # Delete the neutron DHCP port (and its bindings)
            self._delete_subnet_dhcp_port(context, net_id)

    def _get_segment_dhcp_server_config(self, segment_id, az):
        """Return the dhcp server config id the segment should be using

        Usually it the AZ one, but in case of migrated segments,
        the id of the dhcp server config is the same as the segment id
        """
        dhcp_server_config = az._policy_dhcp_server_config
        try:
            seg = self.nsxpolicy.segment.get(segment_id, silent=True)
        except Exception:
            pass
        else:
            if seg.get('dhcp_config_path'):
                dhcp_server_config = p_utils.path_to_id(
                    seg['dhcp_config_path'])
        return dhcp_server_config

    def _update_nsx_net_dhcp(self, context, network, az, subnet=None):
        """Update the DHCP config on a network
        Update the segment DHCP config, as well as the dhcp bindings on the
        ports.
        If just a specific subnet was modified, update only its ports.
        """
        net_id = network['id']
        segment_id = self._get_network_nsx_segment_id(context, net_id)
        seg_subnets = self._get_segment_subnets(context, net_id, net_az=az)

        filters = {'network_id': [net_id]}
        ports = self.get_ports(context, filters=filters)
        dhcp_server_config = self._get_segment_dhcp_server_config(
            segment_id, az)
        self.nsxpolicy.segment.update(
            segment_id=segment_id,
            dhcp_server_config_id=dhcp_server_config,
            subnets=seg_subnets)

        # Update DHCP bindings for all the ports.
        for port in ports:
            self._add_or_overwrite_port_policy_dhcp_binding(
                context, port, segment_id, subnet)

    def _validate_net_type_with_dhcp(self, context, network):
        ddi_support, ddi_type = self._is_ddi_supported_on_net_with_type(
            context, network['id'], network=network)
        if not ddi_support:
            msg = _("Native DHCP is not supported for %(type)s "
                    "network %(id)s") % {'id': network['id'],
                                         'type': ddi_type}
            LOG.error(msg)
            raise n_exc.InvalidInput(error_message=msg)

    def _validate_segment_subnets_num(self, context, net_id, subnet_data):
        """Validate no multiple segment subnets on the NSX
        The NSX cannot support more than 1 segment subnet of the same ip
        version. This include dhcp subnets and overlay router interfaces
        """
        if ('enable_dhcp' not in subnet_data or
            not subnet_data.get('enable_dhcp')):
            # NO DHCP so no new segment subnet
            return

        ip_ver = subnet_data.get('ip_version', 4)
        if ip_ver == 6:
            # Since the plugin does not allow multiple ipv6 subnets,
            # this can be ignored.
            return

        overlay_net = self._is_overlay_network(context, net_id)
        if not overlay_net:
            # Since the plugin allows only 1 DHCP subnet, if this is not an
            # overlay network, no problem.
            return

        interface_ports = self._get_network_interface_ports(
            context, net_id)
        if interface_ports:
            # Should have max 1 router interface per network
            if_port = interface_ports[0]
            if if_port['fixed_ips']:
                if_subnet = interface_ports[0]['fixed_ips'][0]['subnet_id']
                if subnet_data.get('id') != if_subnet:
                    msg = (_("Can not create a DHCP subnet on network %(net)s "
                             "as another %(ver)s subnet is attached to a "
                             "router") % {'net': net_id, 'ver': ip_ver})
                    LOG.error(msg)
                    raise n_exc.InvalidInput(error_message=msg)

    def _init_ipv6_gateway(self, subnet):
        # Override neutron decision to verify that also for ipv6 the first
        # ip in the cidr is not used, as the NSX does not support xxxx::0 as a
        # segment subnet gateway in versions supporting policy DHCP

        if (self.nsxpolicy.feature_supported(
                nsxlib_consts.FEATURE_NSX_POLICY_DHCP) and
            subnet.get('gateway_ip') is const.ATTR_NOT_SPECIFIED and
            subnet.get('ip_version') == const.IP_VERSION_6 and
            subnet.get('cidr') and subnet['cidr'] != const.ATTR_NOT_SPECIFIED):
            net = netaddr.IPNetwork(subnet['cidr'])
            subnet['gateway_ip'] = str(net.network + 1)

    def _validate_subnet_host_routes(self, subnet, orig_subnet=None):
        self._validate_number_of_subnet_static_routes(subnet)
        if orig_subnet:
            self._validate_host_routes_input(
                subnet,
                orig_enable_dhcp=orig_subnet['enable_dhcp'],
                orig_host_routes=orig_subnet['host_routes'])
        else:
            self._validate_host_routes_input(subnet)

        # IPv6 subnets cannot support host routes
        if (subnet['subnet'].get('ip_version') == 6 or
            (orig_subnet and orig_subnet.get('ip_version') == 6)):
            if (validators.is_attr_set(subnet['subnet'].get('host_routes')) and
                subnet['subnet']['host_routes']):
                err_msg = _("Host routes can only be supported with IPv4 "
                            "subnets")
                raise n_exc.InvalidInput(error_message=err_msg)

    def _validate_subnet_gw_ip(self, subnet, orig_subnet=None):
        # Make sure the gw ip is legal and belongs to the subnet
        raw_gw_ip = subnet.get('gateway_ip')
        if (orig_subnet and
            (not raw_gw_ip or raw_gw_ip == const.ATTR_NOT_SPECIFIED)):
            raw_gw_ip = orig_subnet.get('gateway_ip')
        raw_cidr = subnet.get('cidr')
        if (orig_subnet and
            (not raw_cidr or raw_cidr == const.ATTR_NOT_SPECIFIED)):
            raw_cidr = orig_subnet.get('cidr')
        if (not raw_gw_ip or raw_gw_ip == const.ATTR_NOT_SPECIFIED or
            not raw_cidr or raw_cidr == const.ATTR_NOT_SPECIFIED):
            return

        gw_ip = netaddr.IPAddress(raw_gw_ip)
        cidr = netaddr.IPNetwork(raw_cidr)
        if gw_ip.version != cidr.version:
            err_msg = (_("Subnet gateway ip version %s does not match subnet "
                         "cidr %s") % (gw_ip.version, raw_cidr))
            raise n_exc.InvalidInput(error_message=err_msg)

        if gw_ip not in cidr:
            err_msg = (_("Subnet gateway ip %s does not belong to subnet "
                         "cidr %s") % (raw_gw_ip, raw_cidr))
            raise n_exc.InvalidInput(error_message=err_msg)

        if gw_ip.version == const.IP_VERSION_6:
            # NSX does not support xxxx::0 as a segment subnet gateway
            illegal_gw = str(netaddr.IPNetwork(raw_cidr).network)
            if illegal_gw == str(gw_ip):
                err_msg = (_("IPv6 Subnet gateway ip %s is not "
                             "supported") % raw_gw_ip)
                raise n_exc.InvalidInput(error_message=err_msg)

    def _has_dhcp_enabled_subnet(self, context, network, ip_version=4):
        for subnet in network.subnets:
            if subnet.enable_dhcp and subnet.ip_version == ip_version:
                if ip_version == 4:
                    return True
                if subnet.ipv6_address_mode != const.IPV6_SLAAC:
                    return True
        return False

    @nsx_plugin_common.api_replay_mode_wrapper
    def create_subnet(self, context, subnet):
        self._init_ipv6_gateway(subnet['subnet'])
        if not self.use_policy_dhcp:
            # Subnet with MP DHCP
            return self._create_subnet_with_mp_dhcp(context, subnet)

        self._validate_subnet_host_routes(subnet)
        net_id = subnet['subnet']['network_id']
        network = self._get_network(context, net_id)
        self._validate_single_ipv6_subnet(context, network, subnet['subnet'])
        self._validate_subnet_gw_ip(subnet['subnet'])
        net_az = self.get_network_az_by_net_id(context, net_id)

        # Allow manipulation of only 1 subnet of the same network at once
        lock = 'nsxp_network_' + net_id
        with locking.LockManager.get_lock(lock):
            # DHCP validations (before creating the neutron subnet)
            with_dhcp = False
            if self._subnet_with_native_dhcp(subnet['subnet']):
                with_dhcp = True
                self._validate_external_subnet(context, net_id)
                self._validate_net_dhcp_edge_cluster(context, network, net_az)
                self._validate_net_type_with_dhcp(context, network)
                ip_version = subnet['subnet'].get('ip_version', 4)
                if self._has_dhcp_enabled_subnet(context, network, ip_version):
                    msg = (_("Can not create more than one DHCP-enabled "
                             "subnet for IPv%(ver)s in network %(net)s") %
                           {'ver': ip_version, 'net': net_id})
                    LOG.error(msg)
                    raise n_exc.InvalidInput(error_message=msg)
                self._validate_segment_subnets_num(
                    context, net_id, subnet['subnet'])

            # Create the neutron subnet.
            # Any failure from here and on will require rollback.
            created_subnet = super(NsxPolicyPlugin, self).create_subnet(
                context, subnet)
            try:
                # This can be called only after the super create
                # since we need the subnet pool to be translated
                # to allocation pools
                self._validate_address_space(context, created_subnet)
            except n_exc.InvalidInput:
                # revert the subnet creation
                with excutils.save_and_reraise_exception():
                    super(NsxPolicyPlugin, self).delete_subnet(
                        context, created_subnet['id'])

            self._extension_manager.process_create_subnet(context,
                subnet['subnet'], created_subnet)

            if with_dhcp:
                try:
                    # Enable the network DHCP on the NSX
                    self._enable_subnet_dhcp(
                        context, network, created_subnet, net_az)
                except (nsx_lib_exc.ManagerError, nsx_exc.NsxPluginException):
                    # revert the subnet creation
                    with excutils.save_and_reraise_exception():
                        # Try to delete the DHCP port, and the neutron subnet
                        self._delete_subnet_dhcp_port(
                            context, net_id, subnet_id=created_subnet['id'])
                        super(NsxPolicyPlugin, self).delete_subnet(
                            context, created_subnet['id'])

        return created_subnet

    def delete_subnet(self, context, subnet_id):
        if not self.use_policy_dhcp:
            # Subnet with MP DHCP
            return self.delete_subnet_with_mp_dhcp(context, subnet_id)

        if self._has_native_dhcp_metadata():
            # Ensure that subnet is not deleted if attached to router.
            self._subnet_check_ip_allocations_internal_router_ports(
                context, subnet_id)
            # Ensure that subnet is not deleted if it has ports, before
            # changing backend configuration
            subnet = self.get_subnet(context, subnet_id)
            is_auto_addr_subnet = ipv6_utils.is_auto_address_subnet(subnet)
            if not is_auto_addr_subnet:
                # for SLAAC auto allocation subnets ports can still exist
                self._ensure_no_user_ports_on_subnet(context, subnet_id)
            if self._subnet_with_native_dhcp(subnet):
                lock = 'nsxp_network_' + subnet['network_id']
                with locking.LockManager.get_lock(lock):
                    # Remove this subnet DHCP config
                    network = self._get_network(context, subnet['network_id'])
                    try:
                        self._disable_network_dhcp(context, network,
                                                   subnet_id=subnet_id)
                    except Exception as e:
                        LOG.error("Failed to disable DHCP for "
                                  "network %(id)s. Exception: %(e)s",
                                  {'id': network['id'], 'e': e})
                        # Continue for the neutron subnet deletion
        # Delete neutron subnet
        super(NsxPolicyPlugin, self).delete_subnet(context, subnet_id)

    def update_subnet(self, context, subnet_id, subnet):
        if not self.use_policy_dhcp:
            # Subnet with MP DHCP
            return self.update_subnet_with_mp_dhcp(context, subnet_id, subnet)
        subnet_data = subnet['subnet']
        updated_subnet = None
        orig_subnet = self.get_subnet(context, subnet_id)
        self._validate_subnet_host_routes(subnet, orig_subnet=orig_subnet)
        self._validate_subnet_gw_ip(subnet_data, orig_subnet=orig_subnet)

        net_id = orig_subnet['network_id']
        network = self._get_network(context, net_id)
        net_az = self.get_network_az_by_net_id(context, net_id)

        enable_dhcp = self._subnet_with_native_dhcp(
            subnet_data, orig_subnet=orig_subnet)
        orig_enable_dhcp = self._subnet_with_native_dhcp(orig_subnet)

        if enable_dhcp != orig_enable_dhcp:
            # Update subnet with DHCP status change
            self._validate_external_subnet(context, net_id)
            lock = 'nsxp_network_' + net_id
            with locking.LockManager.get_lock(lock):
                if enable_dhcp:
                    self._validate_net_type_with_dhcp(context, network)
                    ip_version = orig_subnet.get('ip_version', 4)
                    if self._has_dhcp_enabled_subnet(context, network,
                                                     ip_version):
                        msg = (_("Can not create more than one DHCP-enabled "
                                "subnet for IPv%(ver)s in network %(net)s") %
                              {'net': net_id, 'ver': ip_version})
                        LOG.error(msg)
                        raise n_exc.InvalidInput(error_message=msg)

                    self._validate_segment_subnets_num(
                        context, net_id, subnet_data)

                updated_subnet = super(NsxPolicyPlugin, self).update_subnet(
                    context, subnet_id, subnet)
                self._extension_manager.process_update_subnet(
                    context, subnet_data, updated_subnet)

                try:
                    if enable_dhcp:
                        self._enable_subnet_dhcp(context, network,
                                                 updated_subnet, net_az)
                    else:
                        self._disable_network_dhcp(context, network,
                                                   subnet_id=subnet_id)
                except (nsx_lib_exc.ManagerError, nsx_exc.NsxPluginException):
                    # revert the subnet update
                    with excutils.save_and_reraise_exception():
                        super(NsxPolicyPlugin, self).update_subnet(
                            context, subnet_id, {'subnet': orig_subnet})

        else:
            # No dhcp changes - just call super update
            updated_subnet = super(NsxPolicyPlugin, self).update_subnet(
                context, subnet_id, subnet)
            self._extension_manager.process_update_subnet(
                context, subnet_data, updated_subnet)

        # Check if needs to update DHCP related NSX resources
        # (only if the subnet changed, but dhcp was already enabled)
        if (enable_dhcp and orig_enable_dhcp and
            ('dns_nameservers' in subnet_data or
             'gateway_ip' in subnet_data or
             'host_routes' in subnet_data)):
            self._update_nsx_net_dhcp(context, network, net_az, updated_subnet)

        return updated_subnet

    def _build_port_address_bindings(self, context, port_data):
        psec_on, has_ip = self._determine_port_security_and_has_ip(context,
                                                                   port_data)
        if not psec_on:
            return None

        address_bindings = []
        for fixed_ip in port_data['fixed_ips']:
            ip_addr = fixed_ip['ip_address']
            mac_addr = self._format_mac_address(port_data['mac_address'])
            binding = self.nsxpolicy.segment_port.build_address_binding(
                ip_addr, mac_addr)
            address_bindings.append(binding)

            # add address binding for link local ipv6 address, otherwise
            # neighbor discovery will be blocked by spoofguard.
            # for now only one ipv6 address is allowed
            if netaddr.IPAddress(ip_addr).version == 6:
                lladdr = netaddr.EUI(mac_addr).ipv6_link_local()
                binding = self.nsxpolicy.segment_port.build_address_binding(
                    lladdr, mac_addr)
                address_bindings.append(binding)

        for pair in port_data.get(addr_apidef.ADDRESS_PAIRS):
            binding = self.nsxpolicy.segment_port.build_address_binding(
                pair['ip_address'],
                self._format_mac_address(pair['mac_address']))
            address_bindings.append(binding)

        return address_bindings

    def _get_network_nsx_id(self, context, network_id):
        """Return the id of this logical switch in the nsx manager

        This api waits for the segment to really be realized, and return the ID
        of the NSX logical switch.
        If it was not realized or timed out retrying, it will return None
        The nova api will use this to attach to the instance.
        """
        if network_id in NET_NEUTRON_2_NSX_ID_CACHE:
            return NET_NEUTRON_2_NSX_ID_CACHE[network_id]

        if not self._network_is_external(context, network_id):
            segment_id = self._get_network_nsx_segment_id(context, network_id)
            try:
                nsx_id = self.nsxpolicy.segment.get_realized_logical_switch_id(
                    segment_id)
                # Add result to caches
                NET_NEUTRON_2_NSX_ID_CACHE[network_id] = nsx_id
                NET_NSX_2_NEUTRON_ID_CACHE[nsx_id] = network_id
                return nsx_id
            except nsx_lib_exc.ManagerError:
                LOG.error("Network %s was not realized", network_id)
                # Do not cache this result
        else:
            # Add empty result to cache
            NET_NEUTRON_2_NSX_ID_CACHE[network_id] = None

    def _get_network_nsx_segment_id(self, context, network_id):
        """Return the NSX segment ID matching the neutron network id

        Usually the NSX ID is the same as the neutron ID. The exception is
        when this is a provider NSX_NETWORK, which means the network already
        existed on the NSX backend, and it is being consumed by the plugin.
        """
        bindings = nsx_db.get_network_bindings(context.session, network_id)
        if (bindings and
            bindings[0].binding_type == utils.NsxV3NetworkTypes.NSX_NETWORK):
            # return the ID of the NSX network
            return bindings[0].phy_uuid
        return network_id

    def _build_port_tags(self, port_data):
        sec_groups = []
        sec_groups.extend(port_data.get(ext_sg.SECURITYGROUPS, []))
        sec_groups.extend(port_data.get(provider_sg.PROVIDER_SECURITYGROUPS,
                                        []))

        tags = []
        for sg in sec_groups:
            tags = nsxlib_utils.add_v3_tag(tags,
                                           NSX_P_SECURITY_GROUP_TAG,
                                           sg)

        return tags

    def _do_port_backend_calls(self, name, segment_id,
                               spoofguard_profile, seg_sec_profile,
                               mac_discovery_profile, qos_policy_id, **kwargs):
        self.nsxpolicy.segment_port.create_or_overwrite(
            name, segment_id, **kwargs)

        # add the security profiles to the port
        self.nsxpolicy.segment_port_security_profiles.create_or_overwrite(
            name, segment_id, port_id=kwargs['port_id'],
            spoofguard_profile_id=spoofguard_profile,
            segment_security_profile_id=seg_sec_profile)

        # add the mac discovery profile to the port
        self.nsxpolicy.segment_port_discovery_profiles.create_or_overwrite(
            name, segment_id, kwargs['port_id'],
            mac_discovery_profile_id=mac_discovery_profile)

        # Add QoS segment profile (only if QoS is enabled)
        if directory.get_plugin(plugin_const.QOS):
            self.nsxpolicy.segment_port_qos_profiles.create_or_overwrite(
                name, segment_id, kwargs['port_id'],
                qos_profile_id=qos_policy_id)

    def _create_or_update_port_on_backend(self, context, port_data, is_psec_on,
                                          qos_policy_id, original_port=None):
        is_create = original_port is None
        is_update = not is_create

        name = self._build_port_name(context, port_data)
        address_bindings = self._build_port_address_bindings(
            context, port_data)
        device_owner = port_data.get('device_owner')
        vif_id = None
        if not device_owner or device_owner != l3_db.DEVICE_OWNER_ROUTER_INTF:
            # Set vif_id even if no device owner so that auto-generated
            # MP ports won't be created for VMs before neutron sets the vif-id
            vif_id = port_data['id']

        tags = self._build_port_tags(port_data)
        if device_owner == l3_db.DEVICE_OWNER_ROUTER_INTF:
            tag_resource_type = 'os-neutron-rport-id'
        else:
            tag_resource_type = NSX_P_PORT_RESOURCE_TYPE
        tags.extend(self.nsxpolicy.build_v3_tags_payload(
            port_data, resource_type=tag_resource_type,
            project_name=context.tenant_name))

        if self._is_excluded_port(device_owner, is_psec_on):
            tags.append({'scope': v3_utils.PORT_SG_SCOPE,
                         'tag': NSX_P_EXCLUDE_LIST_TAG})

        if self.support_external_port_tagging:
            external_tags = self.get_external_tags_for_port(
                context, port_data['id'])
            if external_tags:
                total_len = len(external_tags) + len(tags)
                if total_len > nsxlib_utils.MAX_TAGS:
                    LOG.warning("Cannot add external tags to port %s: "
                                "too many tags", port_data['id'])
                else:
                    tags.extend(external_tags)

        segment_id = self._get_network_nsx_segment_id(
            context, port_data['network_id'])

        # Calculate the port security profiles
        if is_psec_on:
            spoofguard_profile = SPOOFGUARD_PROFILE_ID
            seg_sec_profile = SEG_SECURITY_PROFILE_ID
        else:
            spoofguard_profile = NO_SPOOFGUARD_PROFILE_ID
            seg_sec_profile = NO_SEG_SECURITY_PROFILE_ID
        mac_disc_profile_must = False
        if is_psec_on:
            address_pairs = port_data.get(addr_apidef.ADDRESS_PAIRS)
            if validators.is_attr_set(address_pairs) and address_pairs:
                mac_disc_profile_must = True
        mac_learning_enabled = (
            validators.is_attr_set(port_data.get(mac_ext.MAC_LEARNING)) and
            port_data.get(mac_ext.MAC_LEARNING) is True)
        if mac_disc_profile_must or mac_learning_enabled:
            mac_discovery_profile = MAC_DISCOVERY_PROFILE_ID
        else:
            mac_discovery_profile = NO_MAC_DISCOVERY_PROFILE_ID

        # Prepare the args for the segment port creation
        kwargs = {'port_id': port_data['id'],
                  'description': port_data.get('description', ''),
                  'address_bindings': address_bindings,
                  'tags': tags}
        if vif_id:
            kwargs['vif_id'] = vif_id

        if (self.nsxpolicy.feature_supported(
                nsxlib_consts.FEATURE_NSX_POLICY_ADMIN_STATE) and
            'admin_state_up' in port_data):
            kwargs['admin_state'] = port_data['admin_state_up']

        if not self.nsxpolicy.feature_supported(
            nsxlib_consts.FEATURE_PARTIAL_UPDATES):
            # If partial updates are not supported, using transactions will
            # reset the backend segment name
            self._do_port_backend_calls(
                name, segment_id, spoofguard_profile, seg_sec_profile,
                mac_discovery_profile, qos_policy_id, **kwargs)
        else:
            # Create/ update the backend port in a single transaction
            with policy_trans.NsxPolicyTransaction():
                self._do_port_backend_calls(
                    name, segment_id, spoofguard_profile, seg_sec_profile,
                    mac_discovery_profile, qos_policy_id, **kwargs)

        # Update port admin status using passthrough api, only if it changed
        # or new port with disabled admin state
        if (not self.nsxpolicy.feature_supported(
                nsxlib_consts.FEATURE_NSX_POLICY_ADMIN_STATE) and
            cfg.CONF.nsx_p.allow_passthrough and
            'admin_state_up' in port_data):
            new_state = port_data['admin_state_up']
            if ((is_create and new_state is False) or
                (is_update and
                 original_port.get('admin_state_up') != new_state)):
                # This api uses the passthrough api
                self.nsxpolicy.segment_port.set_admin_state(
                    segment_id, port_data['id'], new_state)

    def base_create_port(self, context, port):
        neutron_db = super(NsxPolicyPlugin, self).create_port(context, port)
        self._extension_manager.process_create_port(
            context, port['port'], neutron_db)
        return neutron_db

    def _is_backend_port(self, context, port_data, delete=False):
        is_external_net = self._network_is_external(
            context, port_data['network_id'])

        device_owner = port_data.get('device_owner')
        is_router_interface = (device_owner == l3_db.DEVICE_OWNER_ROUTER_INTF)
        is_dhcp_port = (device_owner == const.DEVICE_OWNER_DHCP and
                        self.use_policy_dhcp)
        is_octavia_port = (device_owner == oct_const.DEVICE_OWNER_OCTAVIA)

        if is_external_net or is_router_interface or is_dhcp_port:
            # DHCP is handled on NSX level
            # Router is connected automatically in policy
            return False

        if not delete and is_octavia_port:
            # Octavia vip port should not be created on the NSX.
            # Since octavia backend ports from older deployments may exist,
            # need to try and delete those.
            return False

        return True

    def _filter_ipv6_dhcp_fixed_ips(self, context, fixed_ips):
        ips = []
        for fixed_ip in fixed_ips:
            if netaddr.IPNetwork(fixed_ip['ip_address']).version != 6:
                continue
            with db_api.CONTEXT_READER.using(context):
                subnet = self.get_subnet(context, fixed_ip['subnet_id'])
            if (subnet['enable_dhcp'] and
                subnet.get('ipv6_address_mode') != 'slaac'):
                ips.append(fixed_ip)
        return ips

    def _add_or_overwrite_port_policy_dhcp_binding(
        self, context, port, segment_id, dhcp_subnet=None):
        if not utils.is_port_dhcp_configurable(port):
            return
        net_id = port['network_id']

        for fixed_ip in self._filter_ipv4_dhcp_fixed_ips(
            context, port['fixed_ips']):
            # There will be only one ipv4 ip here
            binding_id = port['id'] + '-ipv4'
            name = 'IPv4 binding for port %s' % port['id']
            ip = fixed_ip['ip_address']
            hostname = 'host-%s' % ip.replace('.', '-')
            if dhcp_subnet:
                if fixed_ip['subnet_id'] != dhcp_subnet['id']:
                    continue
                subnet = dhcp_subnet
            else:
                subnet = self.get_subnet(context, fixed_ip['subnet_id'])
            gateway_ip = subnet.get('gateway_ip')
            options = self._get_dhcp_options(
                context, ip, port.get(ext_edo.EXTRADHCPOPTS),
                net_id, subnet)
            self.nsxpolicy.segment_dhcp_static_bindings.create_or_overwrite_v4(
                name, segment_id, binding_id=binding_id,
                gateway_address=gateway_ip,
                host_name=hostname,
                ip_address=ip,
                lease_time=cfg.CONF.nsx_p.dhcp_lease_time,
                mac_address=port['mac_address'],
                options=options)

        for fixed_ip in self._filter_ipv6_dhcp_fixed_ips(
            context, port['fixed_ips']):
            # There will be only one ipv6 ip here
            binding_id = port['id'] + '-ipv6'
            name = 'IPv6 binding for port %s' % port['id']
            ip = fixed_ip['ip_address']
            if dhcp_subnet:
                if fixed_ip['subnet_id'] != dhcp_subnet['id']:
                    continue
                subnet = dhcp_subnet
            else:
                subnet = self.get_subnet(context, fixed_ip['subnet_id'])
            self.nsxpolicy.segment_dhcp_static_bindings.create_or_overwrite_v6(
                name, segment_id, binding_id=binding_id,
                ip_addresses=[ip],
                lease_time=cfg.CONF.nsx_p.dhcp_lease_time,
                mac_address=port['mac_address'])

    def _add_port_policy_dhcp_binding(self, context, port):
        net_id = port['network_id']
        if not self._is_dhcp_network(context, net_id):
            return

        segment_id = self._get_network_nsx_segment_id(context, net_id)
        self._add_or_overwrite_port_policy_dhcp_binding(
            context, port, segment_id)

    def _delete_port_policy_dhcp_binding(self, context, port):
        # Do not check device_owner here because Nova may have already
        # deleted that before Neutron's port deletion.
        net_id = port['network_id']
        if not self._is_dhcp_network(context, net_id):
            return
        segment_id = self._get_network_nsx_segment_id(context, net_id)

        v4_dhcp = v6_dhcp = False
        for fixed_ip in port['fixed_ips']:
            ip_addr = fixed_ip['ip_address']
            if netaddr.IPAddress(ip_addr).version == 6:
                v6_dhcp = True
            else:
                v4_dhcp = True
        if v4_dhcp:
            try:
                bindingv4_id = port['id'] + '-ipv4'
                self.nsxpolicy.segment_dhcp_static_bindings.delete(
                    segment_id, bindingv4_id)
            except nsx_lib_exc.ResourceNotFound:
                pass

        if v6_dhcp:
            try:
                bindingv6_id = port['id'] + '-ipv6'
                self.nsxpolicy.segment_dhcp_static_bindings.delete(
                    segment_id, bindingv6_id)
            except nsx_lib_exc.ResourceNotFound:
                pass

    def _update_port_policy_dhcp_binding(self, context, old_port, new_port):
        # First check if any address in fixed_ips changed.
        # Then update DHCP server setting or DHCP static binding
        # depending on the port type.
        # Note that Neutron allows a port with multiple IPs in the
        # same subnet. But backend DHCP server may not support that.
        if (utils.is_port_dhcp_configurable(old_port) !=
            utils.is_port_dhcp_configurable(new_port)):
            # Note that the device_owner could be changed,
            # but still needs DHCP binding.
            if utils.is_port_dhcp_configurable(old_port):
                self._delete_port_policy_dhcp_binding(context, old_port)
            else:
                self._add_port_policy_dhcp_binding(context, new_port)
            return

        # Collect IPv4 DHCP addresses from original and updated fixed_ips
        # in the form of [(subnet_id, ip_address)].
        old_fixed_v4 = set([(fixed_ip['subnet_id'], fixed_ip['ip_address'])
                            for fixed_ip in self._filter_ipv4_dhcp_fixed_ips(
                                context, old_port['fixed_ips'])])
        new_fixed_v4 = set([(fixed_ip['subnet_id'], fixed_ip['ip_address'])
                            for fixed_ip in self._filter_ipv4_dhcp_fixed_ips(
                                context, new_port['fixed_ips'])])
        old_fixed_v6 = set([(fixed_ip['subnet_id'], fixed_ip['ip_address'])
                            for fixed_ip in self._filter_ipv6_dhcp_fixed_ips(
                                context, old_port['fixed_ips'])])
        new_fixed_v6 = set([(fixed_ip['subnet_id'], fixed_ip['ip_address'])
                            for fixed_ip in self._filter_ipv6_dhcp_fixed_ips(
                                context, new_port['fixed_ips'])])
        # Find out the subnet/IP differences before and after the update.
        v4_to_add = list(new_fixed_v4 - old_fixed_v4)
        v4_to_delete = list(old_fixed_v4 - new_fixed_v4)
        v6_to_add = list(new_fixed_v6 - old_fixed_v6)
        v6_to_delete = list(old_fixed_v6 - new_fixed_v6)
        ip_change = (v4_to_add or v4_to_delete or v6_to_add or v6_to_delete)

        if (old_port["device_owner"] == const.DEVICE_OWNER_DHCP and
            ip_change):
            # Update backend DHCP server address if the IP address of a DHCP
            # port is changed.
            if len(new_fixed_v4) > 1 or len(new_fixed_v6) > 1:
                msg = _("Can only configure one IP address on a DHCP server")
                LOG.error(msg)
                raise n_exc.InvalidInput(error_message=msg)
            net_id = old_port['network_id']
            network = self.get_network(context, net_id)
            net_az = self.get_network_az_by_net_id(context, net_id)
            self._update_nsx_net_dhcp(context, network, net_az)

        elif utils.is_port_dhcp_configurable(new_port):
            dhcp_opts_changed = (old_port[ext_edo.EXTRADHCPOPTS] !=
                                 new_port[ext_edo.EXTRADHCPOPTS])
            if (ip_change or dhcp_opts_changed or
                old_port['mac_address'] != new_port['mac_address']):
                if new_fixed_v4 or new_fixed_v6:
                    # Recreate the bindings of this port
                    self._add_port_policy_dhcp_binding(context, new_port)
                else:
                    self._delete_port_policy_dhcp_binding(context, old_port)

    def _assert_on_ipv6_port_with_dhcpopts(self, context, port_data,
                                           orig_port=None):
        """IPv6 port only port cannot support EXTRADHCPOPTS"""

        # Get the updated EXTRADHCPOPTS
        extradhcpopts = None
        if ext_edo.EXTRADHCPOPTS in port_data:
            extradhcpopts = port_data[ext_edo.EXTRADHCPOPTS]
        elif orig_port:
            extradhcpopts = orig_port.get(ext_edo.EXTRADHCPOPTS)

        if not extradhcpopts:
            return

        # Get the updated list of fixed ips
        fixed_ips = []
        if (port_data.get('fixed_ips') and
            validators.is_attr_set(port_data['fixed_ips'])):
            fixed_ips = port_data['fixed_ips']
        elif (orig_port and orig_port.get('fixed_ips') and
              validators.is_attr_set(orig_port['fixed_ips'])):
            fixed_ips = orig_port['fixed_ips']

        # Check if any of the ips belongs to an ipv6 subnet with DHCP
        # And no ipv4 subnets
        for fixed_ip in fixed_ips:
            if netaddr.IPNetwork(fixed_ip['ip_address']).version == 4:
                # If there are ipv4 addresses - it is allowed
                return
            with db_api.CONTEXT_READER.using(context):
                subnet = self.get_subnet(context, fixed_ip['subnet_id'])
            if (subnet['enable_dhcp'] and
                subnet['ipv6_address_mode'] != const.IPV6_SLAAC):
                err_msg = (_("%s are not supported for IPv6 ports with "
                             "DHCP v6") % ext_edo.EXTRADHCPOPTS)
                LOG.error(err_msg)
                raise n_exc.InvalidInput(error_message=err_msg)

    def raise_port_error(self, e):
        """Raise the proper error when segment port PATCH fails"""
        if isinstance(e, nsx_lib_exc.ManagerError):
            if e.status_code == 400:
                # Try to get the important part of the message
                try:
                    msg = e.msg.split('relatedErrors: ')[1][:-1]
                except Exception:
                    msg = e.msg
                raise n_exc.InvalidInput(error_message=msg)

        raise e

    def create_port(self, context, port, l2gw_port_check=False):
        port_data = port['port']
        # validate the new port parameters
        self._validate_create_port(context, port_data)
        self._assert_on_resource_admin_state_down(port_data)

        # Validate the vnic type (the same types as for the NSX-T plugin)
        direct_vnic_type = self._validate_port_vnic_type(
            context, port_data, port_data['network_id'],
            projectpluginmap.NsxPlugins.NSX_T)

        is_external_net = self._network_is_external(
            context, port_data['network_id'])
        if is_external_net:
            self._assert_on_external_net_with_compute(port_data)

        with db_api.CONTEXT_WRITER.using(context):
            neutron_db = self.base_create_port(context, port)
            port["port"].update(neutron_db)

            try:
                # Validate ipv6 only after fixed_ips are allocated
                self._assert_on_ipv6_port_with_dhcpopts(context, port["port"])
            except Exception:
                with excutils.save_and_reraise_exception():
                    # rollback
                    super(NsxPolicyPlugin, self).delete_port(
                        context, neutron_db['id'])

            self.fix_direct_vnic_port_sec(direct_vnic_type, port_data)
            (is_psec_on, has_ip, sgids, psgids) = (
                self._create_port_preprocess_security(context, port,
                                                      port_data, neutron_db,
                                                      False))
            self._process_portbindings_create_and_update(
                context, port['port'], port_data,
                vif_type=self._vif_type_by_vnic_type(direct_vnic_type))
            self._process_port_create_extra_dhcp_opts(
                context, port_data,
                port_data.get(ext_edo.EXTRADHCPOPTS))
            self._process_port_create_security_group(context, port_data, sgids)
            self._process_port_create_provider_security_group(
                context, port_data, psgids)

            # Handle port mac learning
            if validators.is_attr_set(port_data.get(mac_ext.MAC_LEARNING)):
                # Make sure mac_learning and port sec are not both enabled
                if port_data.get(mac_ext.MAC_LEARNING) and is_psec_on:
                    msg = _('Mac learning requires that port security be '
                            'disabled')
                    LOG.error(msg)
                    raise n_exc.InvalidInput(error_message=msg)
                # save the mac learning value in the DB
                self._create_mac_learning_state(context, port_data)
            elif mac_ext.MAC_LEARNING in port_data:
                # This is due to the fact that the default is
                # ATTR_NOT_SPECIFIED
                port_data.pop(mac_ext.MAC_LEARNING)

        qos_policy_id = self._get_port_qos_policy_id(
            context, None, port_data)

        if self._is_backend_port(context, port_data):
            # router interface port is created automatically by policy
            try:
                self._create_or_update_port_on_backend(
                    context, port_data, is_psec_on, qos_policy_id)
            except Exception as e:
                LOG.error('Failed to create port %(id)s on NSX '
                          'backend. Exception: %(e)s',
                          {'id': neutron_db['id'], 'e': e})
                super(NsxPolicyPlugin, self).delete_port(
                    context, neutron_db['id'])
                self.raise_port_error(e)

        # Attach the QoS policy to the port in the neutron DB
        if qos_policy_id:
            qos_com_utils.update_port_policy_binding(context,
                                                     neutron_db['id'],
                                                     qos_policy_id)
        # this extra lookup is necessary to get the
        # latest db model for the extension functions
        port_model = self._get_port(context, port_data['id'])
        resource_extend.apply_funcs('ports', port_data, port_model)
        self._extend_nsx_port_dict_binding(context, port_data)
        self._remove_provider_security_groups_from_list(port_data)

        # Add Mac/IP binding to native DHCP server and neutron DB.
        try:
            if self.use_policy_dhcp:
                self._add_port_policy_dhcp_binding(context, port_data)
            elif cfg.CONF.nsx_p.allow_passthrough:
                self._add_port_mp_dhcp_binding(context, port_data)
        except nsx_lib_exc.ManagerError:
            # Rollback create port
            self.delete_port(context, port_data['id'],
                             force_delete_dhcp=True)
            msg = _('Unable to create port. Please contact admin')
            LOG.exception(msg)
            raise nsx_exc.NsxPluginException(err_msg=msg)

        kwargs = {'context': context, 'port': neutron_db}
        registry.notify(resources.PORT, events.AFTER_CREATE, self, **kwargs)
        return port_data

    def _delete_port_on_backend(self, context, net_id, port_id):
        try:
            segment_id = self._get_network_nsx_segment_id(context, net_id)
            self.nsxpolicy.segment_port_security_profiles.delete(
                segment_id, port_id)
            self.nsxpolicy.segment_port_discovery_profiles.delete(
                segment_id, port_id)
            if directory.get_plugin(plugin_const.QOS):
                self.nsxpolicy.segment_port_qos_profiles.delete(
                    segment_id, port_id)
            self.nsxpolicy.segment_port.delete(segment_id, port_id)
        except nsx_lib_exc.ResourceNotFound:
            # If the resource was not found on the backend do not worry about
            # it. The conditions has already been logged, so there is no need
            # to do further logging
            pass
        except nsx_lib_exc.ManagerError as e:
            # If there is a failure in deleting the resource.
            # In this case the neutron port was not deleted yet.
            msg = (_("Backend port deletion for neutron port %(id)s "
                     "failed: %(e)s") % {'id': port_id, 'e': e})
            raise nsx_exc.NsxPluginException(err_msg=msg)

    def delete_port(self, context, port_id,
                    l3_port_check=True, l2gw_port_check=True,
                    force_delete_dhcp=False,
                    force_delete_vpn=False):
        # first update neutron (this will perform all types of validations)
        port_data = self.get_port(context, port_id)
        net_id = port_data['network_id']
        # if needed, check to see if this is a port owned by
        # a l3 router.  If so, we should prevent deletion here
        if l3_port_check:
            self.prevent_l3_port_deletion(context, port_id)
        # Prevent DHCP port deletion if native support is enabled
        if (cfg.CONF.nsx_p.allow_passthrough and
            not force_delete_dhcp and
            port_data['device_owner'] in [const.DEVICE_OWNER_DHCP]):
            msg = (_('Can not delete DHCP port %s') % port_id)
            raise n_exc.BadRequest(resource='port', msg=msg)
        if not force_delete_vpn:
            self._assert_on_vpn_port_change(port_data)

        self.disassociate_floatingips(context, port_id)

        # Remove Mac/IP binding from native DHCP server and neutron DB.
        if self.use_policy_dhcp:
            self._delete_port_policy_dhcp_binding(context, port_data)
        elif cfg.CONF.nsx_p.allow_passthrough:
            self._delete_port_mp_dhcp_binding(context, port_data)

        super(NsxPolicyPlugin, self).delete_port(context, port_id)

        # Delete the backend port last to prevent recreation by another process
        if self._is_backend_port(context, port_data, delete=True):
            try:
                self._delete_port_on_backend(context, net_id, port_id)
            except nsx_lib_exc.ResourceNotFound:
                # If the resource was not found on the backend do not worry
                # about it. The conditions has already been logged, so there
                # is no need to do further logging
                pass
            except nsx_lib_exc.ManagerError as e:
                # If there is a failure in deleting the resource, fail the
                # neutron operation even though the neutron object was already
                # deleted. This way the user will be aware of zombie resources
                # that may fail future actions.
                msg = (_("Backend segment port deletion for neutron port "
                         "%(id)s failed. The object was however removed from "
                         "the Neutron database: %(e)s") %
                       {'id': port_id, 'e': e})
                raise nsx_exc.NsxPluginException(err_msg=msg)

    def _update_port_on_backend(self, context, lport_id,
                                original_port, updated_port,
                                is_psec_on, qos_policy_id):
        # For now port create and update are the same
        # Update might evolve with more features
        return self._create_or_update_port_on_backend(
            context, updated_port, is_psec_on,
            qos_policy_id, original_port=original_port)

    def update_port(self, context, port_id, port):
        with db_api.CONTEXT_WRITER.using(context):
            # get the original port, and keep it honest as it is later used
            # for notifications
            original_port = super(NsxPolicyPlugin, self).get_port(
                context, port_id)
            self._remove_provider_security_groups_from_list(original_port)
            port_data = port['port']
            self._validate_update_port(context, port_id, original_port,
                                       port_data)
            self._assert_on_resource_admin_state_down(port_data)
            validate_port_sec = self._should_validate_port_sec_on_update_port(
                port_data)
            is_external_net = self._network_is_external(
                context, original_port['network_id'])
            if is_external_net:
                self._assert_on_external_net_with_compute(port_data)
            device_owner = (port_data['device_owner']
                            if 'device_owner' in port_data
                            else original_port.get('device_owner'))
            self._validate_max_ips_per_port(context,
                                            port_data.get('fixed_ips', []),
                                            device_owner)

            direct_vnic_type = self._validate_port_vnic_type(
                context, port_data, original_port['network_id'])
            self._assert_on_ipv6_port_with_dhcpopts(
                context, port_data, orig_port=original_port)

            updated_port = super(NsxPolicyPlugin, self).update_port(
                context, port_id, port)

            self._extension_manager.process_update_port(context, port_data,
                                                        updated_port)
            # copy values over - except fixed_ips as
            # they've already been processed
            port_data.pop('fixed_ips', None)
            updated_port.update(port_data)

            updated_port = self._update_port_preprocess_security(
                context, port, port_id, updated_port, False,
                validate_port_sec=validate_port_sec,
                direct_vnic_type=direct_vnic_type)

            self._update_extra_dhcp_opts_on_port(context, port_id, port,
                                                 updated_port)

            sec_grp_updated = self.update_security_group_on_port(
                context, port_id, port, original_port, updated_port)

            self._process_port_update_provider_security_group(
                context, port, original_port, updated_port)

            (port_security, has_ip) = self._determine_port_security_and_has_ip(
                context, updated_port)
            self._process_portbindings_create_and_update(
                context, port_data, updated_port,
                vif_type=self._vif_type_by_vnic_type(direct_vnic_type))
            self._extend_nsx_port_dict_binding(context, updated_port)

            mac_learning_state = updated_port.get(mac_ext.MAC_LEARNING)
            if mac_learning_state is not None:
                if port_security and mac_learning_state:
                    msg = _('Mac learning requires that port security be '
                            'disabled')
                    LOG.error(msg)
                    raise n_exc.InvalidInput(error_message=msg)
                self._update_mac_learning_state(context, port_id,
                                                mac_learning_state)
            self._remove_provider_security_groups_from_list(updated_port)

        # Update the QoS policy
        qos_policy_id = self._get_port_qos_policy_id(
            context, original_port, updated_port)
        qos_com_utils.update_port_policy_binding(context, port_id,
                                                 qos_policy_id)

        # update the port in the backend, only if it exists in the DB
        # (i.e not external net) and is not router interface
        if self._is_backend_port(context, updated_port):
            try:
                self._update_port_on_backend(context, port_id,
                                             original_port, updated_port,
                                             port_security, qos_policy_id)
            except Exception as e:
                LOG.error('Failed to update port %(id)s on NSX '
                          'backend. Exception: %(e)s',
                          {'id': port_id, 'e': e})
                # Rollback the change
                with db_api.CONTEXT_WRITER.using(context):
                    self._revert_neutron_port_update(
                        context, port_id, original_port, updated_port,
                        port_security, sec_grp_updated)
                self.raise_port_error(e)
        else:
            # if this port changed ownership to router interface, it should
            # be deleted from policy, since policy handles router connectivity
            original_owner = original_port.get('device_owner')
            new_owner = port_data.get('device_owner')
            if (original_owner != new_owner and
                new_owner == const.DEVICE_OWNER_ROUTER_INTF):
                self._delete_port_on_backend(context,
                                             original_port['network_id'],
                                             port_id)

        # Update DHCP bindings.
        if self.use_policy_dhcp:
            self._update_port_policy_dhcp_binding(
                context, original_port, updated_port)
        elif cfg.CONF.nsx_p.allow_passthrough:
            self._update_port_mp_dhcp_binding(
                context, original_port, updated_port)

        # Make sure the port revision is updated
        if 'revision_number' in updated_port:
            port_model = self._get_port(context, port_id)
            updated_port['revision_number'] = port_model.revision_number

        # Notifications must be sent after the above transaction is complete
        kwargs = {
            'context': context,
            'port': updated_port,
            'mac_address_updated': False,
            'original_port': original_port,
        }
        registry.notify(resources.PORT, events.AFTER_UPDATE, self, **kwargs)
        return updated_port

    def get_port(self, context, id, fields=None):
        port = super(NsxPolicyPlugin, self).get_port(
            context, id, fields=None)
        self._extend_nsx_port_dict_binding(context, port)
        self._extend_qos_port_dict_binding(context, port)
        self._remove_provider_security_groups_from_list(port)
        return db_utils.resource_fields(port, fields)

    def get_ports(self, context, filters=None, fields=None,
                  sorts=None, limit=None, marker=None,
                  page_reverse=False):
        filters = filters or {}
        self._update_filters_with_sec_group(context, filters)
        with db_api.CONTEXT_READER.using(context):
            ports = (
                super(NsxPolicyPlugin, self).get_ports(
                    context, filters, fields, sorts,
                    limit, marker, page_reverse))
            self._log_get_ports(ports, filters)
            # Add port extensions
            for port in ports[:]:
                self._extend_nsx_port_dict_binding(context, port)
                self._extend_qos_port_dict_binding(context, port)
                self._remove_provider_security_groups_from_list(port)
        return (ports if not fields else
                [db_utils.resource_fields(port, fields) for port in ports])

    def _add_subnet_snat_rule(self, context, router_id, subnet,
                              gw_address_scope, gw_ip):
        if not self._need_router_snat_rules(context, router_id, subnet,
                                            gw_address_scope):
            return

        firewall_match = self._get_nat_firewall_match()
        self.nsxpolicy.tier1_nat_rule.create_or_overwrite(
            'snat for subnet %s' % subnet['id'],
            router_id,
            nat_rule_id=self._get_snat_rule_id(subnet),
            action=policy_constants.NAT_ACTION_SNAT,
            sequence_number=NAT_RULE_PRIORITY_GW,
            translated_network=gw_ip,
            source_network=subnet['cidr'],
            firewall_match=firewall_match)

    def _get_snat_rule_id(self, subnet):
        return 'S-' + subnet['id']

    def _get_no_dnat_rule_id(self, subnet):
        return 'ND-' + subnet['id']

    def _add_subnet_no_dnat_rule(self, context, router_id, subnet):
        if not self._need_router_no_dnat_rules(subnet):
            return

        # Add NO-DNAT rule to allow internal traffic between VMs, even if
        # they have floating ips (Only for routers with snat enabled)
        self.nsxpolicy.tier1_nat_rule.create_or_overwrite(
            'no-dnat for subnet %s' % subnet['id'],
            router_id,
            nat_rule_id=self._get_no_dnat_rule_id(subnet),
            action=policy_constants.NAT_ACTION_NO_DNAT,
            sequence_number=NAT_RULE_PRIORITY_GW,
            destination_network=subnet['cidr'],
            firewall_match=policy_constants.NAT_FIREWALL_MATCH_BYPASS)

    def _del_subnet_no_dnat_rule(self, router_id, subnet):
        # Delete the previously created NO-DNAT rules
        self.nsxpolicy.tier1_nat_rule.delete(
            router_id,
            nat_rule_id=self._get_no_dnat_rule_id(subnet))

    def _del_subnet_snat_rule(self, router_id, subnet):
        # Delete the previously created SNAT rules
        self.nsxpolicy.tier1_nat_rule.delete(
            router_id,
            nat_rule_id=self._get_snat_rule_id(subnet))

    def _get_router_edge_cluster_path(self, tier0_uuid, router):
        # Take the AZ edge cluster if configured
        az = self._get_router_az_obj(router)
        if az and az._edge_cluster_uuid:
            ec_id = az._edge_cluster_uuid
            # get the full path of the edge cluster (no backend call)
            return self.nsxpolicy.edge_cluster.get_path(ec_id)

        # Get the current tier0 edge cluster (cached call)
        return self.nsxpolicy.tier0.get_edge_cluster_path(
            tier0_uuid)

    def _get_router_vlan_interfaces(self, context, router_id):
        # return data about VLAN subnet connected to the router
        rtr_subnets = self._load_router_subnet_cidrs_from_db(
            context, router_id)
        vlan_subnets = []
        for sub in rtr_subnets:
            net_id = sub['network_id']
            if not self._is_overlay_network(context, net_id):
                vlan_subnets.append(sub)
        return vlan_subnets

    def service_router_has_services(self, context, router_id, router=None):
        """Check if the neutron router has any services
        which require a backend service router
        currently those are: SNAT, Loadbalancer, Edge firewall,
        VPNaaS & Vlan interfaces
        """
        if not router:
            router = self._get_router(context, router_id)
        snat_exist = router.enable_snat
        fw_exist = self._router_has_edge_fw_rules(context, router)
        vpn_exist = self.service_router_has_vpnaas(context, router_id)
        lb_exist = False
        vlan_interfaces = []
        if not (fw_exist or snat_exist or vpn_exist):
            vlan_interfaces = self._get_router_vlan_interfaces(
                context.elevated(), router_id)
            if not vlan_interfaces:
                lb_exist = self.service_router_has_loadbalancers(
                    context, router_id)
        return (snat_exist or lb_exist or fw_exist or vpn_exist or
                vlan_interfaces)

    def service_router_has_loadbalancers(self, context, router_id):
        service = lb_utils.get_router_nsx_lb_service(self.nsxpolicy, router_id)
        return bool(service)

    def service_router_has_vpnaas(self, context, router_id):
        """Return True if there is a vpn service attached to this router"""
        vpn_plugin = directory.get_plugin(plugin_const.VPN)
        if vpn_plugin:
            filters = {'router_id': [router_id]}
            if vpn_plugin.get_vpnservices(context.elevated(), filters=filters):
                return True
        return False

    def verify_sr_at_backend(self, context, router_id):
        """Check if the backend Tier1 has a service router or not"""
        # Note - this method gets the context so it will have the same
        # signature as the v3 plugin method
        if self.nsxpolicy.tier1.get_edge_cluster_path(router_id):
            return True

    def _wait_until_edge_cluster_realized(self, router_id):
        """Wait until MP logical router has an edge-cluster

        Since currently the locale-services has no realization info,
        And some actions should be performed only after it was realized,
        this method checks the MP Lr for its edge-cluster id until it is set.
        """
        if not cfg.CONF.nsx_p.allow_passthrough:
            return

        lr_id = self.nsxpolicy.tier1.get_realized_id(
            router_id, entity_type='RealizedLogicalRouter')
        if not lr_id:
            LOG.error("_wait_until_edge_cluster_realized Failed: No MP id "
                      "found for Tier1 %s", router_id)
            return

        test_num = 0
        max_attempts = cfg.CONF.nsx_p.realization_max_attempts
        sleep = cfg.CONF.nsx_p.realization_wait_sec
        while test_num < max_attempts:
            # get all the realized resources of the tier1
            lr = self.nsxlib.logical_router.get(lr_id)
            if lr.get('edge_cluster_id'):
                break
            time.sleep(sleep)
            test_num += 1

        if lr.get('edge_cluster_id'):
            LOG.debug("MP LR %s of Tier1 %s edge cluster %s was set after %s "
                      "attempts", lr_id, router_id, lr.get('edge_cluster_id'),
                      test_num + 1)
        else:
            LOG.error("MP LR %s if Tier1 %s edge cluster was not set after %s "
                      "attempts", lr_id, router_id, test_num + 1)

    def create_service_router(self, context, router_id, router=None,
                              update_firewall=True):
        """Create a service router and enable standby relocation"""
        if not router:
            router = self._get_router(context, router_id)
        tier0_uuid = self._get_tier0_uuid_by_router(context, router)
        if not tier0_uuid:
            err_msg = (_("Cannot create service router for %s without a "
                         "gateway") % router_id)
            raise n_exc.InvalidInput(error_message=err_msg)
        edge_cluster_path = self._get_router_edge_cluster_path(
            tier0_uuid, router)
        if edge_cluster_path:
            self.nsxpolicy.tier1.set_edge_cluster_path(
                router_id, edge_cluster_path)
        else:
            LOG.error("Tier0 %s does not have an edge cluster",
                      tier0_uuid)

        try:
            # Enable standby relocation & FW on this router
            self.nsxpolicy.tier1.update(
                router['id'], disable_firewall=False,
                enable_standby_relocation=True)
        except Exception as ex:
            LOG.warning("Failed to enable standby relocation for router "
                        "%s: %s", router_id, ex)

        # Validate locale-services realization before additional tier1 config
        self._wait_until_edge_cluster_realized(router_id)

        # update firewall rules (there might be FW group waiting for a
        # service router)
        if update_firewall:
            self.update_router_firewall(context, router_id)

    def delete_service_router(self, router_id):
        """Delete the Tier1 service router by removing its edge cluster
        Before that - disable all the features that require the service
        router to exist.
        """
        # remove the gateway firewall policy
        if self.fwaas_callbacks and self.fwaas_callbacks.fwaas_enabled:
            self.fwaas_callbacks.delete_router_gateway_policy(router_id)

        # Disable gateway firewall and standby relocation
        self.nsxpolicy.tier1.update(
            router_id, disable_firewall=True, enable_standby_relocation=False)

        # remove the edge cluster from the tier1 router
        self.nsxpolicy.tier1.remove_edge_cluster(router_id)

    def _run_under_transaction(self, method):
        if self.nsxpolicy.feature_supported(
            nsxlib_consts.FEATURE_PARTIAL_UPDATES):
            with policy_trans.NsxPolicyTransaction():
                method()
        else:
            method()

    def _update_router_gw_info(self, context, router_id, info,
                               called_from=None):
        # Get the original data of the router GW
        router = self._get_router(context, router_id)
        orig_info = self._get_router_gw_info(context, router_id)
        org_tier0_uuid = self._get_tier0_uuid_by_router(context, router)
        org_enable_snat = router.enable_snat
        orgaddr, orgmask, _orgnexthop = (
            self._get_external_attachment_info(
                context, router))
        router_subnets = self._load_router_subnet_cidrs_from_db(
            context.elevated(), router_id)
        self._validate_router_gw_and_tz(context, router_id, info,
                                        org_enable_snat, router_subnets)
        # Interface subnets cannot overlap with the GW external subnet
        if info and info.get('network_id'):
            self._validate_gw_overlap_interfaces(
                context, info['network_id'],
                [sub['network_id'] for sub in router_subnets])

        # First update the neutron DB
        super(NsxPolicyPlugin, self)._update_router_gw_info(
            context, router_id, info, router=router)

        # Get the new tier0 of the updated router (or None if GW was removed)
        new_tier0_uuid = self._get_tier0_uuid_by_router(context, router)
        new_enable_snat = router.enable_snat
        newaddr, newmask, _newnexthop = self._get_external_attachment_info(
            context, router)
        sr_currently_exists = self.verify_sr_at_backend(context, router_id)
        fw_exist = self._router_has_edge_fw_rules(context, router)
        vpn_exist = self.service_router_has_vpnaas(context, router_id)
        lb_exist = False
        if not (fw_exist or vpn_exist):
            # This is a backend call, so do it only if must
            lb_exist = self.service_router_has_loadbalancers(
                context, router_id)
        tier1_services_exist = fw_exist or vpn_exist or lb_exist

        actions = self._get_update_router_gw_actions(
            org_tier0_uuid, orgaddr, org_enable_snat,
            new_tier0_uuid, newaddr, new_enable_snat,
            tier1_services_exist, sr_currently_exists)
        try:
            if actions['add_service_router']:
                self.create_service_router(context, router_id, router=router)

            def _do_remove_nat():
                if actions['remove_snat_rules']:
                    for subnet in router_subnets:
                        self._del_subnet_snat_rule(router_id, subnet)
                if actions['remove_no_dnat_rules']:
                    for subnet in router_subnets:
                        self._del_subnet_no_dnat_rule(router_id, subnet)

            self._run_under_transaction(_do_remove_nat)

            if (actions['remove_router_link_port'] or
                actions['add_router_link_port']):
                # GW was changed. update GW and route advertisement
                self.nsxpolicy.tier1.update_route_advertisement(
                    router_id,
                    static_routes=not new_enable_snat,
                    nat=actions['advertise_route_nat_flag'],
                    subnets=actions['advertise_route_connected_flag'],
                    tier0=new_tier0_uuid)
            else:
                # Only update route advertisement
                self.nsxpolicy.tier1.update_route_advertisement(
                    router_id,
                    static_routes=not new_enable_snat,
                    nat=actions['advertise_route_nat_flag'],
                    subnets=actions['advertise_route_connected_flag'])

            def _do_add_nat():
                if actions['add_snat_rules']:
                    # Add SNAT rules for all the subnets which are in different
                    # scope than the GW
                    gw_address_scope = self._get_network_address_scope(
                        context, router.gw_port.network_id)
                    for subnet in router_subnets:
                        self._add_subnet_snat_rule(context, router_id,
                                                   subnet, gw_address_scope,
                                                   newaddr)
                if actions['add_no_dnat_rules']:
                    for subnet in router_subnets:
                        self._add_subnet_no_dnat_rule(
                            context, router_id, subnet)

            self._run_under_transaction(_do_add_nat)

            # always advertise ipv6 subnets if gateway is set
            advertise_ipv6_subnets = bool(info)
            self._update_router_advertisement_rules(router_id,
                                                    router_subnets,
                                                    advertise_ipv6_subnets)
            if actions['remove_service_router']:
                self.delete_service_router(router_id)
        except nsx_lib_exc.NsxLibException as e:
            # GW updates failed on the NSX. Rollback the change,
            # unless it is during create or delete of a router
            with excutils.save_and_reraise_exception():
                if not called_from:
                    LOG.error("Rolling back router %s GW info update because "
                              "of NSX failure %s", router_id, e)
                    super(NsxPolicyPlugin, self)._update_router_gw_info(
                        context, router_id, orig_info, router=router)

    def _update_router_advertisement_rules(self, router_id, subnets,
                                           advertise_ipv6):

        # There is no NAT for ipv6 - all connected ipv6 segments should be
        # advertised
        ipv6_cidrs = [s['cidr'] for s in subnets if s.get('ip_version') == 6]
        if ipv6_cidrs and advertise_ipv6:
            self.nsxpolicy.tier1.add_advertisement_rule(
                router_id,
                IPV6_ROUTER_ADV_RULE_NAME,
                policy_constants.ADV_RULE_PERMIT,
                policy_constants.ADV_RULE_OPERATOR_EQ,
                [policy_constants.ADV_RULE_TIER1_CONNECTED],
                ipv6_cidrs)
        else:
            self.nsxpolicy.tier1.remove_advertisement_rule(
                router_id, IPV6_ROUTER_ADV_RULE_NAME)

    def create_router(self, context, router):
        r = router['router']
        gw_info = self._extract_external_gw(context, router, is_extract=True)

        # validate the availability zone, and get the AZ object
        self._validate_obj_az_on_creation(context, r, 'router')

        with db_api.CONTEXT_WRITER.using(context):
            router = super(NsxPolicyPlugin, self).create_router(
                context, router)
            router_db = self._get_router(context, router['id'])
            self._process_extra_attr_router_create(context, router_db, r)

        router_name = utils.get_name_and_uuid(router['name'] or 'router',
                                              router['id'])
        tags = self.nsxpolicy.build_v3_tags_payload(
            r, resource_type='os-neutron-router-id',
            project_name=context.tenant_name)
        try:
            def _do_create_router():
                self.nsxpolicy.tier1.create_or_overwrite(
                    router_name, router['id'],
                    tier0=None,
                    ipv6_ndra_profile_id=NO_SLAAC_NDRA_PROFILE_ID,
                    tags=tags)
                # Also create the empty locale-service as it must always exist
                self.nsxpolicy.tier1.create_locale_service(router['id'])

            self._run_under_transaction(_do_create_router)

        except Exception as ex:
            with excutils.save_and_reraise_exception():
                LOG.error('Failed to create router %(id)s '
                          'on NSX backend. Exception: %(e)s',
                          {'id': router['id'], 'e': ex})
                self.delete_router(context, router['id'])

        if gw_info and gw_info != const.ATTR_NOT_SPECIFIED:
            try:
                self._update_router_gw_info(context, router['id'], gw_info,
                                            called_from="create")
            except (db_exc.DBError, nsx_lib_exc.NsxLibException):
                with excutils.save_and_reraise_exception():
                    LOG.error("Failed to set gateway info for router "
                              "being created: %s - removing router",
                              router['id'])
                    self.delete_router(context, router['id'])
                    LOG.info("Create router failed while setting external "
                             "gateway. Router:%s has been removed from "
                             "DB and backend",
                             router['id'])

        return self.get_router(context, router['id'])

    def delete_router(self, context, router_id):
        gw_info = self._get_router_gw_info(context, router_id)
        if gw_info:
            try:
                self._update_router_gw_info(context, router_id, {},
                                            called_from="delete")
            except nsx_lib_exc.NsxLibException as e:
                LOG.error("Failed to remove router %s gw info before "
                          "deletion, but going on with the deletion anyway: "
                          "%s", router_id, e)

        super(NsxPolicyPlugin, self).delete_router(context, router_id)

        try:
            self.nsxpolicy.tier1.delete_locale_service(router_id)
            self.nsxpolicy.tier1.delete(router_id)
        except nsx_lib_exc.ResourceNotFound:
            # If the resource was not found on the backend do not worry about
            # it. The conditions has already been logged, so there is no need
            # to do further logging
            pass
        except nsx_lib_exc.ManagerError as e:
            # If there is a failure in deleting the resource, fail the neutron
            # operation even though the neutron object was already deleted.
            # This way the user will be aware of zombie resources that may fail
            # future actions.
            msg = (_("Backend Tier1 deletion for neutron router %(id)s "
                     "failed. The object was however removed from the "
                     "Neutron database: %(e)s") % {'id': router_id, 'e': e})
            nsx_exc.NsxPluginException(err_msg=msg)

    def _get_static_route_id(self, route):
        return "%s-%s" % (route['destination'].replace('/', '_'),
                          route['nexthop'])

    def _add_static_routes(self, router_id, routes):
        def _do_add_routes():
            for route in routes:
                dest = route['destination']
                self.nsxpolicy.tier1_static_route.create_or_overwrite(
                    'Static route for %s' % dest,
                    router_id,
                    static_route_id=self._get_static_route_id(route),
                    network=dest,
                    next_hop=route['nexthop'])

        self._run_under_transaction(_do_add_routes)

    def _delete_static_routes(self, router_id, routes):
        for route in routes:
            self.nsxpolicy.tier1_static_route.delete(
                router_id,
                static_route_id=self._get_static_route_id(route))

    @nsx_plugin_common.api_replay_mode_wrapper
    def update_router(self, context, router_id, router):
        gw_info = self._extract_external_gw(context, router, is_extract=False)
        router_data = router['router']
        self._assert_on_router_admin_state(router_data)

        vpn_driver = None
        if validators.is_attr_set(gw_info):
            self._validate_update_router_gw(context, router_id, gw_info)

            # VPNaaS need to be notified on router GW changes (there is
            # currently no matching upstream registration for this)
            vpn_plugin = directory.get_plugin(plugin_const.VPN)
            if vpn_plugin:
                vpn_driver = vpn_plugin.drivers[vpn_plugin.default_provider]
                vpn_driver.validate_router_gw_info(context, router_id, gw_info)

        routes_added = []
        routes_removed = []
        if 'routes' in router_data:
            routes_added, routes_removed = self._get_static_routes_diff(
                context, router_id, gw_info, router_data)

        # Update the neutron router
        updated_router = super(NsxPolicyPlugin, self).update_router(
            context, router_id, router)

        # Update the policy backend
        try:
            added_routes = removed_routes = False
            # Updating name & description
            if 'name' in router_data or 'description' in router_data:
                router_name = utils.get_name_and_uuid(
                    updated_router.get('name') or 'router',
                    router_id)
                self.nsxpolicy.tier1.update(
                    router_id, name=router_name,
                    description=updated_router.get('description', ''))
            # Updating static routes
            self._delete_static_routes(router_id, routes_removed)
            removed_routes = True
            self._add_static_routes(router_id, routes_added)
            added_routes = True

        except (nsx_lib_exc.ResourceNotFound, nsx_lib_exc.ManagerError):
            with excutils.save_and_reraise_exception():
                with db_api.CONTEXT_WRITER.using(context):
                    router_db = self._get_router(context, router_id)
                    router_db['status'] = const.NET_STATUS_ERROR
                # return the static routes to the old state
                if added_routes:
                    try:
                        self._delete_static_routes(router_id, routes_added)
                    except Exception as e:
                        LOG.error("Rollback router %s changes failed to "
                                  "delete static routes: %s", router_id, e)
                if removed_routes:
                    try:
                        self._add_static_routes(router_id, routes_removed)
                    except Exception as e:
                        LOG.error("Rollback router %s changes failed to add "
                                  "static routes: %s", router_id, e)
        if vpn_driver:
            # Update vpn advertisement if GW was updated
            vpn_driver.update_router_advertisement(context, router_id)
        return updated_router

    def _get_gateway_addr_from_subnet(self, subnet):
        if subnet['gateway_ip'] and subnet['cidr']:
            cidr_prefix = int(subnet['cidr'].split('/')[1])
            return "%s/%s" % (subnet['gateway_ip'], cidr_prefix)

    def _validate_router_segment_subnets(self, context, network_id,
                                         overlay_net, subnet):
        """Validate that adding an interface to a router will not cause
        multiple segments subnets which is not allowed
        """
        if not overlay_net:
            # Only interfaces for overlay networks create segment subnets
            return

        if subnet.get('ip_version', 4) != 4:
            # IPv6 is not relevant here since plugin allow only 1 ipv6 subnet
            # per network
            return

        if subnet['enable_dhcp']:
            # This subnet is with dhcp, so there cannot be any other with dhcp
            return

        if not self.use_policy_dhcp:
            # Only policy DHCP creates segment subnets
            return

        # Look for another subnet with DHCP
        network = self._get_network(context.elevated(), network_id)
        for subnet in network.subnets:
            if subnet.enable_dhcp and subnet.ip_version == 4:
                msg = (_("Can not add router interface on network %(net)s "
                         "as another %(ver)s subnet has enabled DHCP") %
                       {'net': network_id, 'ver': subnet.ip_version})
                LOG.error(msg)
                raise n_exc.InvalidInput(error_message=msg)

    def _get_subnet_ndra_profile(self, subnet):
        ndra_profile_id = NO_SLAAC_NDRA_PROFILE_ID
        if subnet.get('ip_version') == 6 and subnet.get('enable_dhcp', False):
            # Subnet with DHCP v6 of some kind
            addr_mode = subnet.get('ipv6_address_mode')
            if addr_mode == const.IPV6_SLAAC:
                ndra_profile_id = SLAAC_NDRA_PROFILE_ID
            elif addr_mode == const.DHCPV6_STATELESS:
                ndra_profile_id = STATELESS_DHCP_NDRA_PROFILE_ID
            else:
                # Stateful DHCP v6 is the default
                ndra_profile_id = STATEFUL_DHCP_NDRA_PROFILE_ID
        return ndra_profile_id

    def _validate_interfaces_address_mode(self, context, router_id,
                                          router_subnets, subnet):
        """Validate that all the overlay ipv6 interfaces of the router have
        the same ipv6_address_mode, when a new subnet is added
        """
        if subnet['enable_dhcp']:
            subnet_address_mode = subnet.get('ipv6_address_mode',
                                             const.DHCPV6_STATEFUL)
        else:
            # Slaac and non-dhcp can coexist
            subnet_address_mode = const.IPV6_SLAAC

        ipv6_overlay_subnets = [s for s in router_subnets
                                if s['id'] != subnet['id'] and
                                s.get('ip_version') == 6 and
                                s.get('enable_dhcp') and
                                self._is_overlay_network(context,
                                                         s['network_id'])]
        for rtr_subnet in ipv6_overlay_subnets:
            address_mode = rtr_subnet.get('ipv6_address_mode',
                                          const.DHCPV6_STATEFUL)
            if address_mode != subnet_address_mode:
                msg = (_("Interface network %(net_id)s with address mode "
                         "%(am)s conflicts with other interfaces of router "
                         "%(rtr_id)s") % {'net_id': subnet['network_id'],
                                          'am': subnet_address_mode,
                                          'rtr_id': router_id})
                LOG.error(msg)
                raise n_exc.InvalidInput(error_message=msg)

    @nsx_plugin_common.api_replay_mode_wrapper
    def add_router_interface(self, context, router_id, interface_info):
        # NOTE: In dual stack case, neutron would create a separate interface
        # for each IP version
        # We only allow one subnet per IP version
        subnet = self._get_interface_subnet(context, interface_info)
        network_id = self._get_interface_network_id(context, interface_info,
                                                    subnet=subnet)
        extern_net = self._network_is_external(context, network_id)
        overlay_net = self._is_overlay_network(context, network_id)
        router_db = self._get_router(context, router_id)
        gw_network_id = (router_db.gw_port.network_id if router_db.gw_port
                         else None)

        with locking.LockManager.get_lock(str(network_id)):
            # disallow more than one subnets belong to same network being
            # attached to routers
            self._validate_multiple_subnets_routers(
                context, router_id, network_id, subnet)

            # A router interface cannot be an external network
            if extern_net:
                msg = _("An external network cannot be attached as "
                        "an interface to a router")
                raise n_exc.InvalidInput(error_message=msg)

            # Non overlay networks should be configured with a centralized
            # router, which is allowed only if GW network is attached
            if not overlay_net and not gw_network_id:
                msg = _("A router attached to a VLAN backed network "
                        "must have an external network assigned")
                raise n_exc.InvalidInput(error_message=msg)

            # Interface subnets cannot overlap with the GW external subnet
            self._validate_gw_overlap_interfaces(context, gw_network_id,
                                                 [network_id])

            if subnet:
                self._validate_router_segment_subnets(context, network_id,
                                                      overlay_net, subnet)

            if subnet and subnet.get('ip_version') == 6 and overlay_net:
                orig_rtr_subnets = self._load_router_subnet_cidrs_from_db(
                    context.elevated(), router_id)
                self._validate_interfaces_address_mode(
                    context, router_id, orig_rtr_subnets, subnet)

            # Update the interface of the neutron router
            info = super(NsxPolicyPlugin, self).add_router_interface(
                context, router_id, interface_info)

        try:
            # If it is a no-snat router, interface address scope must be the
            # same as the gateways
            self._validate_interface_address_scope(context, router_db, subnet)

            # Check GW & subnets TZ
            tier0_uuid = self._get_tier0_uuid_by_router(
                context.elevated(), router_db)
            # Validate the TZ of the new subnet match the one of the router
            self._validate_router_tz(context.elevated(), tier0_uuid, [subnet])

            segment_id = self._get_network_nsx_segment_id(context, network_id)
            rtr_subnets = self._load_router_subnet_cidrs_from_db(
                context.elevated(), router_id)
            if overlay_net:
                # overlay interface
                pol_subnets = self._get_segment_subnets(
                    context, network_id, interface_subnets=rtr_subnets)
                self.nsxpolicy.segment.update(segment_id,
                                              tier1_id=router_id,
                                              subnets=pol_subnets)

                # will update the router only if needed
                self._update_slaac_on_router(context, router_id,
                                             subnet, rtr_subnets)
            else:
                # Vlan interface
                pol_subnets = []
                for rtr_subnet in rtr_subnets:
                    if rtr_subnet['network_id'] == network_id:
                        prefix_len = int(rtr_subnet['cidr'].split('/')[1])
                        pol_subnets.append(policy_defs.InterfaceSubnet(
                            ip_addresses=[rtr_subnet['gateway_ip']],
                            prefix_len=prefix_len))

                # Service router is mandatory for VLAN interfaces
                if not self.verify_sr_at_backend(context, router_id):
                    self.create_service_router(
                        context, router_id, router=router_db,
                        update_firewall=False)

                ndra_profile_id = self._get_subnet_ndra_profile(subnet)
                self.nsxpolicy.tier1.add_segment_interface(
                    router_id, segment_id,
                    segment_id, pol_subnets,
                    ndra_profile_id)

            # add the SNAT/NO_DNAT rules for this interface
            if router_db.enable_snat and gw_network_id:
                if router_db.gw_port.get('fixed_ips'):
                    gw_ip = router_db.gw_port['fixed_ips'][0]['ip_address']
                    gw_address_scope = self._get_network_address_scope(
                        context, gw_network_id)
                    self._add_subnet_snat_rule(
                        context, router_id,
                        subnet, gw_address_scope, gw_ip)
                self._add_subnet_no_dnat_rule(context, router_id, subnet)

            if subnet.get('ip_version') == 6 and gw_network_id:
                # if this is an ipv6 subnet and router has GW,
                # we need to add advertisement rule
                self._update_router_advertisement_rules(
                    router_id, rtr_subnets, True)

            # update firewall rules
            self.update_router_firewall(context, router_id, router_db)

        except Exception as ex:
            with excutils.save_and_reraise_exception():
                LOG.error('Failed to create router interface for network '
                          '%(id)s on NSX backend. Exception: %(e)s',
                          {'id': network_id, 'e': ex})
                self.remove_router_interface(
                    context, router_id, interface_info)

        return info

    def remove_router_interface(self, context, router_id, interface_info):
        # First get the subnet, which is needed for removing the SNAT rule
        subnet = subnet_id = None
        if 'port_id' in interface_info:
            port_id = interface_info['port_id']
            port = self._get_port(context, port_id)
            if port.get('fixed_ips'):
                subnet_id = port['fixed_ips'][0]['subnet_id']
        elif 'subnet_id' in interface_info:
            subnet_id = interface_info['subnet_id']
        if subnet_id:
            subnet = self.get_subnet(context, subnet_id)

        # Update the neutron router first
        info = super(NsxPolicyPlugin, self).remove_router_interface(
            context, router_id, interface_info)
        network_id = info['network_id']
        overlay_net = self._is_overlay_network(context, network_id)
        segment_id = self._get_network_nsx_segment_id(context, network_id)

        rtr_subnets = self._load_router_subnet_cidrs_from_db(
            context.elevated(), router_id)
        net_rtr_subnets = [sub for sub in rtr_subnets
                           if sub['network_id'] == network_id]
        try:
            if overlay_net:
                # Update the segment subnets, and Remove the tier1 router from
                # this segment it its the last subnet of this network
                # (it is possible to have both IPv4 & 6 subnets)
                seg_subnets = self._get_segment_subnets(
                    context, network_id, interface_subnets=net_rtr_subnets)

                if not net_rtr_subnets and not seg_subnets:
                    # Remove the tier1 connectivity of this segment
                    # This must be done is a separate call as it uses PUT
                    self.nsxpolicy.segment.remove_connectivity_and_subnets(
                        segment_id)
                else:
                    #TODO(asarfaty): Try to combine the 2 backend calls
                    if not net_rtr_subnets:
                        # Remove connectivity path
                        # This must be done is a separate call as it uses PUT
                        self.nsxpolicy.segment.remove_connectivity_path(
                            segment_id)

                    # update remaining (DHCP/ipv4/6) subnets
                    if seg_subnets:
                        self.nsxpolicy.segment.update(segment_id,
                                                      subnets=seg_subnets)

                # will update the router only if needed
                self._update_slaac_on_router(context, router_id,
                                             subnet, rtr_subnets, delete=True)

            else:
                # VLAN interface
                pol_subnets = []
                for rtr_subnet in net_rtr_subnets:
                    prefix_len = int(rtr_subnet['cidr'].split('/')[1])
                    pol_subnets.append(policy_defs.InterfaceSubnet(
                        ip_addresses=[rtr_subnet['gateway_ip']],
                        prefix_len=prefix_len))

                if pol_subnets:
                    # This will update segment interface
                    self.nsxpolicy.tier1.add_segment_interface(
                        router_id, segment_id,
                        segment_id, pol_subnets)
                else:
                    self.nsxpolicy.tier1.remove_segment_interface(
                        router_id, segment_id)

                if not self.service_router_has_services(
                    context.elevated(), router_id):
                    self.delete_service_router(router_id)

            # try to delete the SNAT/NO_DNAT rules of this subnet
            router_db = self._get_router(context, router_id)
            if (subnet and router_db.gw_port and router_db.enable_snat and
                subnet['ip_version'] == 4):
                self._del_subnet_snat_rule(router_id, subnet)
                self._del_subnet_no_dnat_rule(router_id, subnet)

            if subnet and subnet.get('ip_version') == 6 and router_db.gw_port:
                # if this is an ipv6 subnet and router has GW,
                # we need to remove advertisement rule
                self._update_router_advertisement_rules(
                    router_id, rtr_subnets, True)

            # update firewall rules
            self.update_router_firewall(context, router_id, router_db)

        except nsx_lib_exc.ManagerError as e:
            # If there is a failure in deleting the resource, fail the neutron
            # operation even though the neutron object was already deleted.
            # This way the user will be aware of zombie resources that may fail
            # future actions.
            # TODO(asarfaty): Handle specific errors
            msg = (_('Failed to remove router interface for network '
                     '%(id)s on NSX backend. Exception: %(e)s') %
                   {'id': network_id, 'e': e})
            raise nsx_exc.NsxPluginException(err_msg=msg)

        return info

    def _get_fip_snat_rule_id(self, fip_id):
        return 'S-' + fip_id

    def _get_fip_dnat_rule_id(self, fip_id):
        return 'D-' + fip_id

    def _get_nat_firewall_match(self):
        if cfg.CONF.nsx_p.firewall_match_internal_addr:
            return policy_constants.NAT_FIREWALL_MATCH_INTERNAL
        return policy_constants.NAT_FIREWALL_MATCH_EXTERNAL

    def _add_fip_nat_rules(self, tier1_id, fip_id, ext_ip, int_ip):
        def _do_add_fip_nat():
            firewall_match = self._get_nat_firewall_match()
            self.nsxpolicy.tier1_nat_rule.create_or_overwrite(
                'snat for fip %s' % fip_id,
                tier1_id,
                nat_rule_id=self._get_fip_snat_rule_id(fip_id),
                action=policy_constants.NAT_ACTION_SNAT,
                translated_network=ext_ip,
                source_network=int_ip,
                sequence_number=NAT_RULE_PRIORITY_FIP,
                firewall_match=firewall_match)
            self.nsxpolicy.tier1_nat_rule.create_or_overwrite(
                'dnat for fip %s' % fip_id,
                tier1_id,
                nat_rule_id=self._get_fip_dnat_rule_id(fip_id),
                action=policy_constants.NAT_ACTION_DNAT,
                translated_network=int_ip,
                destination_network=ext_ip,
                sequence_number=NAT_RULE_PRIORITY_FIP,
                firewall_match=firewall_match)

        self._run_under_transaction(_do_add_fip_nat)

    def _delete_fip_nat_rules(self, tier1_id, fip_id):
        def _do_delete_fip_nat():
            self.nsxpolicy.tier1_nat_rule.delete(
                tier1_id,
                nat_rule_id=self._get_fip_snat_rule_id(fip_id))
            self.nsxpolicy.tier1_nat_rule.delete(
                tier1_id,
                nat_rule_id=self._get_fip_dnat_rule_id(fip_id))

        self._run_under_transaction(_do_delete_fip_nat)

    def _update_lb_vip(self, port, vip_address):
        # update the load balancer virtual server's VIP with
        # floating ip, but don't add NAT rules
        device_id = port['device_id']
        if device_id.startswith(oct_const.DEVICE_ID_PREFIX):
            device_id = device_id[len(oct_const.DEVICE_ID_PREFIX):]
        tags_to_search = [{'scope': 'os-lbaas-lb-id', 'tag': device_id}]
        vs_client = self.nsxpolicy.load_balancer.virtual_server
        vs_list = self.nsxpolicy.search_by_tags(
            tags_to_search, vs_client.entry_def.resource_type()
        )['results']
        for vs in vs_list:
            vs_client.update(vs['id'], ip_address=vip_address)

    def create_floatingip(self, context, floatingip):
        # First do some validations
        fip_data = floatingip['floatingip']
        port_id = fip_data.get('port_id')
        if port_id:
            port_data = self.get_port(context, port_id)
            self._assert_on_assoc_floatingip_to_special_ports(
                fip_data, port_data)

        new_fip = self._create_floating_ip_wrapper(context, floatingip)
        router_id = new_fip['router_id']
        if not router_id:
            return new_fip

        if port_id:
            device_owner = port_data.get('device_owner')
            fip_address = new_fip['floating_ip_address']
            if (device_owner == const.DEVICE_OWNER_LOADBALANCERV2 or
                device_owner == oct_const.DEVICE_OWNER_OCTAVIA or
                device_owner == lb_const.VMWARE_LB_VIP_OWNER):
                try:
                    self._update_lb_vip(port_data, fip_address)
                except nsx_lib_exc.ManagerError:
                    with excutils.save_and_reraise_exception():
                        super(NsxPolicyPlugin, self).delete_floatingip(
                            context, new_fip['id'])
                return new_fip

        try:
            self._add_fip_nat_rules(
                router_id, new_fip['id'],
                new_fip['floating_ip_address'],
                new_fip['fixed_ip_address'])
        except nsx_lib_exc.ManagerError:
            with excutils.save_and_reraise_exception():
                self.delete_floatingip(context, new_fip['id'])

        if (port_id and not cfg.CONF.nsx_p.firewall_match_internal_addr and
            self.fwaas_callbacks):
            # Might need to update a group related to this fip
            self.fwaas_callbacks.update_segment_group(
                context, router_id, port_data['network_id'])

        return new_fip

    def delete_floatingip(self, context, fip_id):
        fip = self.get_floatingip(context, fip_id)
        router_id = fip['router_id']
        port_id = fip['port_id']
        is_lb_port = False
        if port_id:
            port_data = self.get_port(context, port_id)
            device_owner = port_data.get('device_owner')
            fixed_ip_address = fip['fixed_ip_address']
            if (device_owner == const.DEVICE_OWNER_LOADBALANCERV2 or
                device_owner == oct_const.DEVICE_OWNER_OCTAVIA or
                device_owner == lb_const.VMWARE_LB_VIP_OWNER):
                # If the port is LB VIP port, after deleting the FIP,
                # update the virtual server VIP back to fixed IP.
                is_lb_port = True
                try:
                    self._update_lb_vip(port_data, fixed_ip_address)
                except nsx_lib_exc.ManagerError as e:
                    LOG.error("Exception when updating vip ip_address"
                              "on vip_port %(port)s: %(err)s",
                              {'port': port_id, 'err': e})

        if router_id and not is_lb_port:
            self._delete_fip_nat_rules(router_id, fip_id)

        super(NsxPolicyPlugin, self).delete_floatingip(context, fip_id)

        if (port_id and not cfg.CONF.nsx_p.firewall_match_internal_addr and
            self.fwaas_callbacks):
            # Might need to update a group related to this fip
            self.fwaas_callbacks.update_segment_group(
                context, router_id, port_data['network_id'])

    def update_floatingip(self, context, fip_id, floatingip):
        fip_data = floatingip['floatingip']
        old_fip = self.get_floatingip(context, fip_id)
        old_port_id = old_fip['port_id']
        new_status = (const.FLOATINGIP_STATUS_ACTIVE
                      if fip_data.get('port_id')
                      else const.FLOATINGIP_STATUS_DOWN)

        updated_port_id = fip_data.get('port_id')
        if updated_port_id:
            updated_port_data = self.get_port(context, updated_port_id)
            self._assert_on_assoc_floatingip_to_special_ports(
                fip_data, updated_port_data)

        new_fip = super(NsxPolicyPlugin, self).update_floatingip(
            context, fip_id, floatingip)
        router_id = new_fip['router_id']
        new_port_id = new_fip['port_id']

        # Delete old configuration NAT / vip
        is_lb_port = False
        if old_port_id:
            old_port_data = self.get_port(context, old_port_id)
            old_device_owner = old_port_data['device_owner']
            old_fixed_ip = old_fip['fixed_ip_address']
            if (old_device_owner == const.DEVICE_OWNER_LOADBALANCERV2 or
                old_device_owner == oct_const.DEVICE_OWNER_OCTAVIA or
                old_device_owner == lb_const.VMWARE_LB_VIP_OWNER):
                # If the port is LB VIP port, after deleting the FIP,
                # update the virtual server VIP back to fixed IP.
                is_lb_port = True
                self._update_lb_vip(old_port_data, old_fixed_ip)

        if (not is_lb_port and old_fip['router_id'] and
            (not router_id or old_fip['router_id'] != router_id)):
            # Delete the old rules (if the router did not change - rewriting
            # the rules with _add_fip_nat_rules is enough)
            self._delete_fip_nat_rules(old_fip['router_id'], fip_id)

        # Update LB VIP if the new port is LB port
        is_lb_port = False
        if new_port_id:
            new_port_data = self.get_port(context, new_port_id)
            new_dev_own = new_port_data['device_owner']
            new_fip_address = new_fip['floating_ip_address']
            if (new_dev_own == const.DEVICE_OWNER_LOADBALANCERV2 or
                new_dev_own == oct_const.DEVICE_OWNER_OCTAVIA or
                new_dev_own == lb_const.VMWARE_LB_VIP_OWNER):
                is_lb_port = True
                self._update_lb_vip(new_port_data, new_fip_address)

        if router_id and not is_lb_port:
            self._add_fip_nat_rules(
                router_id, new_fip['id'],
                new_fip['floating_ip_address'],
                new_fip['fixed_ip_address'])

        if new_fip['status'] != new_status:
            new_fip['status'] = new_status
            self.update_floatingip_status(context, fip_id, new_status)

        return new_fip

    def disassociate_floatingips(self, context, port_id):
        fip_qry = context.session.query(l3_db_models.FloatingIP)
        fip_dbs = fip_qry.filter_by(fixed_port_id=port_id)

        for fip_db in fip_dbs:
            if not fip_db.router_id:
                continue
            if fip_db.router_id:
                # Delete the old rules
                self._delete_fip_nat_rules(fip_db.router_id, fip_db.id)
            self.update_floatingip_status(context, fip_db.id,
                                          const.FLOATINGIP_STATUS_DOWN)

        super(NsxPolicyPlugin, self).disassociate_floatingips(
            context, port_id, do_notify=False)

    def _prepare_default_rules(self):
        """Create a default group & communication map in the default domain"""
        # Run this code only on one worker at the time
        with locking.LockManager.get_lock('nsx_p_prepare_default_rules'):
            # Return if the objects were already created
            try:
                self.nsxpolicy.comm_map.get(NSX_P_GLOBAL_DOMAIN_ID,
                                            NSX_P_DEFAULT_SECTION)
                self.nsxpolicy.group.get(NSX_P_GLOBAL_DOMAIN_ID,
                                         NSX_P_DEFAULT_GROUP)
            except nsx_lib_exc.ResourceNotFound:
                LOG.info("Going to create default group & "
                         "communication map")
                exists = False
            else:
                LOG.info("Going to update default group & "
                         "communication map")
                exists = True

            # Create the group only if not exists - no need to update it
            if not exists:
                # Create the default group membership criteria to match all
                # neutron ports by scope (and no tag)
                scope_and_tag = "%s|" % (NSX_P_PORT_RESOURCE_TYPE)
                conditions = [self.nsxpolicy.group.build_condition(
                    cond_val=scope_and_tag,
                    cond_key=policy_constants.CONDITION_KEY_TAG,
                    cond_member_type=policy_constants.CONDITION_MEMBER_PORT)]
                # Create the default OpenStack group
                # (This will not fail if the group already exists)
                try:
                    self.nsxpolicy.group.create_or_overwrite_with_conditions(
                        name=NSX_P_DEFAULT_GROUP,
                        domain_id=NSX_P_GLOBAL_DOMAIN_ID,
                        group_id=NSX_P_DEFAULT_GROUP,
                        description=NSX_P_DEFAULT_GROUP_DESC,
                        conditions=conditions)
                except Exception as e:
                    msg = (_("Failed to create NSX default group: %(e)s") % {
                        'e': e})
                    raise nsx_exc.NsxPluginException(err_msg=msg)

            # create default section and rules
            # (even if already exists - may need to update rules)
            logged = cfg.CONF.nsx_p.log_security_groups_blocked_traffic
            scope = [self.nsxpolicy.group.get_path(
                NSX_P_GLOBAL_DOMAIN_ID, NSX_P_DEFAULT_GROUP)]
            rule_id = 1
            dhcp_client_rule = self.nsxpolicy.comm_map.build_entry(
                'DHCP Reply', NSX_P_GLOBAL_DOMAIN_ID,
                NSX_P_DEFAULT_SECTION,
                rule_id, sequence_number=rule_id,
                service_ids=['DHCP-Client'],
                action=policy_constants.ACTION_ALLOW,
                scope=scope,
                direction=nsxlib_consts.IN,
                logged=logged)
            rule_id += 1
            dhcp_server_rule = self.nsxpolicy.comm_map.build_entry(
                'DHCP Request', NSX_P_GLOBAL_DOMAIN_ID,
                NSX_P_DEFAULT_SECTION,
                rule_id, sequence_number=rule_id,
                service_ids=['DHCP-Server'],
                action=policy_constants.ACTION_ALLOW,
                scope=scope,
                direction=nsxlib_consts.OUT,
                logged=logged)
            rule_id += 1
            nd_rule = self.nsxpolicy.comm_map.build_entry(
                'IPv6 Neighbor Discovery', NSX_P_GLOBAL_DOMAIN_ID,
                NSX_P_DEFAULT_SECTION,
                rule_id, sequence_number=rule_id,
                service_ids=['IPv6-ICMP_Neighbor_Solicitation',
                             'IPv6-ICMP_Neighbor_Advertisement',
                             'IPv6-ICMP_Version_2_Multicast_Listener',
                             'IPv6-ICMP_Multicast_Listener_Query',
                             'IPv6-ICMP_Multicast_Listener_Done',
                             'IPv6-ICMP_Multicast_Listener_Report',
                             IPV6_RA_SERVICE],
                action=policy_constants.ACTION_ALLOW,
                ip_protocol=nsxlib_consts.IPV6,
                scope=scope,
                direction=nsxlib_consts.IN_OUT,
                logged=logged)
            rule_id += 1
            dhcpv6_server_rule = self.nsxpolicy.comm_map.build_entry(
                'DHCPv6 Request', NSX_P_GLOBAL_DOMAIN_ID,
                NSX_P_DEFAULT_SECTION,
                rule_id, sequence_number=rule_id,
                service_ids=['DHCPv6_Server'],
                action=policy_constants.ACTION_ALLOW,
                ip_protocol=nsxlib_consts.IPV6,
                scope=scope,
                direction=nsxlib_consts.OUT,
                logged=logged)
            rule_id += 1
            dhcpv6_client_rule = self.nsxpolicy.comm_map.build_entry(
                'DHCPv6 Reply', NSX_P_GLOBAL_DOMAIN_ID,
                NSX_P_DEFAULT_SECTION,
                rule_id, sequence_number=rule_id,
                service_ids=['DHCPv6_Client'],
                action=policy_constants.ACTION_ALLOW,
                ip_protocol=nsxlib_consts.IPV6,
                scope=scope,
                direction=nsxlib_consts.IN,
                logged=logged)
            rule_id += 1
            block_rule = self.nsxpolicy.comm_map.build_entry(
                'Block All', NSX_P_GLOBAL_DOMAIN_ID,
                NSX_P_DEFAULT_SECTION,
                rule_id, sequence_number=rule_id, service_ids=None,
                action=policy_constants.ACTION_DENY,
                scope=scope,
                direction=nsxlib_consts.IN_OUT,
                logged=logged)
            rules = [dhcp_client_rule, dhcp_server_rule, dhcpv6_client_rule,
                     dhcpv6_server_rule, nd_rule, block_rule]
            try:
                # This will not fail if the map already exists
                self.nsxpolicy.comm_map.create_with_entries(
                    name=NSX_P_DEFAULT_SECTION,
                    domain_id=NSX_P_GLOBAL_DOMAIN_ID,
                    map_id=NSX_P_DEFAULT_SECTION,
                    description=NSX_P_DEFAULT_SECTION_DESC,
                    category=NSX_P_DEFAULT_SECTION_CATEGORY,
                    entries=rules)
            except Exception as e:
                msg = (_("Failed to create NSX default communication map: "
                         "%(e)s") % {'e': e})
                raise nsx_exc.NsxPluginException(err_msg=msg)

    def _prepare_exclude_list_group(self):
        try:
            self.nsxpolicy.group.get(NSX_P_GLOBAL_DOMAIN_ID,
                                     NSX_P_EXCLUDE_LIST_GROUP)
        except nsx_lib_exc.ResourceNotFound:
            LOG.info("Going to create exclude list group")
        else:
            LOG.debug("Verified exclude list group already exists")
            return

        # Create the group membership criteria to match excluded neutron
        # ports by scope and tag
        scope_and_tag = "%s|%s" % (v3_utils.PORT_SG_SCOPE,
                                   NSX_P_EXCLUDE_LIST_TAG)
        conditions = [self.nsxpolicy.group.build_condition(
            cond_val=scope_and_tag,
            cond_key=policy_constants.CONDITION_KEY_TAG,
            cond_member_type=policy_constants.CONDITION_MEMBER_PORT)]
        # Create the exclude list group
        # (This will not fail if the group already exists)
        try:
            self.nsxpolicy.group.create_or_overwrite_with_conditions(
                name=NSX_P_EXCLUDE_LIST_GROUP,
                domain_id=NSX_P_GLOBAL_DOMAIN_ID,
                group_id=NSX_P_EXCLUDE_LIST_GROUP,
                conditions=conditions)

        except Exception as e:
            msg = (_("Failed to create NSX exclude list group: %(e)s") % {
                'e': e})
            raise nsx_exc.NsxPluginException(err_msg=msg)

    def _add_exclude_list_group(self):
        member = self.nsxpolicy.group.get_path(
            domain_id=NSX_P_GLOBAL_DOMAIN_ID,
            group_id=NSX_P_EXCLUDE_LIST_GROUP)

        exclude_list = self.nsxpolicy.exclude_list.get()
        if member in exclude_list['members']:
            LOG.debug("Verified that group %s was already added to the "
                      "NSX exclude list", member)
            return

        LOG.info("Going to add group %s to the NSX exclude list", member)
        members = exclude_list['members']
        members.append(member)
        try:
            self.nsxpolicy.exclude_list.create_or_overwrite(members=members)
        except Exception as e:
            msg = (_("Failed to add group to the NSX exclude list: %(e)s") % {
                'e': e})
            raise nsx_exc.NsxPluginException(err_msg=msg)

    def _prepare_exclude_list(self):
        """Create exclude list for ports without port security

        Create a group for excluded ports and add it to the NSX exclude list
        """
        # Run this code only on one worker at the time
        with locking.LockManager.get_lock('nsx_p_prepare_exclude_list'):
            self._prepare_exclude_list_group()
            self._add_exclude_list_group()

    def _create_security_group_backend_resources(self, context, secgroup,
                                                 entries):
        """Create communication map (=section) and group (=NS group)

        Both will have the security group id as their NSX id.
        """
        sg_id = secgroup['id']
        tags = self.nsxpolicy.build_v3_tags_payload(
            secgroup, resource_type='os-neutron-secg-id',
            project_name=secgroup.get('tenant_id'))
        nsx_name = utils.get_name_and_uuid(secgroup['name'] or 'securitygroup',
                                           sg_id)
        # Create the groups membership criteria for ports by scope & tag
        scope_and_tag = "%s|%s" % (NSX_P_SECURITY_GROUP_TAG, sg_id)
        condition = self.nsxpolicy.group.build_condition(
            cond_val=scope_and_tag,
            cond_key=policy_constants.CONDITION_KEY_TAG,
            cond_member_type=policy_constants.CONDITION_MEMBER_PORT)

        category = NSX_P_REGULAR_SECTION_CATEGORY
        if secgroup.get(provider_sg.PROVIDER) is True:
            category = NSX_P_PROVIDER_SECTION_CATEGORY

        try:
            def _do_create_sg():
                # Create the group
                self.nsxpolicy.group.create_or_overwrite_with_conditions(
                    nsx_name, NSX_P_GLOBAL_DOMAIN_ID, group_id=sg_id,
                    description=secgroup.get('description'),
                    conditions=[condition], tags=tags)

                # create the communication map (=section) and entries (=rules)
                self.nsxpolicy.comm_map.create_or_overwrite_map_only(
                    nsx_name, NSX_P_GLOBAL_DOMAIN_ID, map_id=sg_id,
                    description=secgroup.get('description'),
                    tags=tags, category=category)
                for entry in entries:
                    self.nsxpolicy.comm_map.create_entry_from_def(entry)

            self._run_under_transaction(_do_create_sg)
        except Exception as e:
            msg = (_("Failed to create NSX resources for SG %(sg)s: "
                     "%(e)s") % {'sg': sg_id, 'e': e})
            raise nsx_exc.NsxPluginException(err_msg=msg)

    def _get_rule_ip_protocol(self, sg_rule):
        ethertype = sg_rule.get('ethertype')
        if ethertype == const.IPv4:
            return nsxlib_consts.IPV4
        if ethertype == const.IPv6:
            return nsxlib_consts.IPV6

        return nsxlib_consts.IPV4_IPV6

    def _get_rule_service_id(self, context, sg_rule, tags):
        """Return the NSX Policy service id matching the SG rule"""
        srv_id = None
        l4_protocol = nsxlib_utils.get_l4_protocol_name(sg_rule['protocol'])
        srv_name = 'Service for OS rule %s' % sg_rule['id']

        if l4_protocol in [nsxlib_consts.TCP, nsxlib_consts.UDP]:
            # If port_range_min is not specified then we assume all ports are
            # matched, relying on neutron to perform validation.
            if sg_rule['port_range_min'] is None:
                destination_ports = []
            elif sg_rule['port_range_min'] != sg_rule['port_range_max']:
                # NSX API requires a non-empty range (e.g - '22-23')
                destination_ports = ['%(port_range_min)s-%(port_range_max)s'
                                     % sg_rule]
            else:
                destination_ports = ['%(port_range_min)s' % sg_rule]

            srv_id = self.nsxpolicy.service.create_or_overwrite(
                srv_name, service_id=sg_rule['id'],
                description=sg_rule.get('description'),
                protocol=l4_protocol,
                dest_ports=destination_ports,
                tags=tags)
        elif l4_protocol in [nsxlib_consts.ICMPV4, nsxlib_consts.ICMPV6]:
            # Validate the icmp type & code
            version = 4 if l4_protocol == nsxlib_consts.ICMPV4 else 6
            icmp_type = sg_rule['port_range_min']
            icmp_code = sg_rule['port_range_max']
            nsxlib_utils.validate_icmp_params(
                icmp_type, icmp_code, icmp_version=version, strict=True)

            srv_id = self.nsxpolicy.icmp_service.create_or_overwrite(
                srv_name, service_id=sg_rule['id'],
                description=sg_rule.get('description'),
                version=version,
                icmp_type=icmp_type,
                icmp_code=icmp_code,
                tags=tags)
        elif l4_protocol:
            srv_id = self.nsxpolicy.ip_protocol_service.create_or_overwrite(
                srv_name, service_id=sg_rule['id'],
                description=sg_rule.get('description'),
                protocol_number=l4_protocol,
                tags=tags)

        return srv_id

    def _get_sg_rule_remote_ip_group_id(self, sg_rule):
        return '%s_remote_group' % sg_rule['id']

    def _get_sg_rule_local_ip_group_id(self, sg_rule):
        return '%s_local_group' % sg_rule['id']

    def _create_security_group_backend_rule(self, context, map_id,
                                            sg_rule, secgroup_logging,
                                            is_provider_sg=False,
                                            create_related_resource=True):
        """Create backend resources for a DFW rule

        All rule resources (service, groups) will be created
        The rule itself will be created if create_rule=True.
        Else this method will return the rule entry structure for future use.
        """
        # The id of the map and group is the same as the security group id
        this_group_id = map_id
        # There is no rule name in neutron. Using ID instead
        nsx_name = sg_rule['id']
        direction = (nsxlib_consts.IN if sg_rule.get('direction') == 'ingress'
                     else nsxlib_consts.OUT)
        self._fix_sg_rule_dict_ips(sg_rule)
        source = None
        destination = this_group_id

        tags = self.nsxpolicy.build_v3_tags_payload(
            sg_rule, resource_type='os-neutron-secgr-id',
            project_name=sg_rule.get('tenant_id'))

        if sg_rule.get('remote_group_id'):
            # This is the ID of a security group that already exists,
            # so it should be known to the policy manager
            source = sg_rule.get('remote_group_id')
        elif sg_rule.get('remote_ip_prefix'):
            # Create a group for the remote IPs
            remote_ip = sg_rule['remote_ip_prefix']
            remote_group_id = self._get_sg_rule_remote_ip_group_id(sg_rule)
            if create_related_resource:
                expr = self.nsxpolicy.group.build_ip_address_expression(
                    [remote_ip])
                self.nsxpolicy.group.create_or_overwrite_with_conditions(
                    remote_group_id, NSX_P_GLOBAL_DOMAIN_ID,
                    group_id=remote_group_id,
                    description='%s for OS rule %s' % (remote_ip,
                                                       sg_rule['id']),
                    conditions=[expr], tags=tags)
            source = remote_group_id
        if sg_rule.get(sg_prefix.LOCAL_IP_PREFIX):
            # Create a group for the local ips
            local_ip = sg_rule[sg_prefix.LOCAL_IP_PREFIX]
            local_group_id = self._get_sg_rule_local_ip_group_id(sg_rule)
            if create_related_resource:
                expr = self.nsxpolicy.group.build_ip_address_expression(
                    [local_ip])
                self.nsxpolicy.group.create_or_overwrite_with_conditions(
                    local_group_id, NSX_P_GLOBAL_DOMAIN_ID,
                    group_id=local_group_id,
                    description='%s for OS rule %s' % (local_ip,
                                                       sg_rule['id']),
                    conditions=[expr], tags=tags)
            destination = local_group_id

        if direction == nsxlib_consts.OUT:
            # Swap source and destination
            source, destination = destination, source

        if create_related_resource:
            service = self._get_rule_service_id(context, sg_rule, tags)
        else:
            if nsxlib_utils.get_l4_protocol_name(sg_rule['protocol']):
                service = sg_rule['id']
            else:
                service = None
        ip_protocol = self._get_rule_ip_protocol(sg_rule)
        logging = (cfg.CONF.nsx_p.log_security_groups_allowed_traffic or
                   secgroup_logging)
        scope = [self.nsxpolicy.group.get_path(NSX_P_GLOBAL_DOMAIN_ID,
                                               this_group_id)]
        action = (policy_constants.ACTION_DENY if is_provider_sg
                  else policy_constants.ACTION_ALLOW)
        # Just return the rule entry without creating it
        rule_entry = self.nsxpolicy.comm_map.build_entry(
            nsx_name, NSX_P_GLOBAL_DOMAIN_ID,
            map_id, entry_id=sg_rule['id'],
            description=sg_rule.get('description'),
            service_ids=[service] if service else None,
            ip_protocol=ip_protocol,
            action=action,
            source_groups=[source] if source else None,
            dest_groups=[destination] if destination else None,
            scope=scope,
            tag=sg_rule.get('project_id'),
            direction=direction, logged=logging)
        return rule_entry

    def create_security_group(self, context, security_group, default_sg=False):
        secgroup = security_group['security_group']
        # Make sure the ID is initialized, as it is used for the backend
        # objects too
        secgroup['id'] = secgroup.get('id') or uuidutils.generate_uuid()

        project_id = secgroup['tenant_id']
        if not default_sg:
            self._ensure_default_security_group(context, project_id)

        # create the Neutron SG
        with db_api.CONTEXT_WRITER.using(context):
            if secgroup.get(provider_sg.PROVIDER) is True:
                secgroup_db = self.create_provider_security_group(
                    context, security_group)
            else:
                secgroup_db = (
                    super(NsxPolicyPlugin, self).create_security_group(
                        context, security_group, default_sg))

            self._process_security_group_properties_create(context,
                                                           secgroup_db,
                                                           secgroup,
                                                           default_sg)

            if cfg.CONF.api_replay_mode:
                self._handle_api_replay_default_sg(context, secgroup_db)

        if cfg.CONF.api_replay_mode:
            # Do not create backend resources for SG with api_replay
            return secgroup_db

        try:
            # create all the rule entries
            sg_rules = secgroup_db['security_group_rules']
            secgroup_logging = secgroup.get(sg_logging.LOGGING, False)
            backend_rules = []
            # Create all the rules resources in a single transaction
            for sg_rule in sg_rules:
                rule_entry = self._create_security_group_backend_rule(
                    context, secgroup_db['id'], sg_rule,
                    secgroup_logging)
                backend_rules.append(rule_entry)
            # Create Group & communication map on the NSX
            self._create_security_group_backend_resources(
                context, secgroup, backend_rules)

        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.exception("Failed to create backend SG rules "
                              "for security-group %(name)s (%(id)s), "
                              "rolling back changes. Error: %(e)s",
                              {'name': secgroup_db['name'],
                               'id': secgroup_db['id'],
                               'e': e})
                # rollback SG creation (which will also delete the backend
                # objects)
                super(NsxPolicyPlugin, self).delete_security_group(
                    context, secgroup['id'])

        return secgroup_db

    def update_security_group(self, context, sg_id, security_group):
        self._prevent_non_admin_edit_provider_sg(context, sg_id)
        sg_data = security_group['security_group']

        # update the neutron security group
        with db_api.CONTEXT_WRITER.using(context):
            secgroup_res = super(NsxPolicyPlugin, self).update_security_group(
                context, sg_id, security_group)
            self._process_security_group_properties_update(
                context, secgroup_res, sg_data)

        domain_id = NSX_P_GLOBAL_DOMAIN_ID
        # Update the name and description on NSX backend
        if 'name' in sg_data or 'description' in sg_data:
            nsx_name = utils.get_name_and_uuid(
                secgroup_res['name'] or 'securitygroup', sg_id)
            try:
                self.nsxpolicy.group.update(
                    domain_id, sg_id,
                    name=nsx_name,
                    description=secgroup_res.get('description', ''))
                self.nsxpolicy.comm_map.update(
                    domain_id, sg_id,
                    name=nsx_name,
                    description=secgroup_res.get('description', ''))
            except Exception as e:
                LOG.warning("Failed to update SG %s NSX resources: %s",
                            sg_id, e)
                # Go on with the update anyway (it's just the name & desc)

        # If the logging of the SG changed - update the backend rules
        if sg_logging.LOGGING in sg_data:
            logged = (sg_data[sg_logging.LOGGING] or
                      cfg.CONF.nsx_p.log_security_groups_allowed_traffic)
            self.nsxpolicy.comm_map.update_entries_logged(domain_id, sg_id,
                                                          logged)

        return secgroup_res

    def delete_security_group(self, context, sg_id):
        self._prevent_non_admin_edit_provider_sg(context, sg_id)
        sg = self.get_security_group(context, sg_id)

        super(NsxPolicyPlugin, self).delete_security_group(context, sg_id)

        domain_id = NSX_P_GLOBAL_DOMAIN_ID
        try:
            self.nsxpolicy.comm_map.delete(domain_id, sg_id)
            self.nsxpolicy.group.delete(domain_id, sg_id)
            for rule in sg['security_group_rules']:
                self._delete_security_group_rule_backend_resources(
                    context, rule)
        except nsx_lib_exc.ResourceNotFound:
            # If the resource was not found on the backend do not worry about
            # it. The conditions has already been logged, so there is no need
            # to do further logging
            pass
        except nsx_lib_exc.ManagerError as e:
            # If there is a failure in deleting the resource, fail the neutron
            # operation even though the neutron object was already deleted.
            # This way the user will be aware of zombie resources that may fail
            # future actions.
            msg = (_("Backend security group objects deletion for neutron "
                     "security group %(id)s failed. The object was however "
                     "removed from the Neutron database: %(e)s") %
                   {'id': sg_id, 'e': e})
            raise nsx_exc.NsxPluginException(err_msg=msg)

    def create_security_group_rule(self, context, security_group_rule):
        bulk_rule = {'security_group_rules': [security_group_rule]}
        return self.create_security_group_rule_bulk(context, bulk_rule)[0]

    def create_security_group_rule_bulk(self, context, security_group_rules):
        sg_rules = security_group_rules['security_group_rules']
        for r in sg_rules:
            self._check_local_ip_prefix(context, r['security_group_rule'])

        # Tenant & security group are the same for all rules in the bulk
        example_rule = sg_rules[0]['security_group_rule']
        sg_id = example_rule['security_group_id']
        sg = self.get_security_group(context, sg_id)
        self._prevent_non_admin_edit_provider_sg(context, sg_id)

        with db_api.CONTEXT_WRITER.using(context):
            rules_db = (super(NsxPolicyPlugin,
                              self).create_security_group_rule_bulk_native(
                                  context, security_group_rules))
            for i, r in enumerate(sg_rules):
                self._process_security_group_rule_properties(
                    context, rules_db[i], r['security_group_rule'])

        if cfg.CONF.api_replay_mode:
            # Do not create backend resources for SG with api_replay
            return rules_db

        is_provider_sg = sg.get(provider_sg.PROVIDER)
        secgroup_logging = self._is_security_group_logged(context, sg_id)
        category = (NSX_P_PROVIDER_SECTION_CATEGORY if is_provider_sg
                    else NSX_P_REGULAR_SECTION_CATEGORY)
        # Create the NSX backend rules in a single transaction

        def _do_update_rules():
            # Build new rules and relevant objects
            backend_rules = []
            for rule_data in rules_db:
                rule_entry = self._create_security_group_backend_rule(
                    context, sg_id, rule_data, secgroup_logging,
                    is_provider_sg=is_provider_sg)
                backend_rules.append(rule_entry)
            # Add the old rules
            for rule in sg['security_group_rules']:
                rule_entry = self._create_security_group_backend_rule(
                    context, sg_id, rule, secgroup_logging,
                    is_provider_sg=is_provider_sg,
                    create_related_resource=True)
                backend_rules.append(rule_entry)

            # Update the policy with all the rules.
            self.nsxpolicy.comm_map.update_with_entries(
                NSX_P_GLOBAL_DOMAIN_ID, sg_id, entries=backend_rules,
                category=category, use_child_rules=False)

        self._run_under_transaction(_do_update_rules)

        return rules_db

    def _delete_security_group_rule_backend_resources(
        self, context, rule_db):
        rule_id = rule_db['id']
        # try to delete the service of this rule, if exists
        if rule_db['protocol']:
            try:
                self.nsxpolicy.service.delete(rule_id)
            except nsx_lib_exc.ResourceNotFound:
                pass

        # Try to delete the remote ip prefix group, if exists
        if rule_db['remote_ip_prefix']:
            try:
                remote_group_id = self._get_sg_rule_remote_ip_group_id(rule_db)
                self.nsxpolicy.group.delete(NSX_P_GLOBAL_DOMAIN_ID,
                                            remote_group_id)
            except nsx_lib_exc.ResourceNotFound:
                pass

        # Try to delete the local ip prefix group, if exists
        if self._get_security_group_rule_local_ip(context, rule_id):
            try:
                local_group_id = self._get_sg_rule_local_ip_group_id(rule_db)
                self.nsxpolicy.group.delete(NSX_P_GLOBAL_DOMAIN_ID,
                                            local_group_id)
            except nsx_lib_exc.ResourceNotFound:
                pass

    def delete_security_group_rule(self, context, rule_id):
        rule_db = self._get_security_group_rule(context, rule_id)
        sg_id = rule_db['security_group_id']
        self._prevent_non_admin_edit_provider_sg(context, sg_id)

        # Delete the rule itself
        try:
            self.nsxpolicy.comm_map.delete_entry(
                policy_constants.DEFAULT_DOMAIN, sg_id, rule_id)
            self._delete_security_group_rule_backend_resources(
                context, rule_db)
        except nsx_lib_exc.ResourceNotFound:
            # Go on with the deletion anyway
            pass
        except nsx_lib_exc.ManagerError as e:
            msg = (_("Backend security group rule deletion for neutron "
                     "rule %(id)s failed: %(e)s") % {'id': rule_id, 'e': e})
            nsx_exc.NsxPluginException(err_msg=msg)

        super(NsxPolicyPlugin, self).delete_security_group_rule(
            context, rule_id)

    def _is_overlay_network(self, context, network_id):
        """Return True if this is an overlay network

        1. No binding ("normal" overlay networks will have no binding)
        2. Geneve network
        3. nsx network where the backend network is connected to an overlay TZ
        """
        bindings = nsx_db.get_network_bindings(context.session, network_id)
        # With NSX plugin, "normal" overlay networks will have no binding
        if not bindings:
            # using the default/AZ overlay_tz
            return True

        binding = bindings[0]
        if binding.binding_type == utils.NsxV3NetworkTypes.GENEVE:
            return True
        if binding.binding_type == utils.NsxV3NetworkTypes.NSX_NETWORK:
            # check the backend network
            segment = self.nsxpolicy.segment.get(binding.phy_uuid)
            tz = self._get_nsx_net_tz_id(segment)
            if tz:
                # This call is cached on the nsxlib side
                type = self.nsxpolicy.transport_zone.get_transport_type(
                    tz)
                return type == nsxlib_consts.TRANSPORT_TYPE_OVERLAY

        return False

    def _is_ens_tz(self, tz_id):
        # This call is cached on the nsxlib side
        mode = self.nsxpolicy.transport_zone.get_host_switch_mode(tz_id)
        return mode == nsxlib_consts.HOST_SWITCH_MODE_ENS

    def _has_native_dhcp_metadata(self):
        return True

    def _get_tier0_uplink_cidrs(self, tier0_id):
        # return a list of tier0 uplink ip/prefix addresses
        return self.nsxpolicy.tier0.get_uplink_cidrs(tier0_id)

    def _get_neutron_net_ids_by_nsx_id(self, context, lswitch_id):
        """Translate nsx ls IDs given by Nova to neutron network ids.

        Since there is no DB mapping for this, the plugin will query the NSX
        for this, and cache the results.
        """
        if lswitch_id not in NET_NSX_2_NEUTRON_ID_CACHE:
            segments_path = self.nsxpolicy.search_resource_by_realized_id(
                lswitch_id, "RealizedLogicalSwitch")
            if not segments_path or len(segments_path) != 1:
                LOG.warning("Could not find policy segment with realized id "
                            "%s", lswitch_id)
                return []
            neutron_id = p_utils.path_to_id(segments_path[0])
            if neutron_id:
                # Cache the result
                NET_NSX_2_NEUTRON_ID_CACHE[lswitch_id] = neutron_id
                NET_NEUTRON_2_NSX_ID_CACHE[neutron_id] = lswitch_id

        if NET_NSX_2_NEUTRON_ID_CACHE.get(lswitch_id):
            return [NET_NSX_2_NEUTRON_ID_CACHE[lswitch_id]]
        return []

    def _get_net_tz(self, context, net_id):
        bindings = nsx_db.get_network_bindings(context.session, net_id)
        if bindings:
            bind_type = bindings[0].binding_type
            if bind_type == utils.NsxV3NetworkTypes.NSX_NETWORK:
                # If it is an NSX network, return the TZ of the backend segment
                segment_id = bindings[0].phy_uuid
                return self.nsxpolicy.segment.get_transport_zone_id(segment_id)
            if bind_type == utils.NetworkTypes.L3_EXT:
                # External network has tier0 as phy_uuid
                return
            return bindings[0].phy_uuid
        # Get the default one for the network AZ
        az = self.get_network_az_by_net_id(context, net_id)
        return az._default_overlay_tz_uuid

    def _validate_router_tz(self, context, tier0_uuid, subnets):
        # make sure the related GW (Tier0 router) belongs to the same TZ
        # as the subnets attached to the Tier1 router
        if not subnets or not tier0_uuid:
            return
        tier0_tzs = self.nsxpolicy.tier0.get_transport_zones(tier0_uuid)
        if not tier0_tzs:
            return
        for sub in subnets:
            tz_uuid = self._get_net_tz(context, sub['network_id'])
            if tz_uuid not in tier0_tzs:
                msg = (_("Tier0 router %(rtr)s transport zone should match "
                         "transport zone %(tz)s of the network %(net)s") % {
                    'rtr': tier0_uuid,
                    'tz': tz_uuid,
                    'net': sub['network_id']})
                raise n_exc.InvalidInput(error_message=msg)

    def _get_net_dhcp_relay(self, context, net_id):
        # No dhcp relay support yet
        return None

    def update_router_firewall(self, context, router_id, router_db=None,
                               from_fw=False):
        """Rewrite all the rules in the router edge firewall

        This method should be called on FWaaS v2 updates, and on router
        interfaces changes.
        When FWaaS is disabled, there is no need to update the NSX router FW,
        as the default rule is allow-all.
        """
        if (self.fwaas_callbacks and
            self.fwaas_callbacks.fwaas_enabled):

            if not router_db:
                router_db = self._get_router(context, router_id)

            # find all the relevant ports of the router for FWaaS v2
            # TODO(asarfaty): Add vm ports as well
            ports = self._get_router_interfaces(context, router_id)

            # let the fwaas callbacks update the router FW
            return self.fwaas_callbacks.update_router_firewall(
                context, router_id, router_db, ports, called_from_fw=from_fw)

    def update_port_nsx_tags(self, context, port_id, tags, is_delete=False):
        """Update backend NSX segment port with tags from the tagging plugin"""
        # Make sure it is a backend port
        ctx = n_context.get_admin_context()
        port_data = self.get_port(ctx, port_id)
        if not self._is_backend_port(ctx, port_data):
            LOG.info("Ignoring tags on port %s: this port has no backend "
                     "NSX logical port", port_id)
            return

        # Get the current tags on this port
        segment_id = self._get_network_nsx_segment_id(
            ctx, port_data['network_id'])
        lport = self.nsxpolicy.segment_port.get(segment_id, port_id)
        port_tags = lport.get('tags')
        orig_len = len(port_tags)

        # Update and validate the list of tags
        extra_tags = self._translate_external_tags(tags, port_id)
        if is_delete:
            port_tags = [tag for tag in port_tags if tag not in extra_tags]
        else:
            port_tags.extend(
                [tag for tag in extra_tags if tag not in port_tags])
            if len(port_tags) > nsxlib_utils.MAX_TAGS:
                LOG.warning("Cannot add external tags to port %s: "
                            "too many tags", port_id)

        # Update the NSX port
        if len(port_tags) != orig_len:
            self.nsxpolicy.segment_port.update(
                segment_id, port_id, tags=port_tags)

    def get_extra_fw_rules(self, context, router_id, port_id):
        """Return firewall rules that should be added to the router firewall

        This method should return a list of allow firewall rules that are
        required in order to enable different plugin features with north/south
        traffic.
        The returned rules will be added after the FWaaS rules, and before the
        default drop rule.
        Only rules relevant for port_id router interface port should be
        returned, and the rules should be ingress/egress
        (but not both) and include the source/dest nsx logical port.
        """
        extra_rules = []

        # VPN rules:
        vpn_plugin = directory.get_plugin(plugin_const.VPN)
        if vpn_plugin:
            vpn_driver = vpn_plugin.drivers[vpn_plugin.default_provider]
            vpn_rules = (
                vpn_driver._generate_ipsecvpn_firewall_rules(
                    self.plugin_type(), context, router_id=router_id))
            if vpn_rules:
                extra_rules.extend(vpn_rules)

        return extra_rules

    def _validate_net_mdproxy_tz(self, az, tz_uuid, mdproxy_uuid):
        """Validate that the network TZ matches the mdproxy edge cluster"""
        if not self.nsxlib:
            # No passthrough api support
            return True

        if az.use_policy_md:
            # Policy obj
            md_ec_path = self.nsxpolicy.md_proxy.get(
                mdproxy_uuid).get('edge_cluster_path')
            md_ec = p_utils.path_to_id(md_ec_path)
        else:
            # MP obj
            md_ec = self.nsxlib.native_md_proxy.get(
                mdproxy_uuid).get('edge_cluster_id')

        try:
            ec_tzs = plugin_utils.get_edge_cluster_tzs(
                self.nsxpolicy, self.nsxlib, md_ec)
        except nsx_lib_exc.ResourceNotFound as e:
            # Do not fail neutron action init if this code fails
            LOG.warning("Failed to get edge cluster %s transport zones: %s",
                        md_ec, e)
            return True

        if tz_uuid not in ec_tzs:
            return False
        return True

    def _support_address_pairs_ipv4_cidr(self):
        return self.nsxpolicy.feature_supported(
            nsxlib_consts.FEATURE_SPOOFGUARD_CIDR)
