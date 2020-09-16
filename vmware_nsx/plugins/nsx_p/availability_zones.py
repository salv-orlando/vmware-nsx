# Copyright 2017 VMware, Inc.
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

from oslo_config import cfg
from oslo_log import log

from vmware_nsx.common import availability_zones as common_az
from vmware_nsx.common import config
from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.plugins.common_v3 import availability_zones as v3_az
from vmware_nsx.plugins.nsx_p import utils
from vmware_nsxlib.v3 import exceptions as nsx_lib_exc
from vmware_nsxlib.v3 import nsx_constants
from vmware_nsxlib.v3.policy import utils as p_utils

LOG = log.getLogger(__name__)

DEFAULT_NAME = common_az.DEFAULT_NAME + 'p'


class NsxPAvailabilityZone(v3_az.NsxV3AvailabilityZone):

    def get_az_opts(self):
        return config.get_nsxp_az_opts(self.name)

    def init_defaults(self):
        # use the default configuration
        self.metadata_proxy = cfg.CONF.nsx_p.metadata_proxy
        self.dhcp_profile = cfg.CONF.nsx_p.dhcp_profile
        self.native_metadata_route = cfg.CONF.nsx_p.native_metadata_route
        self.default_overlay_tz = cfg.CONF.nsx_p.default_overlay_tz
        self.default_vlan_tz = cfg.CONF.nsx_p.default_vlan_tz
        self.default_tier0_router = cfg.CONF.nsx_p.default_tier0_router
        self.dns_domain = cfg.CONF.nsx_p.dns_domain
        self.nameservers = cfg.CONF.nsx_p.nameservers
        self.edge_cluster = cfg.CONF.nsx_p.edge_cluster

    def _init_default_resource(self, nsxpolicy, resource_api, config_name,
                               filter_list_results=None,
                               auto_config=False,
                               is_mandatory=True,
                               search_scope=None):
        # NOTE(annak): we may need to generalize this for API calls
        # requiring path ids
        name_or_id = getattr(self, config_name)
        if not name_or_id:
            if auto_config:
                # If the field not specified, the system will auto-configure
                # in case only single resource is present
                resources = resource_api.list()
                if filter_list_results:
                    resources = filter_list_results(resources)
                if len(resources) == 1:
                    return resources[0]['id']

            if is_mandatory:
                if self.is_default():
                    raise cfg.RequiredOptError(config_name,
                                               group=cfg.OptGroup('nsx_p'))
                msg = (_("No %(res)s provided for availability "
                         "zone %(az)s") % {
                    'res': config_name,
                    'az': self.name})
                raise nsx_exc.NsxPluginException(err_msg=msg)
            return None

        try:
            # Check if the configured value is the ID
            resource_api.get(name_or_id, silent=True)
            return name_or_id
        except nsx_lib_exc.ResourceNotFound:
            # Search by tags
            if search_scope:
                resource_type = resource_api.entry_def.resource_type()
                resource_id = nsxpolicy.get_id_by_resource_and_tag(
                    resource_type,
                    search_scope,
                    name_or_id)
                if resource_id:
                    return resource_id

            # Check if the configured value is the name
            resource = resource_api.get_by_name(name_or_id)
            if resource:
                return resource['id']

            # Resource not found
            if self.is_default():
                raise cfg.RequiredOptError(config_name,
                                           group=cfg.OptGroup('nsx_p'))
            msg = (_("Could not find %(res)s %(id)s for availability "
                     "zone %(az)s") % {
                'res': config_name,
                'id': name_or_id,
                'az': self.name})
            raise nsx_exc.NsxPluginException(err_msg=msg)

    def translate_configured_names_to_uuids(self, nsxpolicy, nsxlib=None,
                                            search_scope=None):
        super(NsxPAvailabilityZone, self).translate_configured_names_to_uuids(
            nsxpolicy)

        self._default_overlay_tz_uuid = self._init_default_resource(
            nsxpolicy, nsxpolicy.transport_zone, 'default_overlay_tz',
            auto_config=True, is_mandatory=True,
            filter_list_results=lambda tzs: [
                tz for tz in tzs if tz['tz_type'].startswith('OVERLAY')],
            search_scope=search_scope)

        self._default_vlan_tz_uuid = self._init_default_resource(
            nsxpolicy, nsxpolicy.transport_zone, 'default_vlan_tz',
            auto_config=True, is_mandatory=False,
            filter_list_results=lambda tzs: [
                tz for tz in tzs if tz['tz_type'].startswith('VLAN')],
            search_scope=search_scope)

        self._default_tier0_router = self._init_default_resource(
            nsxpolicy, nsxpolicy.tier0, 'default_tier0_router',
            auto_config=True, is_mandatory=True,
            search_scope=search_scope)

        self._edge_cluster_uuid = self._init_default_resource(
            nsxpolicy, nsxpolicy.edge_cluster, 'edge_cluster',
            auto_config=False, is_mandatory=False,
            search_scope=search_scope)

        # Init dhcp config from policy or MP
        self.use_policy_dhcp = False
        if (nsxpolicy.feature_supported(
                nsx_constants.FEATURE_NSX_POLICY_DHCP)):
            try:
                self._policy_dhcp_server_config = self._init_default_resource(
                    nsxpolicy, nsxpolicy.dhcp_server_config, 'dhcp_profile',
                    auto_config=False, is_mandatory=False,
                    search_scope=search_scope)
                if self._policy_dhcp_server_config:
                    self.use_policy_dhcp = True
            except Exception:
                # Not found. try as MP profile
                pass
        self._native_dhcp_profile_uuid = None
        if not self.use_policy_dhcp and nsxlib:
            self._translate_dhcp_profile(nsxlib, search_scope=search_scope)

        self.use_policy_md = False
        if (nsxpolicy.feature_supported(
                nsx_constants.FEATURE_NSX_POLICY_MDPROXY)):
            # Try to initialize md-proxy from the policy
            try:
                self._native_md_proxy_uuid = self._init_default_resource(
                    nsxpolicy, nsxpolicy.md_proxy, 'metadata_proxy',
                    auto_config=True, is_mandatory=True,
                    search_scope=search_scope)
                LOG.info("NSX-P az using policy MD proxy: %s",
                    self._native_md_proxy_uuid)
                self.use_policy_md = True
            except Exception:
                LOG.info("NSX-P az could not use policy MD proxy. Using MP "
                         "one instead")

        if not self.use_policy_md:
            # Try to initialize md-proxy from the MP
            if nsxlib:
                self._translate_metadata_proxy(
                    nsxlib, search_scope=search_scope)
                LOG.info("NSX-P az using MP MD proxy: %s",
                    self._native_md_proxy_uuid)
            else:
                self._native_md_proxy_uuid = None

    def _validate_tz(self, nsxpolicy, nsxlib, obj_type, obj_id, ec_uuid):
        try:
            obj_tzs = utils.get_edge_cluster_tzs(nsxpolicy, nsxlib, ec_uuid)
        except nsx_lib_exc.ResourceNotFound as e:
            # Do not fail plugin init if this code fails
            LOG.warning("Failed to get edge cluster %s transport zones: %s",
                        ec_uuid, e)
            return

        if self._default_overlay_tz_uuid not in obj_tzs:
            msg = (_("%(type)s %(id)s of availability zone %(az)s with edge "
                     "cluster %(ec)s does not match the default overlay tz "
                     "%(tz)s") % {
                'type': obj_type,
                'id': obj_id,
                'ec': ec_uuid,
                'tz': self._default_overlay_tz_uuid,
                'az': self.name})
            raise nsx_exc.NsxPluginException(err_msg=msg)

        if (self._default_vlan_tz_uuid and
            self._default_vlan_tz_uuid not in obj_tzs):
            msg = (_("%(type)s %(id)s of availability zone %(az)s with edge "
                     "cluster %(ec)s does not match the default vlan tz "
                     "%(tz)s") % {
                'type': obj_type,
                'id': obj_id,
                'ec': ec_uuid,
                'tz': self._default_vlan_tz_uuid,
                'az': self.name})
            raise nsx_exc.NsxPluginException(err_msg=msg)

    def validate_availability_zone(self, nsxpolicy, nsxlib=None):
        """Validate that all the components of this AZ are connected"""

        if not nsxlib:
            LOG.warning("Cannot validate availability zone %s without "
                        "passthrough api", self.name)
            return

        # Validate tier0 TZ match the default ones
        tier0_ec_path = nsxpolicy.tier0.get_edge_cluster_path(
            self._default_tier0_router)
        if not tier0_ec_path:
            msg = (_("Tier0 %(id)s of availability zone %(az)s does not have "
                     "an edge cluster") % {
                'id': self._default_tier0_router,
                'az': self.name})
            raise nsx_exc.NsxPluginException(err_msg=msg)
        tier0_ec_uuid = p_utils.path_to_id(tier0_ec_path)
        self._validate_tz(nsxpolicy, nsxlib, 'Tier0',
                          self._default_tier0_router,
                          tier0_ec_uuid)

        if self.use_policy_dhcp:
            dhcp_ec_path = nsxpolicy.dhcp_server_config.get(
                self._policy_dhcp_server_config).get('edge_cluster_path')
            dhcp_ec = p_utils.path_to_id(dhcp_ec_path)
            if dhcp_ec != tier0_ec_uuid:
                self._validate_tz(nsxpolicy, nsxlib, 'DHCP server config',
                                  self._policy_dhcp_server_config,
                                  dhcp_ec)
        elif self._native_dhcp_profile_uuid:
            dhcp_ec = nsxlib.native_dhcp_profile.get(
                self._native_dhcp_profile_uuid).get('edge_cluster_id')
            if dhcp_ec != tier0_ec_uuid:
                self._validate_tz(nsxpolicy, nsxlib, 'DHCP profile',
                                  self._native_dhcp_profile_uuid,
                                  dhcp_ec)

        if self._native_md_proxy_uuid:
            # Validate that the edge cluster of the MD proxy (MP or policy one)
            # match the configured TZs
            if self.use_policy_md:
                md_ec_path = nsxpolicy.md_proxy.get(
                    self._native_md_proxy_uuid).get('edge_cluster_path')
                md_ec = p_utils.path_to_id(md_ec_path)
            else:
                md_ec = nsxlib.native_md_proxy.get(
                    self._native_md_proxy_uuid).get('edge_cluster_id')
            if md_ec != tier0_ec_uuid:
                self._validate_tz(nsxpolicy, nsxlib, 'MD Proxy',
                                  self._native_md_proxy_uuid,
                                  md_ec)


class NsxPAvailabilityZones(common_az.ConfiguredAvailabilityZones):

    default_name = DEFAULT_NAME

    def __init__(self):
        default_azs = cfg.CONF.default_availability_zones
        super(NsxPAvailabilityZones, self).__init__(
            cfg.CONF.nsx_p.availability_zones,
            NsxPAvailabilityZone,
            default_availability_zones=default_azs)
        self.non_default_dns_domain = self.dns_domain_configured_non_default()

    def dns_domain_configured_non_default(self):
        for az in self.availability_zones.values():
            if az.dns_domain and az.dns_domain != cfg.CONF.nsx_p.dns_domain:
                return True
        return False
