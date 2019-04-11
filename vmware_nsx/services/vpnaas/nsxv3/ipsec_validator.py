# Copyright 2017 VMware, Inc.
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

from oslo_log import log as logging

from vmware_nsx._i18n import _
from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.services.vpnaas.common_v3 import ipsec_utils
from vmware_nsx.services.vpnaas.common_v3 import ipsec_validator
from vmware_nsxlib.v3 import nsx_constants as consts

LOG = logging.getLogger(__name__)


class IPsecV3Validator(ipsec_validator.IPsecCommonValidator):
    """Validator methods for Vmware NSX-V3 VPN support"""
    def __init__(self, service_plugin):
        super(IPsecV3Validator, self).__init__(service_plugin)

    @property
    def nsxlib(self):
        return self._core_plugin.nsxlib

    def check_backend_version(self):
        if not self.nsxlib.feature_supported(consts.FEATURE_IPSEC_VPN):
            # ipsec vpn is not supported
            LOG.warning("VPNaaS is not supported by the NSX backend (version "
                        "%s)",
                        self.nsxlib.get_version())
            self.backend_support = False
        else:
            self.backend_support = True

    def _validate_backend_version(self):
        if not self.backend_support:
            msg = (_("VPNaaS is not supported by the NSX backend "
                     "(version %s)") % self.nsxlib.get_version())
            raise nsx_exc.NsxVpnValidationError(details=msg)

    @property
    def auth_algorithm_map(self):
        return ipsec_utils.AUTH_ALGORITHM_MAP

    @property
    def pfs_map(self):
        return ipsec_utils.PFS_MAP

    def _validate_t0_ha_mode(self, tier0_uuid):
        # TODO(asarfaty): cache this result
        tier0_router = self.nsxlib.logical_router.get(tier0_uuid)
        if (not tier0_router or
            tier0_router.get('high_availability_mode') != 'ACTIVE_STANDBY'):
            msg = _("The router GW should be connected to a TIER-0 router "
                    "with ACTIVE_STANDBY HA mode")
            raise nsx_exc.NsxVpnValidationError(details=msg)

    def _validate_router(self, context, router_id):
        super(IPsecV3Validator, self)._validate_router(context, router_id)

        # Verify that this is a no-snat router
        router_db = self._core_plugin._get_router(context, router_id)
        if router_db.enable_snat:
            msg = _("VPN is supported only for routers with disabled SNAT")
            raise nsx_exc.NsxVpnValidationError(details=msg)
