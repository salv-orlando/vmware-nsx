# Copyright 2019 VMware, Inc.
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

LOG = logging.getLogger(__name__)


class IPsecNsxPValidator(ipsec_validator.IPsecCommonValidator):
    """Validator methods for Vmware NSX-Policy VPN support"""
    def __init__(self, service_plugin):
        super(IPsecNsxPValidator, self).__init__(service_plugin)
        self.nsxpolicy = self._core_plugin.nsxpolicy

    @property
    def auth_algorithm_map(self):
        return ipsec_utils.AUTH_ALGORITHM_MAP_P

    @property
    def pfs_map(self):
        return ipsec_utils.PFS_MAP_P

    def _validate_t0_ha_mode(self, tier0_uuid):
        tier0_router = self.nsxpolicy.tier0.get(tier0_uuid)
        if (not tier0_router or
            tier0_router.get('ha_mode') != 'ACTIVE_STANDBY'):
            msg = _("The router GW should be connected to a TIER-0 router "
                    "with ACTIVE_STANDBY HA mode")
            raise nsx_exc.NsxVpnValidationError(details=msg)

    def _support_endpoint_groups(self):
        return True
