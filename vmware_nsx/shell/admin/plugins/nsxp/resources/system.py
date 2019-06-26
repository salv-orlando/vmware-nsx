# Copyright 2018 VMware, Inc.  All rights reserved.
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

from oslo_log import log as logging

from vmware_nsx.shell.admin.plugins.common import constants
from vmware_nsx.shell.admin.plugins.common import utils as admin_utils
from vmware_nsx.shell.admin.plugins.nsxp.resources import utils as p_utils
from vmware_nsx.shell import resources as shell

from neutron_lib.callbacks import registry


LOG = logging.getLogger(__name__)

MIN_REALIZATION_INTERVAL = 1
MAX_REALIZATION_INTERVAL = 10


def set_system_parameters(resource, event, trigger, **kwargs):
    """Set interval that controls realization and purge frequency

    This setting is affecting NSX Policy Manager appliance.
    """
    if kwargs.get('property'):
        properties = admin_utils.parse_multi_keyval_opt(kwargs['property'])
        interval = properties.get('realization_interval')

        if interval:
            int_interval = int(interval)
            if int_interval not in range(MIN_REALIZATION_INTERVAL,
                                         MAX_REALIZATION_INTERVAL + 1):
                LOG.info("Realization interval should be in range %d-%d",
                         MIN_REALIZATION_INTERVAL, MAX_REALIZATION_INTERVAL)
                return

            nsxpolicy = p_utils.get_connected_nsxpolicy()
            try:
                nsxpolicy.set_realization_interval(int_interval)
            except Exception as ex:
                LOG.error("Failed to apply intent realization interval to "
                          "policy appliance - %s", ex)

            LOG.info("Intent realization interval set to %s min" % interval)


registry.subscribe(set_system_parameters,
                   constants.SYSTEM,
                   shell.Operations.SET.value)
