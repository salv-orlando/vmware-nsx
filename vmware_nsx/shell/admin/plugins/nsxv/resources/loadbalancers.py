# Copyright 2021 VMware, Inc.
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

from neutron_lib.callbacks import registry

from vmware_nsx.shell.admin.plugins.common import constants
from vmware_nsx.shell.admin.plugins.common import loadbalancers
from vmware_nsx.shell import resources as shell


registry.subscribe(loadbalancers.set_loadbalancer_status_error,
                   constants.LOADBALANCERS,
                   shell.Operations.SET_STATUS_ERROR.value)
