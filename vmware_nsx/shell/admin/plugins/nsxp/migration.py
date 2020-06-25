# Copyright 2020 VMware, Inc.  All rights reserved.
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
from vmware_nsx.shell.admin.plugins.common import utils as admin_utils
from vmware_nsx.shell.admin.plugins.nsxv3.resources import migration
from vmware_nsx.shell import resources as shell


@admin_utils.output_header
def cleanup_db_mappings(resource, event, trigger, **kwargs):
    """Delete all entries from nsx-t mapping tables in DB"""
    return migration.cleanup_db_mappings(resource, event, trigger, **kwargs)


registry.subscribe(cleanup_db_mappings,
                   constants.NSX_MIGRATE_T_P,
                   shell.Operations.CLEAN_ALL.value)
