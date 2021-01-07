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
from oslo_log import log as logging

from vmware_nsx.shell.admin.plugins.common import constants
from vmware_nsx.shell.admin.plugins.common import utils as admin_utils
from vmware_nsx.shell.admin.plugins.nsxp.resources import utils as p_utils
from vmware_nsx.shell.admin.plugins.nsxv3.resources import migration
from vmware_nsx.shell import resources as shell
from vmware_nsxlib.v3.policy import constants as policy_constants

LOG = logging.getLogger(__name__)


@admin_utils.output_header
def cleanup_db_mappings(resource, event, trigger, **kwargs):
    """Delete all entries from nsx-t mapping tables in DB"""
    return migration.MP2Policy_cleanup_db_mappings(
        resource, event, trigger, **kwargs)


@admin_utils.output_header
def post_v2t_migration_cleanups(resource, event, trigger, **kwargs):
    """Cleanup unneeded migrated resources after v2t migration is done"""
    nsxpolicy = p_utils.get_connected_nsxpolicy()
    # clean all migrated DFW sections
    sections = nsxpolicy.comm_map.list(policy_constants.DEFAULT_DOMAIN)
    for section in sections:
        # Look for the tag marking the migrated sections
        for tag in section.get('tags', []):
            if tag['scope'] == 'v_origin':
                LOG.info("Deleting migrated: %s", tag['tag'])
                nsxpolicy.comm_map.delete(policy_constants.DEFAULT_DOMAIN,
                                          section['id'])
                continue


registry.subscribe(cleanup_db_mappings,
                   constants.NSX_MIGRATE_T_P,
                   shell.Operations.CLEAN_ALL.value)

registry.subscribe(post_v2t_migration_cleanups,
                   constants.NSX_MIGRATE_V_T,
                   shell.Operations.CLEAN_ALL.value)
