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

import copy

from neutron_lib.callbacks import registry
from oslo_log import log as logging
from oslo_serialization import jsonutils

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

    # cleanup migrated DVS ports (belong to the edges that are not in use)
    segments = nsxpolicy.segment.list()
    for seg in segments:
        # skip non-neutron segments
        if not p_utils.is_neutron_resource(seg):
            continue
        ports = nsxpolicy.segment_port.list(seg['id'])
        # find the non-neutron ports and delete them
        for port in ports:
            if not p_utils.is_neutron_resource(port):
                nsxpolicy.segment_port.delete(seg['id'], port['id'])
                LOG.error("Deleted migrated non-neutron port %s", port['id'])


@admin_utils.output_header
def migration_tier0_redistribute(resource, event, trigger, **kwargs):
    """Disable/Restore tier0s route redistribution during V2T migration"""
    errmsg = ("Need to specify --property action=disable/restore and a comma "
              "separated tier0 list as --property tier0s")
    if not kwargs.get('property'):
        LOG.error("%s", errmsg)
        return
    properties = admin_utils.parse_multi_keyval_opt(kwargs['property'])
    action = properties.get('action')
    tier0string = properties.get('tier0s')
    if not tier0string or not action:
        LOG.error("%s", errmsg)
        return

    tier0s = tier0string.split(",")
    nsxpolicy = p_utils.get_connected_nsxpolicy()
    file_name = "tier0_redistribution_conf.json"

    if action.lower() == 'disable':
        orig_conf_map = {}
        for tier0 in tier0s:
            # get the current config
            try:
                orig_conf = nsxpolicy.tier0.get_route_redistribution_config(
                    tier0)
            except Exception:
                LOG.error("Did not find Tier0 %s", tier0)
                return
            fixed_conf = copy.deepcopy(orig_conf)
            if ((not orig_conf['bgp_enabled'] and
                 not orig_conf['ospf_enabled']) or
                not orig_conf.get('redistribution_rules')):
                # Already disabled
                LOG.info("Tier0 %s route redistribution config was not "
                         "changed because it is disabled", tier0)
                continue
            # Check if any of the rules have tier1 flags enabled
            found = False
            rule_num = 0
            for rule in orig_conf['redistribution_rules']:
                fixed_types = []
                for route_type in rule['route_redistribution_types']:
                    if route_type.startswith('TIER1'):
                        found = True
                    else:
                        fixed_types.append(route_type)
                fixed_conf['redistribution_rules'][rule_num][
                    'route_redistribution_types'] = fixed_types
                rule_num = rule_num + 1
            if not found:
                LOG.info("Tier0 %s route redistribution config was not "
                         "changed because there are no Tier1 types", tier0)
                continue
            # Save the original config so it can be reverted later
            orig_conf_map[tier0] = orig_conf
            nsxpolicy.tier0.update_route_redistribution_config(
                tier0, fixed_conf)
            LOG.info("Disabled Tier0 %s route redistribution config for "
                     "Tier1 routes", tier0)
        f = open(file_name, "w")
        f.write("%s" % jsonutils.dumps(orig_conf_map))
        f.close()

    elif action.lower() == 'restore':
        try:
            f = open(file_name, "r")
            orig_conf_map = jsonutils.loads(f.read())
            f.close()
        except Exception:
            LOG.error("Didn't find input file %s", file_name)
            return
        for tier0 in tier0s:
            if tier0 in orig_conf_map:
                # Restore its original config:
                try:
                    nsxpolicy.tier0.update_route_redistribution_config(
                        tier0, orig_conf_map[tier0])
                    LOG.info("Restored Tier0 %s original route redistribution "
                             "config", tier0)
                except Exception:
                    LOG.error("Failed to update redistribution of Tier0 %s",
                              tier0)
            else:
                LOG.info("Tier0 %s route redistribution config was not "
                         "changed", tier0)
    else:
        LOG.error("%s", errmsg)


registry.subscribe(cleanup_db_mappings,
                   constants.NSX_MIGRATE_T_P,
                   shell.Operations.CLEAN_ALL.value)

registry.subscribe(post_v2t_migration_cleanups,
                   constants.NSX_MIGRATE_V_T,
                   shell.Operations.CLEAN_ALL.value)

registry.subscribe(migration_tier0_redistribute,
                   constants.NSX_MIGRATE_V_T,
                   shell.Operations.NSX_REDISTRIBUTE.value)
