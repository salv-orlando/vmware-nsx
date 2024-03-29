# Copyright 2015 VMware, Inc.  All rights reserved.
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

import enum
import glob
import importlib
import os

from oslo_config import cfg
from oslo_log import log as logging
import requests

from vmware_nsx.common import config  # noqa
from vmware_nsx.shell.admin.plugins.common import constants

# Suppress the Insecure request warning
requests.packages.urllib3.disable_warnings()

LOG = logging.getLogger(__name__)


class Operations(enum.Enum):
    LIST = 'list'
    SET = 'set'
    CLEAN = 'clean'
    CLEAN_ALL = 'clean-all'
    CREATE = 'create'
    DELETE = 'delete'
    LIST_MISMATCHES = 'list-mismatches'
    FIX_MISMATCH = 'fix-mismatch'
    LIST_UNUSED = 'list-unused'
    LIST_ORPHANED = 'list-orphaned'
    CLEAN_ORPHANED = 'clean-orphaned'

    NEUTRON_LIST = 'neutron-list'
    NEUTRON_CLEAN = 'neutron-clean'
    NEUTRON_UPDATE = 'neutron-update'

    NSX_LIST = 'nsx-list'
    NSX_CLEAN = 'nsx-clean'
    NSX_UPDATE = 'nsx-update'
    NSX_UPDATE_ALL = 'nsx-update-all'
    NSX_UPDATE_SECRET = 'nsx-update-secret'
    NSX_UPDATE_RULES = 'nsx-update-rules'
    NSX_UPDATE_DHCP_RELAY = 'nsx-update-dhcp-relay'
    NSX_UPDATE_STATE = 'nsx-update-state'
    NSX_ENABLE_STANDBY_RELOCATION = 'nsx-enable-standby-relocation'
    NSX_UPDATE_IP = 'nsx-update-ip'
    NSX_UPDATE_TAGS = 'nsx-update-tags'
    NSX_UPDATE_FW = 'nsx-update-fw'
    NSX_RECREATE = 'nsx-recreate'
    NSX_REDISTRIBUTE = 'nsx-redistribute'
    NSX_REORDER = 'nsx-reorder'
    NSX_DISCONNECT = 'nsx-disconnect'
    NSX_RECONNECT = 'nsx-reconnect'
    NSX_TAG_DEFAULT = 'nsx-tag-default'
    NSX_MIGRATE_V_V3 = 'nsx-migrate-v-v3'
    MIGRATE_TO_POLICY = 'migrate-to-policy'
    LIST_POLICIES = 'list-policies'
    UPDATE_LOGGING = 'update-logging'
    NSX_MIGRATE_EXCLUDE_PORTS = 'migrate-exclude-ports'
    MIGRATE_VDR_DHCP = 'migrate-vdr-dhcp'
    STATUS = 'status'
    GENERATE = 'generate'
    IMPORT = 'import'
    SHOW = 'show'
    VALIDATE = 'validate'
    REUSE = 'reuse'
    UPDATE_TIER0 = 'update-tier0'
    RECOVER_TIER0 = 'recover-tier0'
    UPDATE_METADATA = 'update-metadata'
    UPDATE_DHCP_EDGE = 'update-dhcp-profile-edge'
    UPDATE_FIREWALL_MATCH = 'update-nat-firewall-match'
    SET_STATUS_ERROR = 'set-status-error'
    CHECK_COMPUTE_CLUSTERS = 'check-compute-clusters'
    CUTOVER_MAPPINGS = 'mappings-for-edge-cutover'


ops = [op.value for op in Operations]


class Resource(object):
    def __init__(self, name, ops_obj):
        self.name = name
        self.supported_ops = ops_obj


# Add supported NSX-V3 resources in this dictionary
nsxv3_resources = {
    constants.SECURITY_GROUPS: Resource(constants.SECURITY_GROUPS,
                                        [Operations.LIST.value,
                                         Operations.FIX_MISMATCH.value,
                                         Operations.UPDATE_LOGGING.value]),
    constants.FIREWALL_SECTIONS: Resource(constants.FIREWALL_SECTIONS,
                                          [Operations.LIST.value,
                                           Operations.LIST_MISMATCHES.value,
                                           Operations.REUSE.value]),
    constants.FIREWALL_NSX_GROUPS: Resource(
        constants.FIREWALL_NSX_GROUPS, [
            Operations.LIST.value,
            Operations.LIST_MISMATCHES.value]),
    constants.ORPHANED_FIREWALL_SECTIONS: Resource(
        constants.ORPHANED_FIREWALL_SECTIONS, [
            Operations.NSX_LIST.value,
            Operations.NSX_CLEAN.value]),
    constants.NETWORKS: Resource(constants.NETWORKS,
                                 [Operations.LIST_MISMATCHES.value]),
    constants.PORTS: Resource(constants.PORTS,
                              [Operations.LIST_MISMATCHES.value,
                               Operations.NSX_TAG_DEFAULT.value,
                               Operations.NSX_MIGRATE_V_V3.value,
                               Operations.NSX_MIGRATE_EXCLUDE_PORTS.value]),
    constants.ROUTERS: Resource(
        constants.ROUTERS, [
            Operations.LIST_MISMATCHES.value,
            Operations.NSX_UPDATE_RULES.value,
            Operations.NSX_UPDATE_DHCP_RELAY.value,
            Operations.NSX_ENABLE_STANDBY_RELOCATION.value,
            Operations.UPDATE_TIER0.value,
            Operations.RECOVER_TIER0.value]),
    constants.DHCP_BINDING: Resource(constants.DHCP_BINDING,
                                     [Operations.LIST.value,
                                      Operations.NSX_RECREATE.value]),
    constants.METADATA_PROXY: Resource(constants.METADATA_PROXY,
                                       [Operations.LIST.value,
                                        Operations.NSX_UPDATE_IP.value]),
    constants.ORPHANED_DHCP_SERVERS: Resource(constants.ORPHANED_DHCP_SERVERS,
                                              [Operations.NSX_LIST.value,
                                               Operations.NSX_CLEAN.value]),
    constants.CERTIFICATE: Resource(constants.CERTIFICATE,
                                    [Operations.GENERATE.value,
                                     Operations.SHOW.value,
                                     Operations.CLEAN.value,
                                     Operations.IMPORT.value,
                                     Operations.NSX_LIST.value]),
    constants.CONFIG: Resource(constants.CONFIG,
                               [Operations.VALIDATE.value]),
    constants.ORPHANED_NETWORKS: Resource(constants.ORPHANED_NETWORKS,
                                 [Operations.LIST.value,
                                  Operations.NSX_CLEAN.value]),
    constants.ORPHANED_ROUTERS: Resource(constants.ORPHANED_ROUTERS,
                                [Operations.LIST.value,
                                 Operations.NSX_CLEAN.value]),
    constants.LB_SERVICES: Resource(constants.LB_SERVICES,
                                    [Operations.LIST.value,
                                     Operations.LIST_ORPHANED.value,
                                     Operations.CLEAN_ORPHANED.value]),
    constants.LB_VIRTUAL_SERVERS: Resource(constants.LB_VIRTUAL_SERVERS,
                                           [Operations.LIST.value]),
    constants.LB_POOLS: Resource(constants.LB_POOLS,
                                 [Operations.LIST.value]),
    constants.LB_MONITORS: Resource(constants.LB_MONITORS,
                                    [Operations.LIST.value]),
    constants.RATE_LIMIT: Resource(constants.RATE_LIMIT,
                                   [Operations.SHOW.value,
                                    Operations.NSX_UPDATE.value]),
    constants.LB_ADVERTISEMENT: Resource(constants.LB_ADVERTISEMENT,
                                         [Operations.NSX_UPDATE.value]),
    constants.CLUSTER: Resource(constants.CLUSTER,
                                [Operations.SHOW.value]),
    constants.NSX_MIGRATE_T_P: Resource(constants.NSX_MIGRATE_T_P,
                                        [Operations.IMPORT.value,
                                         Operations.CLEAN_ALL.value,
                                         Operations.VALIDATE.value]),
    constants.LOADBALANCERS: Resource(constants.LOADBALANCERS,
                                      [Operations.SET_STATUS_ERROR.value]),
}

# Add supported NSX-V resources in this dictionary
nsxv_resources = {
    constants.EDGES: Resource(constants.EDGES,
                              [Operations.NSX_LIST.value,
                               Operations.NEUTRON_LIST.value,
                               Operations.NSX_UPDATE.value,
                               Operations.NSX_UPDATE_ALL.value,
                               Operations.NSX_DISCONNECT.value,
                               Operations.NSX_RECONNECT.value]),
    constants.BACKUP_EDGES: Resource(constants.BACKUP_EDGES,
                                     [Operations.LIST.value,
                                      Operations.CLEAN.value,
                                      Operations.CLEAN_ALL.value,
                                      Operations.LIST_MISMATCHES.value,
                                      Operations.FIX_MISMATCH.value,
                                      Operations.NEUTRON_CLEAN.value]),
    constants.ORPHANED_EDGES: Resource(constants.ORPHANED_EDGES,
                                       [Operations.LIST.value,
                                        Operations.CLEAN.value]),
    constants.ORPHANED_BINDINGS: Resource(constants.ORPHANED_BINDINGS,
                                          [Operations.LIST.value,
                                           Operations.CLEAN.value]),
    constants.MISSING_EDGES: Resource(constants.MISSING_EDGES,
                                      [Operations.LIST.value]),
    constants.SPOOFGUARD_POLICY: Resource(constants.SPOOFGUARD_POLICY,
                                          [Operations.LIST.value,
                                           Operations.CLEAN.value,
                                           Operations.LIST_MISMATCHES.value,
                                           Operations.FIX_MISMATCH.value]),
    constants.DHCP_BINDING: Resource(constants.DHCP_BINDING,
                                     [Operations.LIST.value,
                                      Operations.NSX_UPDATE.value,
                                      Operations.NSX_REDISTRIBUTE.value,
                                      Operations.NSX_RECREATE.value]),
    constants.NETWORKS: Resource(constants.NETWORKS,
                                 [Operations.LIST.value,
                                  Operations.NSX_UPDATE.value]),
    constants.MISSING_NETWORKS: Resource(constants.MISSING_NETWORKS,
                                [Operations.LIST.value]),
    constants.ORPHANED_NETWORKS: Resource(constants.ORPHANED_NETWORKS,
                                 [Operations.LIST.value,
                                  Operations.NSX_CLEAN.value]),
    constants.NSX_PORTGROUPS: Resource(constants.NSX_PORTGROUPS,
                                       [Operations.LIST.value,
                                        Operations.NSX_CLEAN.value]),
    constants.NSX_VIRTUALWIRES: Resource(constants.NSX_VIRTUALWIRES,
                                         [Operations.LIST.value]),
    constants.SECURITY_GROUPS: Resource(constants.SECURITY_GROUPS,
                                        [Operations.LIST.value,
                                         Operations.FIX_MISMATCH.value,
                                         Operations.MIGRATE_TO_POLICY.value,
                                         Operations.LIST_POLICIES.value,
                                         Operations.UPDATE_LOGGING.value]),
    constants.FIREWALL_NSX_GROUPS: Resource(
        constants.FIREWALL_NSX_GROUPS, [Operations.LIST.value,
                                        Operations.LIST_MISMATCHES.value]),
    constants.FIREWALL_SECTIONS: Resource(constants.FIREWALL_SECTIONS,
                                          [Operations.LIST.value,
                                           Operations.LIST_MISMATCHES.value,
                                           Operations.NSX_UPDATE.value,
                                           Operations.NSX_REORDER.value,
                                           Operations.LIST_UNUSED.value,
                                           Operations.NSX_CLEAN.value]),
    constants.ORPHANED_RULES: Resource(constants.ORPHANED_RULES,
                                       [Operations.LIST.value,
                                        Operations.NSX_CLEAN.value]),
    constants.METADATA: Resource(
        constants.METADATA, [Operations.NSX_UPDATE.value,
                             Operations.NSX_UPDATE_SECRET.value,
                             Operations.STATUS.value]),
    constants.ROUTERS: Resource(constants.ROUTERS,
                                [Operations.NSX_RECREATE.value,
                                 Operations.NSX_REDISTRIBUTE.value,
                                 Operations.MIGRATE_VDR_DHCP.value,
                                 Operations.NSX_UPDATE_FW.value]),
    constants.ORPHANED_VNICS: Resource(constants.ORPHANED_VNICS,
                                       [Operations.NSX_LIST.value,
                                        Operations.NSX_CLEAN.value]),
    constants.CONFIG: Resource(constants.CONFIG,
                               [Operations.VALIDATE.value,
                                Operations.CHECK_COMPUTE_CLUSTERS.value]),
    constants.BGP_GW_EDGE: Resource(constants.BGP_GW_EDGE,
                                    [Operations.CREATE.value,
                                     Operations.DELETE.value,
                                     Operations.LIST.value]),
    constants.ROUTING_REDIS_RULE: Resource(constants.ROUTING_REDIS_RULE,
                                           [Operations.CREATE.value,
                                            Operations.DELETE.value]),
    constants.BGP_NEIGHBOUR: Resource(constants.BGP_NEIGHBOUR,
                                      [Operations.CREATE.value,
                                       Operations.DELETE.value]),
    constants.NSX_MIGRATE_V_T: Resource(constants.NSX_MIGRATE_V_T,
                                        [Operations.VALIDATE.value,
                                         Operations.CUTOVER_MAPPINGS.value]),
    constants.PORTS: Resource(constants.PORTS,
                              [Operations.LIST.value]),
    constants.LOADBALANCERS: Resource(constants.LOADBALANCERS,
                                      [Operations.SET_STATUS_ERROR.value]),
}


# Add supported NSX-TVD resources in this dictionary
nsxtvd_resources = {
    constants.PROJECTS: Resource(constants.PROJECTS,
                                 [Operations.IMPORT.value,
                                  Operations.NSX_MIGRATE_V_V3.value]),
}

nsxp_resources = {
    constants.SECURITY_GROUPS: Resource(constants.SECURITY_GROUPS,
                                        [Operations.LIST.value]),
    constants.NETWORKS: Resource(constants.NETWORKS,
                                 [Operations.LIST.value,
                                  Operations.NSX_UPDATE_STATE.value,
                                  Operations.UPDATE_METADATA.value]),
    constants.DHCP_BINDING: Resource(constants.DHCP_BINDING,
                                 [Operations.MIGRATE_TO_POLICY.value,
                                  Operations.UPDATE_DHCP_EDGE.value]),
    constants.ROUTERS: Resource(constants.ROUTERS,
                                [Operations.LIST.value,
                                 Operations.UPDATE_TIER0.value,
                                 Operations.RECOVER_TIER0.value,
                                 Operations.UPDATE_FIREWALL_MATCH.value]),
    constants.LB_SERVICES: Resource(constants.LB_SERVICES,
                                    [Operations.NSX_UPDATE_TAGS.value,
                                     Operations.LIST_ORPHANED.value,
                                     Operations.CLEAN_ORPHANED.value]),
    constants.CERTIFICATE: Resource(constants.CERTIFICATE,
                                    [Operations.GENERATE.value,
                                     Operations.SHOW.value,
                                     Operations.CLEAN.value,
                                     Operations.IMPORT.value,
                                     Operations.NSX_LIST.value]),
    constants.SYSTEM: Resource(constants.SYSTEM,
                               [Operations.SET.value]),
    constants.NSX_MIGRATE_T_P: Resource(constants.NSX_MIGRATE_T_P,
                                        [Operations.CLEAN_ALL.value]),
    constants.NSX_MIGRATE_V_T: Resource(constants.NSX_MIGRATE_V_T,
                                        [Operations.CLEAN_ALL.value,
                                         Operations.VALIDATE.value,
                                         Operations.NSX_REDISTRIBUTE.value]),
    constants.LOADBALANCERS: Resource(constants.LOADBALANCERS,
                                      [Operations.SET_STATUS_ERROR.value]),
}

nsxv3_resources_names = list(nsxv3_resources.keys())
nsxv_resources_names = list(nsxv_resources.keys())
nsxtvd_resources_names = list(nsxtvd_resources.keys())
nsxp_resources_names = list(nsxp_resources.keys())


def get_resources(plugin_dir):
    modules = glob.glob(plugin_dir + "/*.py")
    return map(lambda module: os.path.splitext(os.path.basename(module))[0],
               modules)


def get_plugin():
    plugin = cfg.CONF.core_plugin
    plugin_name = ''
    if plugin in (constants.NSXV3_PLUGIN, constants.VMWARE_NSXV3):
        plugin_name = 'nsxv3'
    elif plugin in (constants.NSXV_PLUGIN, constants.VMWARE_NSXV):
        plugin_name = 'nsxv'
    elif plugin in (constants.NSXTVD_PLUGIN, constants.VMWARE_NSXTVD):
        plugin_name = 'nsxtvd'
    elif plugin in (constants.NSXP_PLUGIN, constants.VMWARE_NSXP):
        plugin_name = 'nsxp'
    return plugin_name


def _get_choices():
    plugin = get_plugin()
    if plugin == 'nsxv3':
        return nsxv3_resources_names
    if plugin == 'nsxv':
        return nsxv_resources_names
    if plugin == 'nsxtvd':
        return nsxtvd_resources_names


def _get_resources():
    plugin = get_plugin()
    if plugin == 'nsxv3':
        return f"NSX-V3 resources: {(', '.join(nsxv3_resources_names))}"
    if plugin == 'nsxv':
        return f"NSX-V resources: {(', '.join(nsxv_resources_names))}"
    if plugin == 'nsxtvd':
        return f"NSX-TVD resources: {(', '.join(nsxtvd_resources_names))}"


cli_opts = [cfg.StrOpt('fmt',
                       short='f',
                       default='psql',
                       choices=['psql', 'json'],
                       help='Supported output formats: json, psql'),
            cfg.StrOpt('resource',
                       short='r',
                       choices=_get_choices(),
                       help=_get_resources()),
            cfg.StrOpt('operation',
                       short='o',
                       help=f"Supported list of operations:"
                            f" {(', '.join(ops))}"),
            cfg.StrOpt('plugin',
                       help='nsxv or nsxv3 if the tvd plugin is used'),
            cfg.BoolOpt('force',
                        default=False,
                        help='Enables \'force\' mode. No confirmations will '
                             'be made before deletions.'),
            cfg.MultiStrOpt('property',
                            short='p',
                            help='Key-value pair containing the information '
                                 'to be updated. For ex: key=value.'),
            cfg.BoolOpt('verbose',
                        short='v',
                        default=False,
                        help='Triggers detailed output for some commands')
            ]


# Describe dependencies between admin utils resources and external libraries
# that are not always installed
resources_dependencies = {
    'nsxv': {'gw_edges': ['neutron_dynamic_routing.extensions']}}


def verify_external_dependencies(plugin_name, resource):
    if plugin_name in resources_dependencies:
        deps = resources_dependencies[plugin_name]
        if resource in deps:
            for d in deps[resource]:
                try:
                    importlib.import_module(d)
                except ImportError:
                    return False
    return True


def init_resource_plugin(plugin_name, plugin_dir):
    plugin_resources = get_resources(plugin_dir)
    for resource in plugin_resources:
        if (resource != '__init__'):
            # skip unsupported resources
            if not verify_external_dependencies(plugin_name, resource):
                LOG.info("Skipping resource %s because of dependencies",
                         resource)
                continue
            # load the resource
            importlib.import_module(
                f"vmware_nsx.shell.admin.plugins."
                f"{plugin_name}.resources." + resource)


def get_plugin_dir(plugin_name):
    plugin_dir = (os.path.dirname(os.path.realpath(__file__)) +
                  "/admin/plugins")
    return f"{plugin_dir}/{plugin_name}/resources"
