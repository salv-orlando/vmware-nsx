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

# Default conf file locations
NEUTRON_CONF = '/etc/neutron/neutron.conf'
NSX_INI = '/etc/neutron/plugins/vmware/nsx.ini'

# NSX Plugin Constants
NSXP_PLUGIN = 'vmware_nsx.plugin.NsxPolicyPlugin'
NSXV3_PLUGIN = 'vmware_nsx.plugin.NsxV3Plugin'
NSXV_PLUGIN = 'vmware_nsx.plugin.NsxVPlugin'
NSXTVD_PLUGIN = 'vmware_nsx.plugin.NsxTVDPlugin'
VMWARE_NSXV = 'vmware_nsxv'
VMWARE_NSXV3 = 'vmware_nsxv3'
VMWARE_NSXP = 'vmware_nsxp'
VMWARE_NSXTVD = 'vmware_nsxtvd'

# Common Resource Constants
NETWORKS = 'networks'
ROUTERS = 'routers'
DHCP_BINDING = 'dhcp-binding'
FIREWALL_SECTIONS = 'firewall-sections'
FIREWALL_NSX_GROUPS = 'nsx-security-groups'
SECURITY_GROUPS = 'security-groups'
CONFIG = 'config'
ORPHANED_NETWORKS = 'orphaned-networks'
ORPHANED_ROUTERS = 'orphaned-routers'
SYSTEM = 'system'
LOADBALANCERS = 'loadbalancers'

# NSXV3 only Resource Constants
PORTS = 'ports'
METADATA_PROXY = 'metadata-proxy'
ORPHANED_DHCP_SERVERS = 'orphaned-dhcp-servers'
CERTIFICATE = 'certificate'
LB_SERVICES = 'lb-services'
LB_VIRTUAL_SERVERS = 'lb-virtual-servers'
LB_POOLS = 'lb-pools'
LB_MONITORS = 'lb-monitors'
LB_ADVERTISEMENT = 'lb-advertisement'
RATE_LIMIT = 'rate-limit'
CLUSTER = 'cluster'
ORPHANED_FIREWALL_SECTIONS = 'orphaned-firewall-sections'
NSX_MIGRATE_T_P = 'nsx-migrate-t2p'

# NSXV only Resource Constants
EDGES = 'edges'
SPOOFGUARD_POLICY = 'spoofguard-policy'
BACKUP_EDGES = 'backup-edges'
ORPHANED_EDGES = 'orphaned-edges'
ORPHANED_BINDINGS = 'orphaned-bindings'
ORPHANED_RULES = 'orphaned-rules'
ORPHANED_VNICS = 'orphaned-vnics'
MISSING_EDGES = 'missing-edges'
METADATA = 'metadata'
MISSING_NETWORKS = 'missing-networks'
BGP_GW_EDGE = 'bgp-gw-edge'
ROUTING_REDIS_RULE = 'routing-redistribution-rule'
BGP_NEIGHBOUR = 'bgp-neighbour'
NSX_PORTGROUPS = 'nsx-portgroups'
NSX_VIRTUALWIRES = 'nsx-virtualwires'
NSX_MIGRATE_V_T = 'nsx-migrate-v2t'

# NSXTV only Resource Constants
PROJECTS = 'projects'
