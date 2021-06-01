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

import os
import time
import xml.etree.ElementTree as et

import mock

from oslo_config import cfg
from oslo_log import log as logging

from neutron_lib import context as neutron_context
from neutron_lib.plugins import directory

from vmware_nsx.common import config
from vmware_nsx.db import db as nsx_db
from vmware_nsx.db import nsxv_db
from vmware_nsx.extensions import projectpluginmap
from vmware_nsx import plugin
from vmware_nsx.plugins.nsx_v.vshield import vcns
from vmware_nsx.shell.admin.plugins.common import utils as admin_utils

LOG = logging.getLogger(__name__)
network_types = ['Network', 'VirtualWire', 'DistributedVirtualPortgroup']
PORTGROUP_PREFIX = 'dvportgroup'


def get_nsxv_client():
    return vcns.Vcns(
        address=cfg.CONF.nsxv.manager_uri,
        user=cfg.CONF.nsxv.user,
        password=cfg.CONF.nsxv.password,
        ca_file=cfg.CONF.nsxv.ca_file,
        insecure=cfg.CONF.nsxv.insecure)


def get_plugin_filters(context):
    return admin_utils.get_plugin_filters(
        context, projectpluginmap.NsxPlugins.NSX_V)


class NeutronDbClient(object):
    def __init__(self):
        super(NeutronDbClient, self)
        self.context = neutron_context.get_admin_context()


class NsxVPluginWrapper(plugin.NsxVPlugin):

    def _ensure_ca_file(self):
        # Ensure CA file is used if /etc/ssl/certs/vcenter.pem exists
        # otherwise secure connection to vcenter will fail
        if not cfg.CONF.dvs.ca_file:
            ca_file_default = "/etc/ssl/certs/vcenter.pem"
            if os.path.isfile(ca_file_default):
                LOG.info("ca_file for vCenter unset, defaulting to: %s",
                        ca_file_default)
                cfg.CONF.set_override('ca_file', ca_file_default, 'dvs')

    def __init__(self):
        config.register_nsxv_azs(cfg.CONF, cfg.CONF.nsxv.availability_zones)
        self.context = neutron_context.get_admin_context()
        self.filters = get_plugin_filters(self.context)
        self._ensure_ca_file()
        super(NsxVPluginWrapper, self).__init__()
        # Make this the core plugin
        directory.add_plugin('CORE', self)
        # finish the plugin initialization
        # (with md-proxy config, but without housekeeping)
        with mock.patch("vmware_nsx.plugins.common.housekeeper."
                        "housekeeper.NsxHousekeeper"):
            self.init_complete(0, 0, 0)
        admin_utils._init_plugin_mock_quota()

    def start_rpc_listeners(self):
        pass

    def _extend_get_network_dict_provider(self, context, net):
        self._extend_network_dict_provider(context, net)
        # skip getting the Qos policy ID because get_object calls
        # plugin init again on admin-util environment

    def count_spawn_jobs(self):
        # check if there are any spawn jobs running
        return self.edge_manager._get_worker_pool().running()

    # Define enter & exit to be used in with statements
    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        """Wait until no more jobs are pending

        We want to wait until all spawn edge creation are done, or else the
        edges might be in PERNDING_CREATE state in the nsx DB
        """
        if not self.count_spawn_jobs():
            return

        LOG.warning("Waiting for plugin jobs to finish properly...")
        sleep_time = 1
        print_time = 20
        max_loop = 600
        for print_index in range(1, max_loop):
            n_jobs = self.count_spawn_jobs()
            if n_jobs > 0:
                if (print_index % print_time) == 0:
                    LOG.warning("Still Waiting on %(jobs)s "
                                "job%(plural)s",
                                {'jobs': n_jobs,
                                 'plural': 's' if n_jobs > 1 else ''})
                time.sleep(sleep_time)
            else:
                LOG.warning("Done.")
                return

        LOG.warning("Sorry. Waited for too long. Some jobs are still "
                    "running.")

    def _update_filters(self, requested_filters):
        filters = self.filters.copy()
        if requested_filters:
            filters.update(requested_filters)
        return filters

    def get_networks(self, context, filters=None, fields=None,
                     filter_project=True):
        if filter_project:
            filters = self._update_filters(filters)
        return super(NsxVPluginWrapper, self).get_networks(
            context, filters=filters, fields=fields)

    def get_subnets(self, context, filters=None, fields=None,
                    filter_project=True):
        if filter_project:
            filters = self._update_filters(filters)
        return super(NsxVPluginWrapper, self).get_subnets(
            context, filters=filters, fields=fields)

    def get_ports(self, context, filters=None, fields=None,
                  filter_project=True):
        if filter_project:
            filters = self._update_filters(filters)
        return super(NsxVPluginWrapper, self).get_ports(
            context, filters=filters, fields=fields)

    def get_routers(self, context, filters=None, fields=None,
                    filter_project=True):
        if filter_project:
            filters = self._update_filters(filters)
        return super(NsxVPluginWrapper, self).get_routers(
            context, filters=filters, fields=fields)


def get_nsxv_backend_edges():
    """Get a list of all the backend edges and some of their attributes
    """
    nsxv = get_nsxv_client()
    edges = nsxv.get_edges()
    backend_edges = []
    for edge in edges:
        summary = edge.get('appliancesSummary')
        size = ha = None
        if summary:
            size = summary.get('applianceSize')
            deployed_vms = summary.get('numberOfDeployedVms', 1)
            ha = 'Enabled' if deployed_vms > 1 else 'Disabled'
        # get all the relevant backend information for this edge
        edge_data = {
            'id': edge.get('id'),
            'name': edge.get('name'),
            'size': size,
            'type': edge.get('edgeType'),
            'ha': ha,
        }
        backend_edges.append(edge_data)
    return backend_edges


def get_edge_syslog_info(edge_id):
    """Get syslog information for specific edge id"""

    nsxv = get_nsxv_client()
    syslog_info = nsxv.get_edge_syslog(edge_id)[1]
    if not syslog_info['enabled']:
        return 'Disabled'

    output = ""
    if 'protocol' in syslog_info:
        output += syslog_info['protocol']
    if 'serverAddresses' in syslog_info:
        for server_address in syslog_info['serverAddresses']['ipAddress']:
            output += "\n" + server_address

    return output


def get_networks_from_backend():
    nsxv = get_nsxv_client()
    so_list = nsxv.get_scoping_objects()
    return et.fromstring(so_list)


def get_networks():
    """Create an array of all the backend networks and their data
    """
    root = get_networks_from_backend()
    networks = []
    for obj in root.iter('object'):
        if obj.find('objectTypeName').text in network_types:
            networks.append({'type': obj.find('objectTypeName').text,
                             'moref': obj.find('objectId').text,
                             'name': obj.find('name').text})
    return networks


def get_orphaned_networks(backend_networks):
    """List the NSX networks which are missing the neutron DB
    """
    admin_context = neutron_context.get_admin_context()
    missing_networks = []

    # get all neutron distributed routers in advanced
    with NsxVPluginWrapper() as plugin:
        neutron_routers = plugin.get_routers(
            admin_context, fields=['id', 'name', 'distributed'])
        neutron_dist_routers = [rtr for rtr in neutron_routers
                                if rtr['distributed']]

    # get the list of backend networks:
    for net in backend_networks:
        moref = net['moref']
        backend_name = net['name']
        # Decide if this is a neutron network by its name (which should always
        # contain the net-id), and type
        if (backend_name.startswith('edge-') or len(backend_name) < 36 or
            net['type'] == 'Network'):
            # This is not a neutron network
            continue
        if backend_name.startswith('int-') and net['type'] == 'VirtualWire':
            # This is a PLR network. Check that the router exists
            found = False
            # compare the expected lswitch name by the dist router name & id
            for rtr in neutron_dist_routers:
                lswitch_name = ('int-' + rtr['name'] + rtr['id'])[:36]
                if lswitch_name == backend_name:
                    found = True
                    break
            # if the neutron router got renamed, this will not work.
            # compare ids prefixes instead (might cause false positives)
            for rtr in neutron_dist_routers:
                if rtr['id'][:5] in backend_name:
                    LOG.info("Logical switch %s probably matches distributed "
                             "router %s", backend_name, rtr['id'])
                    found = True
                    break
            if not found:
                missing_networks.append(net)
            continue

        # get the list of neutron networks with this moref
        neutron_networks = nsx_db.get_nsx_network_mapping_for_nsx_id(
            admin_context.session, moref)
        if not neutron_networks:
            # no network found for this moref
            missing_networks.append(net)

        elif moref.startswith(PORTGROUP_PREFIX):
            # This is a VLAN network. Also verify that the DVS Id matches
            for entry in neutron_networks:
                if (not entry['dvs_id'] or
                    backend_name.startswith(entry['dvs_id'])):
                    found = True
            # this moref & dvs-id does not appear in the DB
            if not found:
                missing_networks.append(net)
    return missing_networks


def get_router_edge_bindings():
    edgeapi = NeutronDbClient()
    return nsxv_db.get_nsxv_router_bindings(edgeapi.context)


def get_orphaned_edges_data():
    nsxv_edges = get_nsxv_backend_edges()
    neutron_edge_bindings = set()
    for binding in get_router_edge_bindings():
        neutron_edge_bindings.add(binding.edge_id)

    return [edge for edge in nsxv_edges
            if edge['id'] not in neutron_edge_bindings]


def get_orphaned_edges():
    return [edge['id'] for edge in get_orphaned_edges_data()]
