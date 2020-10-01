# Copyright 2016 VMware, Inc.  All rights reserved.
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

import logging

from oslo_config import cfg

from neutron.db import db_base_plugin_v2
from neutron.db import l3_dvr_db  # noqa
from neutron import manager
from neutron_lib import context
from neutron_lib.plugins import constants as const
from neutron_lib.plugins import directory

from vmware_nsx.common import config
from vmware_nsx.db import db as nsx_db
from vmware_nsx.extensions import projectpluginmap
from vmware_nsx.plugins.common_v3 import utils as v3_utils
from vmware_nsx.plugins.nsx_v3 import plugin
from vmware_nsx.services.fwaas.nsx_v3 import fwaas_callbacks_v2
from vmware_nsx.shell.admin.plugins.common import utils as admin_utils
from vmware_nsxlib.v3 import nsx_constants

_NSXLIB = None


def get_nsxv3_client(nsx_username=None, nsx_password=None,
                     use_basic_auth=False,
                     plugin_conf=None):

    return get_connected_nsxlib(nsx_username,
                                nsx_password,
                                use_basic_auth,
                                plugin_conf).client


def reset_global_nsxlib():
    global _NSXLIB
    _NSXLIB = None


def get_connected_nsxlib(nsx_username=None, nsx_password=None,
                         use_basic_auth=False,
                         plugin_conf=None,
                         allow_overwrite_header=False,
                         retriable_exceptions=None,
                         verbose=False):
    global _NSXLIB

    if not verbose:
        # Suppress logs for nsxlib init
        logging.disable(logging.INFO)

    # for non-default arguments, initiate new lib
    if nsx_username or use_basic_auth:
        if not verbose:
            # Return logs to normal
            logging.disable(logging.NOTSET)
        return v3_utils.get_nsxlib_wrapper(
            nsx_username, nsx_password, use_basic_auth,
            plugin_conf=plugin_conf,
            retriable_exceptions=retriable_exceptions,
            allow_overwrite_header=allow_overwrite_header)

    if _NSXLIB is None:
        _NSXLIB = v3_utils.get_nsxlib_wrapper(
            plugin_conf=plugin_conf,
            allow_overwrite_header=allow_overwrite_header,
            retriable_exceptions=retriable_exceptions)

    if not verbose:
        # Return logs to normal
        logging.disable(logging.NOTSET)
    return _NSXLIB


def get_plugin_filters(ctx):
    return admin_utils.get_plugin_filters(
        ctx, projectpluginmap.NsxPlugins.NSX_T)


class NeutronDbClient(db_base_plugin_v2.NeutronDbPluginV2):
    def __init__(self):
        super(NeutronDbClient, self).__init__()
        self.context = context.get_admin_context()
        self.filters = get_plugin_filters(self.context)

    def _update_filters(self, requested_filters):
        filters = self.filters.copy()
        if requested_filters:
            filters.update(requested_filters)
        return filters

    def get_ports(self, filters=None, fields=None):
        filters = self._update_filters(filters)
        return super(NeutronDbClient, self).get_ports(
            self.context, filters=filters, fields=fields)

    def get_networks(self, filters=None, fields=None):
        filters = self._update_filters(filters)
        return super(NeutronDbClient, self).get_networks(
            self.context, filters=filters, fields=fields)

    def get_network(self, ctx, network_id):
        if not ctx:
            ctx = self.context
        return super(NeutronDbClient, self).get_network(ctx, network_id)

    def get_subnet(self, ctx, subnet_id):
        if not ctx:
            ctx = self.context
        return super(NeutronDbClient, self).get_subnet(ctx, subnet_id)

    def get_lswitch_and_lport_id(self, port_id):
        return nsx_db.get_nsx_switch_and_port_id(self.context.session, port_id)

    def net_id_to_lswitch_id(self, net_id):
        lswitch_ids = nsx_db.get_nsx_switch_ids(self.context.session, net_id)
        return lswitch_ids[0] if lswitch_ids else None

    def add_dhcp_service_binding(self, network_id, port_id, server_id):
        return nsx_db.add_neutron_nsx_service_binding(
            self.context.session, network_id, port_id,
            nsx_constants.SERVICE_DHCP, server_id)

    def add_dhcp_static_binding(self, port_id, subnet_id, ip_address,
                                server_id, binding_id):
        return nsx_db.add_neutron_nsx_dhcp_binding(
            self.context.session, port_id, subnet_id, ip_address, server_id,
            binding_id)


class NsxV3PluginWrapper(plugin.NsxV3Plugin):
    def __init__(self, verbose=False):
        if not verbose:
            # Suppress logs for plugin init
            logging.disable(logging.INFO)

        # initialize the availability zones
        config.register_nsxv3_azs(cfg.CONF, cfg.CONF.nsx_v3.availability_zones)
        super(NsxV3PluginWrapper, self).__init__()
        self.context = context.get_admin_context()
        admin_utils._init_plugin_mock_quota()

        if not verbose:
            # Return logs to normal
            logging.disable(logging.NOTSET)

    def __enter__(self):
        directory.add_plugin(const.CORE, self)
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        directory.add_plugin(const.CORE, None)

    def _cleanup_duplicates(self, ns_group_id, section_id):
        # Do not remove DFW sections during dummy plugin initialization
        pass

    def _init_fwaas_plugin(self, provider, callbacks_class, plugin_callbacks):
        fwaas_plugin_class = manager.NeutronManager.load_class_for_provider(
            'neutron.service_plugins', provider)
        fwaas_plugin = fwaas_plugin_class()
        self.fwaas_callbacks = callbacks_class(False)
        # override the fwplugin_rpc since there is no RPC support in adminutils
        if plugin_callbacks:
            self.fwaas_callbacks.fwplugin_rpc = plugin_callbacks(fwaas_plugin)
        self.init_is_complete = True

    def init_fwaas_for_admin_utils(self):
        # initialize the FWaaS plugin and callbacks
        self.fwaas_callbacks = None
        # This is an ugly patch to find out if it is v1 or v2
        service_plugins = cfg.CONF.service_plugins
        for srv_plugin in service_plugins:
            if 'firewall' in srv_plugin or 'fwaas' in srv_plugin:
                if 'v2' in srv_plugin:
                    # FWaaS V2
                    self._init_fwaas_plugin(
                        'firewall_v2',
                        fwaas_callbacks_v2.Nsxv3FwaasCallbacksV2,
                        None)
                return

    def _init_dhcp_metadata(self):
        pass

    def _extend_get_network_dict_provider(self, ctx, net):
        self._extend_network_dict_provider(ctx, net)
        # skip getting the Qos policy ID because get_object calls
        # plugin init again on admin-util environment

    def _extend_get_port_dict_binding(self, ctx, port):
        self._extend_port_dict_binding(ctx, port)
        # skip getting the Qos policy ID because get_object calls
        # plugin init again on admin-util environment

    def delete_network(self, ctx, network_id):
        if not ctx:
            ctx = self.context
        return super(NsxV3PluginWrapper, self).delete_network(
            ctx, network_id)

    def remove_router_interface(self, ctx, router_id, interface):
        if not ctx:
            ctx = self.context
        return super(NsxV3PluginWrapper, self).remove_router_interface(
            ctx, router_id, interface)
