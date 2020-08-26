# Copyright 2018 VMware, Inc.
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

import copy

from neutron_lib import exceptions as n_exc
from oslo_log import log as logging
from oslo_utils import excutils

from vmware_nsx._i18n import _
from vmware_nsx.services.lbaas import base_mgr
from vmware_nsx.services.lbaas import lb_common
from vmware_nsx.services.lbaas import lb_const
from vmware_nsx.services.lbaas.nsx_p.implementation import lb_utils
from vmware_nsxlib.v3 import exceptions as nsxlib_exc
from vmware_nsxlib.v3.policy import core_resources
from vmware_nsxlib.v3.policy import lb_defs
from vmware_nsxlib.v3.policy import utils as p_utils
from vmware_nsxlib.v3 import utils

LOG = logging.getLogger(__name__)


class EdgeListenerManagerFromDict(base_mgr.NsxpLoadbalancerBaseManager):
    def _get_listener_tags(self, context, listener):
        tags = lb_utils.get_tags(self.core_plugin, listener['id'],
                                 lb_const.LB_LISTENER_TYPE,
                                 listener.get('tenant_id'),
                                 context.project_name)
        if listener['loadbalancer'].get('name'):
            tags.append({
                'scope': lb_const.LB_LB_NAME,
                'tag': listener['loadbalancer']['name'][:utils.MAX_TAG_LEN]})
        tags.append({
            'scope': lb_const.LB_LB_TYPE,
            'tag': listener['loadbalancer_id']})
        return tags

    def _upload_certificate(self, listener_id, cert_href, tags,
                            certificate):
        nsxpolicy = self.core_plugin.nsxpolicy
        cert_client = nsxpolicy.certificate
        ssl_client = nsxpolicy.load_balancer.client_ssl_profile

        # check if this certificate was already uploaded
        cert_ids = cert_client.find_cert_with_pem(
            certificate.get('certificate'))
        if cert_ids:
            nsx_cert_id = cert_ids[0]
        else:
            # Create it with a random id as this might not be the first one
            passphrase = certificate.get('passphrase')
            if not passphrase:
                passphrase = core_resources.IGNORE
            nsx_cert_id = cert_client.create_or_overwrite(
                cert_href,
                pem_encoded=certificate.get('certificate'),
                private_key=certificate.get('private_key'),
                passphrase=passphrase,
                tags=tags)

        return {
            'client_ssl_profile_binding': {
                'ssl_profile_path': ssl_client.get_path(
                    self.core_plugin.client_ssl_profile),
                'default_certificate_path': cert_client.get_path(nsx_cert_id)
            }
        }

    def _get_virtual_server_kwargs(self, context, listener, vs_name, tags,
                                   certificate=None):
        # If loadbalancer vip_port already has floating ip, use floating
        # IP as the virtual server VIP address. Else, use the loadbalancer
        # vip_address directly on virtual server.
        filters = {'port_id': [listener['loadbalancer']['vip_port_id']]}
        floating_ips = self.core_plugin.get_floatingips(context,
                                                        filters=filters)
        if floating_ips:
            lb_vip_address = floating_ips[0]['floating_ip_address']
        else:
            lb_vip_address = listener['loadbalancer']['vip_address']
        lb_service = lb_utils.get_lb_nsx_lb_service(
            self.core_plugin.nsxpolicy, listener['loadbalancer_id'])

        kwargs = {'virtual_server_id': listener['id'],
                  'ip_address': lb_vip_address,
                  'ports': [listener['protocol_port']],
                  'application_profile_id': listener['id'],
                  'lb_service_id': lb_service['id'],
                  'description': listener.get('description')}
        if vs_name:
            kwargs['name'] = vs_name
        if tags:
            kwargs['tags'] = tags
        if listener['connection_limit'] != -1:
            kwargs['max_concurrent_connections'] = listener['connection_limit']
        if 'default_pool_id' in listener:
            if listener['default_pool_id']:
                kwargs['pool_id'] = listener['default_pool_id']
            else:
                # Remove the default pool
                kwargs['pool_id'] = ''
                kwargs['lb_persistence_profile_id'] = ''
        if certificate:
            ssl_profile_binding = self._upload_certificate(
                listener['id'], certificate['ref'], tags,
                certificate=certificate)
            if (listener['protocol'] ==
                    lb_const.LB_PROTOCOL_TERMINATED_HTTPS and
                    ssl_profile_binding):
                kwargs.update(ssl_profile_binding)

        waf_profile, mode = self.core_plugin.get_waf_profile_path_and_mode()
        if (waf_profile and (
            listener['protocol'] == lb_const.LB_PROTOCOL_HTTP or
            listener['protocol'] == lb_const.LB_PROTOCOL_TERMINATED_HTTPS)):
            kwargs['waf_profile_binding'] = lb_defs.WAFProfileBindingDef(
                waf_profile_path=waf_profile,
                operational_mode=mode)

        return kwargs

    def _get_nsxlib_app_profile(self, nsxlib_lb, listener):
        if (listener['protocol'] == lb_const.LB_PROTOCOL_HTTP or
                listener['protocol'] == lb_const.LB_PROTOCOL_TERMINATED_HTTPS):
            app_client = nsxlib_lb.lb_http_profile
        elif (listener['protocol'] == lb_const.LB_PROTOCOL_TCP or
              listener['protocol'] == lb_const.LB_PROTOCOL_HTTPS):
            app_client = nsxlib_lb.lb_fast_tcp_profile
        else:
            msg = (_('Cannot create listener %(listener)s with '
                     'protocol %(protocol)s') %
                   {'listener': listener['id'],
                    'protocol': listener['protocol']})
            raise n_exc.BadRequest(resource='lbaas-listener', msg=msg)

        return app_client

    def _validate_default_pool(self, listener, completor):
        def_pool_id = listener.get('default_pool_id')
        if def_pool_id:
            vs_client = self.core_plugin.nsxpolicy.load_balancer.virtual_server
            vs_list = vs_client.list()
            for vs in vs_list:
                if vs.get('id') == listener['id']:
                    continue
                pool_id = p_utils.path_to_id(vs.get('pool_path', ''))
                if pool_id == def_pool_id:
                    completor(success=False)
                    msg = (_('Default pool %s is already used by another '
                             'listener %s') % (def_pool_id, vs.get('id')))
                    raise n_exc.BadRequest(resource='lbaas-pool', msg=msg)

            lb_common.validate_session_persistence(
                listener.get('default_pool'), listener, completor)

    def create(self, context, listener, completor, certificate=None):
        nsxlib_lb = self.core_plugin.nsxpolicy.load_balancer
        vs_client = nsxlib_lb.virtual_server
        vs_name = utils.get_name_and_uuid(listener['name'] or 'listener',
                                          listener['id'])
        tags = self._get_listener_tags(context, listener)
        self._validate_default_pool(listener, completor)
        try:
            app_client = self._get_nsxlib_app_profile(nsxlib_lb, listener)
            app_client.create_or_overwrite(
                lb_app_profile_id=listener['id'], name=vs_name, tags=tags)
            kwargs = self._get_virtual_server_kwargs(
                context, listener, vs_name, tags, certificate)
            vs_client.create_or_overwrite(**kwargs)
        except nsxlib_exc.ManagerError:
            completor(success=False)
            msg = _('Failed to create virtual server at NSX backend')
            raise n_exc.BadRequest(resource='lbaas-listener', msg=msg)

        self._update_default_pool(context, listener, completor)

        completor(success=True)

    def _get_pool_tags(self, context, pool, listener_tenant_id):
        return lb_utils.get_tags(self.core_plugin, pool['id'],
                                 lb_const.LB_POOL_TYPE,
                                 pool.get('tenant_id', listener_tenant_id),
                                 context.project_name)

    def _update_default_pool(self, context, listener,
                             completor, old_listener=None):
        if not listener.get('default_pool_id'):
            return
        nsxlib_lb = self.core_plugin.nsxpolicy.load_balancer
        vs_client = nsxlib_lb.virtual_server
        vs_data = vs_client.get(listener['id'])
        pool_id = listener['default_pool_id']
        pool = listener['default_pool']
        old_pool = None
        if old_listener:
            old_pool = old_listener.get('default_pool')
        try:
            switch_type = lb_common.session_persistence_type_changed(
                pool, old_pool)
            (persistence_profile_id,
             post_process_func) = lb_utils.setup_session_persistence(
                self.core_plugin.nsxpolicy,
                pool,
                self._get_pool_tags(context, pool, listener.get('tenant_id')),
                switch_type, listener, vs_data)
        except nsxlib_exc.ManagerError:
            with excutils.save_and_reraise_exception():
                completor(success=False)
                LOG.error("Failed to configure session persistence "
                          "profile for listener %s", listener['id'])
        try:
            # Update persistence profile and pool on virtual server
            vs_client.update(
                listener['id'],
                pool_id=pool_id,
                lb_persistence_profile_id=persistence_profile_id)
            LOG.debug("Updated NSX virtual server %(vs_id)s with "
                      "persistence profile %(prof)s",
                      {'vs_id': listener['id'],
                       'prof': persistence_profile_id})
            if post_process_func:
                post_process_func()
        except nsxlib_exc.ManagerError:
            with excutils.save_and_reraise_exception():
                completor(success=False)
                LOG.error("Failed to attach persistence profile %s to "
                          "virtual server %s",
                          persistence_profile_id, listener['id'])

    def update(self, context, old_listener, new_listener, completor,
               certificate=None):
        nsxlib_lb = self.core_plugin.nsxpolicy.load_balancer
        vs_client = nsxlib_lb.virtual_server
        app_client = self._get_nsxlib_app_profile(nsxlib_lb, old_listener)

        vs_name = None
        self._validate_default_pool(new_listener, completor)

        if new_listener['name'] != old_listener['name']:
            vs_name = utils.get_name_and_uuid(
                new_listener['name'] or 'listener',
                new_listener['id'])
        tags = self._get_listener_tags(context, new_listener)

        try:
            app_profile_id = new_listener['id']
            updated_kwargs = self._get_virtual_server_kwargs(
                context, new_listener, vs_name, tags, certificate)
            vs_client.update(**updated_kwargs)
            if vs_name:
                app_client.update(app_profile_id, name=vs_name,
                                  tags=tags)
        except Exception as e:
            with excutils.save_and_reraise_exception():
                completor(success=False)
                LOG.error('Failed to update listener %(listener)s with '
                          'error %(error)s',
                          {'listener': old_listener['id'], 'error': e})

        # Update default pool and session persistence
        if (old_listener.get('default_pool_id') !=
            new_listener.get('default_pool_id')):
            self._update_default_pool(context, new_listener,
                                      completor, old_listener)
        completor(success=True)

    def delete(self, context, listener, completor):
        nsxlib_lb = self.core_plugin.nsxpolicy.load_balancer
        vs_client = nsxlib_lb.virtual_server
        app_client = self._get_nsxlib_app_profile(nsxlib_lb, listener)

        vs_id = listener['id']
        app_profile_id = listener['id']

        try:
            profile_path = None
            if listener.get('default_pool_id'):
                vs_data = vs_client.get(vs_id)
                profile_path = vs_data.get('lb_persistence_profile_path', '')
            vs_client.delete(vs_id)
            # Also delete the old session persistence profile
            if profile_path:
                lb_utils.delete_persistence_profile(
                    self.core_plugin.nsxpolicy, profile_path)
        except nsxlib_exc.ResourceNotFound:
            LOG.error("virtual server not found on nsx: %(vs)s", {'vs': vs_id})
        except nsxlib_exc.ManagerError:
            completor(success=False)
            msg = (_('Failed to delete virtual server: %(vs)s') %
                   {'vs': vs_id})
            raise n_exc.BadRequest(resource='lbaas-listener', msg=msg)

        try:
            app_client.delete(app_profile_id)
        except nsxlib_exc.ResourceNotFound:
            LOG.error("application profile not found on nsx: %s",
                      app_profile_id)
        except nsxlib_exc.ManagerError as e:
            # This probably means that the application profile is being
            # used by a listener outside of openstack
            LOG.error("Failed to delete application profile %s from the "
                      "NSX: %s", app_profile_id, e)

        # Delete imported NSX certificates if there is any
        cert_client = self.core_plugin.nsxpolicy.certificate
        cert_tags = [{'scope': lb_const.LB_LISTENER_TYPE,
                      'tag': listener['id']}]
        results = self.core_plugin.nsxpolicy.search_by_tags(
            cert_tags, cert_client.entry_def.resource_type())
        for res_obj in results['results']:
            try:
                cert_client.delete(res_obj['id'])
            except nsxlib_exc.ManagerError:
                msg = (_('Failed to delete certificate: %(crt)s for '
                         'listener %(list)s') %
                       {'crt': res_obj['id'], 'list': listener['id']})
                LOG.error(msg)

        completor(success=True)

    def delete_cascade(self, context, listener, completor):
        self.delete(context, listener, completor)


def stats_getter(context, core_plugin, ignore_list=None):
    """Update Octavia statistics for each listener (virtual server)"""
    stat_list = []
    lb_service_client = core_plugin.nsxpolicy.load_balancer.lb_service

    # Since this is called periodically, silencing it at the logs
    lb_services = lb_service_client.list(silent=True)
    # Go over all the loadbalancers & services
    for lb_service in lb_services:
        if ignore_list and lb_service['id'] in ignore_list:
            continue

        lb_service_id = lb_service.get('id')
        try:
            # get the NSX statistics for this LB service
            stats_results = lb_service_client.get_statistics(
                lb_service_id, silent=True).get('results', [])
            if stats_results:
                rsp = stats_results[0]
            else:
                rsp = {}

            # Go over each virtual server in the response
            for vs in rsp.get('virtual_servers', []):
                # look up the virtual server in the DB
                if vs.get('statistics'):
                    vs_stats = vs['statistics']
                    stats = copy.copy(lb_const.LB_EMPTY_STATS)
                    stats['id'] = p_utils.path_to_id(
                        vs['virtual_server_path'])
                    stats['request_errors'] = 0  # currently unsupported
                    for stat in lb_const.LB_STATS_MAP:
                        lb_stat = lb_const.LB_STATS_MAP[stat]
                        stats[stat] += vs_stats[lb_stat]
                    stat_list.append(stats)

        except nsxlib_exc.ManagerError:
            pass

    return stat_list
