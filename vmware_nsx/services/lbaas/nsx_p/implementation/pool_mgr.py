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

import functools

from neutron_lib import exceptions as n_exc
from oslo_log import log as logging
from oslo_utils import excutils

from vmware_nsx._i18n import _
from vmware_nsx.services.lbaas import base_mgr
from vmware_nsx.services.lbaas import lb_common
from vmware_nsx.services.lbaas import lb_const
from vmware_nsx.services.lbaas.nsx_p.implementation import lb_utils
from vmware_nsxlib.v3 import exceptions as nsxlib_exc
from vmware_nsxlib.v3 import utils

LOG = logging.getLogger(__name__)


class EdgePoolManagerFromDict(base_mgr.NsxpLoadbalancerBaseManager):
    def _get_pool_kwargs(self, name=None, tags=None, algorithm=None,
                         description=None):
        kwargs = {
            'snat_translation': {'type': "LBSnatAutoMap"}}
        if name:
            kwargs['name'] = name
        if tags:
            kwargs['tags'] = tags
        if algorithm:
            kwargs['algorithm'] = algorithm
        if description:
            kwargs['description'] = description
        return kwargs

    def _get_pool_tags(self, context, pool):
        return lb_utils.get_tags(self.core_plugin, pool['id'],
                                 lb_const.LB_POOL_TYPE, pool['tenant_id'],
                                 context.project_name)

    def _remove_persistence(self, vs_data):
        lb_utils.delete_persistence_profile(
            self.core_plugin.nsxpolicy,
            vs_data.get('lb_persistence_profile_path', ''))

    def _process_vs_update(self, context, pool, pool_id, switch_type,
                           listener, completor):
        vs_client = self.core_plugin.nsxpolicy.load_balancer.virtual_server
        try:
            # Process pool persistence profile and
            # create/update/delete profile for virtual server
            vs_data = vs_client.get(listener['id'])
            if pool and pool_id:
                (persistence_profile_id,
                 post_process_func) = lb_utils.setup_session_persistence(
                    self.core_plugin.nsxpolicy, pool,
                    self._get_pool_tags(context, pool),
                    switch_type, listener, vs_data)
            else:
                post_process_func = functools.partial(
                    self._remove_persistence, vs_data)
                persistence_profile_id = None
        except nsxlib_exc.ManagerError:
            with excutils.save_and_reraise_exception():
                completor(success=False)
                LOG.error("Failed to configure session persistence "
                          "profile for pool %(pool_id)s",
                          {'pool_id': pool['id']})
        try:
            # Update persistence profile and pool on virtual server
            vs_client.update(
                listener['id'],
                pool_id=pool_id,
                lb_persistence_profile_id=persistence_profile_id)

            LOG.debug("Updated NSX virtual server %(vs_id)s with "
                      "pool %(pool_id)s and persistence profile %(prof)s",
                      {'vs_id': listener['id'], 'pool_id': pool['id'],
                       'prof': persistence_profile_id})
            if post_process_func:
                post_process_func()
        except nsxlib_exc.ManagerError:
            with excutils.save_and_reraise_exception():
                completor(success=False)
                LOG.error('Failed to attach pool %s to virtual '
                          'server %s', pool['id'], listener['id'])

    def create(self, context, pool, completor):
        pool_client = self.core_plugin.nsxpolicy.load_balancer.lb_pool

        pool_name = utils.get_name_and_uuid(pool['name'] or 'pool', pool['id'])
        tags = self._get_pool_tags(context, pool)

        description = pool.get('description')
        lb_algorithm = lb_const.LB_POOL_ALGORITHM_MAP.get(pool['lb_algorithm'])

        if pool.get('listeners') and len(pool['listeners']) > 1:
            completor(success=False)
            msg = (_('Failed to create pool: Multiple listeners are not '
                     'supported.'))
            raise n_exc.BadRequest(resource='lbaas-pool', msg=msg)

        # NOTE(salv-orlando): Guard against accidental compat breakages
        try:
            listener = pool['listener'] or pool['listeners'][0]
        except IndexError:
            # If listeners is an empty list we hit this exception
            listener = None
        # Perform additional validation for session persistence before
        # creating resources in the backend
        lb_common.validate_session_persistence(pool, listener, completor)
        try:
            kwargs = self._get_pool_kwargs(
                pool_name, tags, lb_algorithm, description)
            pool_client.create_or_overwrite(lb_pool_id=pool['id'], **kwargs)
        except nsxlib_exc.ManagerError:
            completor(success=False)
            msg = (_('Failed to create pool on NSX backend: %(pool)s') %
                   {'pool': pool['id']})
            raise n_exc.BadRequest(resource='lbaas-pool', msg=msg)

        # The pool object can be created with either --listener or
        # --loadbalancer option. If listener is present, the virtual server
        # will be updated with the pool. Otherwise, just return. The binding
        # will be added later when the pool is associated with layer7 rule.
        # FIXME(salv-orlando): This two-step process can leave a zombie pool on
        # NSX if the VS update operation fails
        if listener:
            self._process_vs_update(context, pool, pool['id'], False,
                                    listener, completor)
        completor(success=True)

    def update(self, context, old_pool, new_pool, completor):
        pool_client = self.core_plugin.nsxpolicy.load_balancer.lb_pool

        pool_name = None
        tags = None
        lb_algorithm = None
        description = None
        if new_pool.get('listeners') and len(new_pool['listeners']) > 1:
            completor(success=False)
            msg = (_('Failed to update pool %s: Multiple listeners are not '
                     'supported.') % new_pool['id'])
            raise n_exc.BadRequest(resource='lbaas-pool', msg=msg)

        if new_pool['name'] != old_pool['name']:
            pool_name = utils.get_name_and_uuid(new_pool['name'] or 'pool',
                                                new_pool['id'])
            tags = self._get_pool_tags(context, new_pool)
        if new_pool['lb_algorithm'] != old_pool['lb_algorithm']:
            lb_algorithm = lb_const.LB_POOL_ALGORITHM_MAP.get(
                new_pool['lb_algorithm'])
        if new_pool.get('description') != old_pool.get('description'):
            description = new_pool['description']
        # NOTE(salv-orlando): Guard against accidental compat breakages
        try:
            listener = new_pool['listener'] or new_pool['listeners'][0]
        except IndexError:
            # If listeners is an empty list we hit this exception
            listener = None
            # Perform additional validation for session persistence before
            # operating on resources in the backend
        lb_common.validate_session_persistence(new_pool, listener, completor)
        try:
            kwargs = self._get_pool_kwargs(pool_name, tags, lb_algorithm,
                                           description)
            pool_client.update(lb_pool_id=new_pool['id'], **kwargs)
            if (listener and new_pool['session_persistence'] !=
                old_pool['session_persistence']):
                switch_type = lb_common.session_persistence_type_changed(
                    new_pool, old_pool)
                self._process_vs_update(context, new_pool, new_pool['id'],
                                        switch_type, listener, completor)
            completor(success=True)
        except Exception as e:
            with excutils.save_and_reraise_exception():
                completor(success=False)
                LOG.error('Failed to update pool %(pool)s with '
                          'error %(error)s',
                          {'pool': old_pool['id'], 'error': e})

    def delete(self, context, pool, completor):
        pool_client = self.core_plugin.nsxpolicy.load_balancer.lb_pool

        # NOTE(salv-orlando): Guard against accidental compat breakages
        try:
            listener = pool.get('listener') or pool.get('listeners', [])[0]
        except IndexError:
            # If listeners is an empty list we hit this exception
            listener = None
        if listener:
            try:
                self._process_vs_update(
                    context, pool, None, False, listener, completor)
            except Exception as e:
                LOG.error('Disassociation of listener %(lsn)s from pool '
                          '%(pool)s failed with error %(err)s',
                          {'lsn': listener['id'],
                           'pool': pool['id'],
                           'err': e})
        try:
            pool_client.delete(pool['id'])
        except nsxlib_exc.ResourceNotFound:
            pass
        except nsxlib_exc.ManagerError:
            completor(success=False)
            msg = (_('Failed to delete lb pool from nsx: %(pool)s') %
                   {'pool': pool['id']})
            raise n_exc.BadRequest(resource='lbaas-pool', msg=msg)

        # Delete the attached health monitor as well
        if pool.get('healthmonitor'):
            hm = pool['healthmonitor']
            monitor_client = lb_utils.get_monitor_policy_client(
                self.core_plugin.nsxpolicy.load_balancer, hm)

            try:
                monitor_client.delete(hm['id'])
            except nsxlib_exc.ResourceNotFound:
                pass
            except nsxlib_exc.ManagerError as exc:
                completor(success=False)
                msg = _('Failed to delete monitor %(monitor)s from backend '
                        'with exception %(exc)s') % {'monitor': hm['id'],
                                                     'exc': exc}
                raise n_exc.BadRequest(resource='lbaas-pool', msg=msg)

        completor(success=True)

    def delete_cascade(self, context, pool, completor):
        self.delete(context, pool, completor)
