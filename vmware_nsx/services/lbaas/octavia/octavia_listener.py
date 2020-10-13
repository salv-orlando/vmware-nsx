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

import socket
import time

import eventlet

from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants as n_consts
from neutron_lib import context as neutron_context
from neutron_lib import exceptions as n_exc
from oslo_config import cfg
from oslo_log import helpers as log_helpers
from oslo_log import log as logging
import oslo_messaging as messaging
from oslo_messaging.rpc import dispatcher

from vmware_nsx.services.lbaas.octavia import constants

LOG = logging.getLogger(__name__)


class NSXOctaviaListener(object):
    @log_helpers.log_method_call
    def __init__(self, loadbalancer=None, listener=None, pool=None,
                 member=None, healthmonitor=None, l7policy=None, l7rule=None):
        self._init_rpc_messaging()
        self._init_rpc_listener(healthmonitor, l7policy, l7rule, listener,
                                loadbalancer, member, pool)

    def _init_rpc_messaging(self):
        if cfg.CONF.api_replay_mode:
            topic = constants.DRIVER_TO_OCTAVIA_MIGRATION_TOPIC
        else:
            topic = constants.DRIVER_TO_OCTAVIA_TOPIC
        transport = messaging.get_rpc_transport(cfg.CONF)
        target = messaging.Target(topic=topic, exchange="common",
                                  namespace='control', fanout=False,
                                  version='1.0')
        self.client = messaging.RPCClient(transport, target)

    def _init_rpc_listener(self, healthmonitor, l7policy, l7rule, listener,
                           loadbalancer, member, pool):
        # Initialize RPC listener
        if cfg.CONF.api_replay_mode:
            topic = constants.OCTAVIA_TO_DRIVER_MIGRATION_TOPIC
        else:
            topic = constants.OCTAVIA_TO_DRIVER_TOPIC
        server = socket.gethostname()
        transport = messaging.get_rpc_transport(cfg.CONF)
        target = messaging.Target(topic=topic, server=server,
                                  exchange="common", fanout=False)
        self.endpoints = [NSXOctaviaListenerEndpoint(
            client=self.client, loadbalancer=loadbalancer, listener=listener,
            pool=pool, member=member, healthmonitor=healthmonitor,
            l7policy=l7policy, l7rule=l7rule)]
        access_policy = dispatcher.DefaultRPCAccessPolicy
        self.octavia_server = messaging.get_rpc_server(
            transport, target, self.endpoints, executor='eventlet',
            access_policy=access_policy)
        self.octavia_server.start()


class NSXOctaviaListenerEndpoint(object):
    target = messaging.Target(namespace="control", version='1.0')

    def __init__(self, client=None, loadbalancer=None, listener=None,
                 pool=None, member=None, healthmonitor=None, l7policy=None,
                 l7rule=None):

        self.client = client
        self.loadbalancer = loadbalancer
        self.listener = listener
        self.pool = pool
        self.member = member
        self.healthmonitor = healthmonitor
        self.l7policy = l7policy
        self.l7rule = l7rule

        self._subscribe_router_delete_callback()

    def _subscribe_router_delete_callback(self):
        # Check if there is any LB attachment for the NSX router.
        # This callback is subscribed here to prevent router/GW/interface
        # deletion if it still has LB service attached to it.

        #Note(asarfaty): Those callbacks are used by Octavia as well even
        # though they are bound only here
        registry.subscribe(self._check_lb_service_on_router,
                           resources.ROUTER, events.BEFORE_DELETE)
        registry.subscribe(self._check_lb_service_on_router,
                           resources.ROUTER_GATEWAY, events.BEFORE_DELETE)
        registry.subscribe(self._check_lb_service_on_router_interface,
                           resources.ROUTER_INTERFACE, events.BEFORE_DELETE)

    def _unsubscribe_router_delete_callback(self):
        registry.unsubscribe(self._check_lb_service_on_router,
                             resources.ROUTER, events.BEFORE_DELETE)
        registry.unsubscribe(self._check_lb_service_on_router,
                             resources.ROUTER_GATEWAY, events.BEFORE_DELETE)
        registry.unsubscribe(self._check_lb_service_on_router_interface,
                             resources.ROUTER_INTERFACE, events.BEFORE_DELETE)

    def _get_core_plugin(self, context, project_id=None):
        core_plugin = self.loadbalancer.core_plugin
        if core_plugin.is_tvd_plugin():
            # get the right plugin for this project
            # (if project_id is None, the default one will be returned)
            core_plugin = core_plugin._get_plugin_from_project(
                context, project_id)
        return core_plugin

    def _get_default_core_plugin(self, context):
        return self._get_core_plugin(context, project_id=None)

    def _get_lb_ports(self, context, subnet_ids):
        dev_owner_v2 = n_consts.DEVICE_OWNER_LOADBALANCERV2
        dev_owner_oct = constants.DEVICE_OWNER_OCTAVIA
        filters = {'device_owner': [dev_owner_v2, dev_owner_oct],
                   'fixed_ips': {'subnet_id': subnet_ids}}
        core_plugin = self._get_default_core_plugin(context)
        return core_plugin.get_ports(context, filters=filters)

    def _check_lb_service_on_router(self, resource, event, trigger,
                                    payload=None):
        """Prevent removing a router GW or deleting a router used by LB"""
        router_id = payload.resource_id
        core_plugin = self.loadbalancer.core_plugin
        if core_plugin.is_tvd_plugin():
            # TVD support
            # get the default core plugin so we can get the router project
            default_core_plugin = self._get_default_core_plugin(
                payload.context)
            router = default_core_plugin.get_router(
                payload.context, router_id)
            # get the real core plugin
            core_plugin = self._get_core_plugin(
                payload.context, router['project_id'])
        if core_plugin.service_router_has_loadbalancers(
            payload.context, router_id):
            msg = _('Cannot delete a %s as it still has lb service '
                    'attachment') % resource
            raise n_exc.BadRequest(resource='lbaas-lb', msg=msg)

    def _check_lb_service_on_router_interface(
            self, resource, event, trigger, payload=None):
        # Prevent removing the interface of an LB subnet from a router
        router_id = payload.resource_id
        subnet_id = payload.metadata.get('subnet_id')
        if not router_id or not subnet_id:
            return

        # get LB ports and check if any loadbalancer is using this subnet
        if self._get_lb_ports(payload.context.elevated(), [subnet_id]):
            msg = _('Cannot delete a router interface as it used by a '
                    'loadbalancer')
            raise n_exc.BadRequest(resource='lbaas-lb', msg=msg)

    def get_completor_func(self, obj_type, obj, delete=False, cascade=False):
        # return a method that will be called on success/failure completion
        def completor_func(success=True):
            LOG.debug("Octavia transaction completed. delete %s, status %s",
                      delete, 'success' if success else 'failure')

            # calculate the provisioning and operating statuses
            main_prov_status = constants.ACTIVE
            parent_prov_status = constants.ACTIVE
            if not success:
                main_prov_status = constants.ERROR
                parent_prov_status = constants.ERROR
            elif delete:
                main_prov_status = constants.DELETED
            op_status = constants.ONLINE if success else constants.ERROR

            # add the status of the created/deleted/updated object
            status_dict = {
                obj_type: [{
                    'id': obj['id'],
                    constants.PROVISIONING_STATUS: main_prov_status,
                    constants.OPERATING_STATUS: op_status}]}

            # Get all its parents, and update their statuses as well
            loadbalancer_id = None
            listener_id = None
            pool_id = None
            policy_id = None
            if obj_type != constants.LOADBALANCERS:
                loadbalancer_id = None
                if obj.get('loadbalancer_id'):
                    loadbalancer_id = obj.get('loadbalancer_id')
                if obj.get('pool'):
                    pool_id = obj['pool']['id']
                    listener_id = obj['pool'].get('listener_id')
                    if not loadbalancer_id:
                        loadbalancer_id = obj['pool'].get('loadbalancer_id')
                elif obj.get('pool_id'):
                    pool_id = obj['pool_id']
                if obj.get('listener'):
                    listener_id = obj['listener']['id']
                    if not loadbalancer_id:
                        loadbalancer_id = obj['listener'].get(
                            'loadbalancer_id')
                elif obj.get('listener_id'):
                    listener_id = obj['listener_id']
                if obj.get('policy') and obj['policy'].get('listener'):
                    policy_id = obj['policy']['id']
                    if not listener_id:
                        listener_id = obj['policy']['listener']['id']
                        if not loadbalancer_id:
                            loadbalancer_id = obj['policy']['listener'].get(
                                'loadbalancer_id')

                if (loadbalancer_id and
                    not status_dict.get(constants.LOADBALANCERS)):
                    status_dict[constants.LOADBALANCERS] = [{
                        'id': loadbalancer_id,
                        constants.PROVISIONING_STATUS: parent_prov_status,
                        constants.OPERATING_STATUS: op_status}]
                if (listener_id and
                    not status_dict.get(constants.LISTENERS)):
                    status_dict[constants.LISTENERS] = [{
                        'id': listener_id,
                        constants.PROVISIONING_STATUS: parent_prov_status,
                        constants.OPERATING_STATUS: op_status}]
                if (pool_id and
                    not status_dict.get(constants.POOLS)):
                    status_dict[constants.POOLS] = [{
                        'id': pool_id,
                        constants.PROVISIONING_STATUS: parent_prov_status,
                        constants.OPERATING_STATUS: op_status}]
                if (policy_id and
                    not status_dict.get(constants.L7POLICIES)):
                    status_dict[constants.L7POLICIES] = [{
                        'id': policy_id,
                        constants.PROVISIONING_STATUS: parent_prov_status,
                        constants.OPERATING_STATUS: op_status}]
            elif delete and cascade:
                # add deleted status to all other objects
                status_dict[constants.LISTENERS] = []
                status_dict[constants.POOLS] = []
                status_dict[constants.MEMBERS] = []
                status_dict[constants.L7POLICIES] = []
                status_dict[constants.L7RULES] = []
                status_dict[constants.HEALTHMONITORS] = []
                for pool in obj.get('pools', []):
                    for member in pool.get('members', []):
                        status_dict[constants.MEMBERS].append(
                            {'id': member['id'],
                             constants.PROVISIONING_STATUS: constants.DELETED,
                             constants.OPERATING_STATUS: op_status})
                    if pool.get('healthmonitor'):
                        status_dict[constants.HEALTHMONITORS].append(
                            {'id': pool['healthmonitor']['id'],
                             constants.PROVISIONING_STATUS: constants.DELETED,
                             constants.OPERATING_STATUS: op_status})
                    status_dict[constants.POOLS].append(
                        {'id': pool['id'],
                         constants.PROVISIONING_STATUS: constants.DELETED,
                         constants.OPERATING_STATUS: op_status})
                for listener in obj.get('listeners', []):
                    status_dict[constants.LISTENERS].append(
                        {'id': listener['id'],
                         constants.PROVISIONING_STATUS: constants.DELETED,
                         constants.OPERATING_STATUS: op_status})
                    for policy in listener.get('l7policies', []):
                        status_dict[constants.L7POLICIES].append(
                            {'id': policy['id'],
                             constants.PROVISIONING_STATUS: constants.DELETED,
                             constants.OPERATING_STATUS: op_status})
                        for rule in policy.get('rules', []):
                            status_dict[constants.L7RULES].append(
                                {'id': rule['id'],
                                 constants.PROVISIONING_STATUS:
                                 constants.DELETED,
                                 constants.OPERATING_STATUS: op_status})

            LOG.debug("Octavia transaction completed with statuses %s",
                      status_dict)
            kw = {'status': status_dict}
            self.client.cast({}, 'update_loadbalancer_status', **kw)

        return completor_func

    def update_listener_statistics(self, statistics):
        kw = {'statistics': statistics}
        self.client.cast({}, 'update_listener_statistics', **kw)

    def update_loadbalancer_status(self, status):
        kw = {'status': status}
        self.client.cast({}, 'update_loadbalancer_status', **kw)

    @log_helpers.log_method_call
    def loadbalancer_create(self, ctxt, loadbalancer):
        ctx = neutron_context.Context(None, loadbalancer['project_id'])
        completor = self.get_completor_func(constants.LOADBALANCERS,
                                            loadbalancer)
        try:
            self.loadbalancer.create(ctx, loadbalancer, completor)
        except Exception as e:
            LOG.error('NSX driver loadbalancer_create failed %s', e)
            completor(success=False)
            return False
        return True

    @log_helpers.log_method_call
    def loadbalancer_delete_cascade(self, ctxt, loadbalancer):
        ctx = neutron_context.Context(None, loadbalancer['project_id'])

        def dummy_completor(success=True):
            pass

        completor = self.get_completor_func(constants.LOADBALANCERS,
                                            loadbalancer, delete=True)

        listener_dict = {}
        # Go over the LB tree and delete one by one using the cascade
        # api implemented for each resource
        try:
            for listener in loadbalancer.get('listeners', []):
                listener['loadbalancer'] = loadbalancer
                listener_dict[listener['id']] = listener
                for policy in listener.get('l7policies', []):
                    for rule in policy.get('rules', []):
                        self.l7rule.delete_cascade(ctx, rule, dummy_completor)
                    self.l7policy.delete_cascade(ctx, policy, dummy_completor)
                self.listener.delete_cascade(ctx, listener, dummy_completor)
            for pool in loadbalancer.get('pools', []):
                if not pool.get('loadbalancer'):
                    pool['loadbalancer'] = loadbalancer
                if pool.get('listener_id'):
                    pool['listener'] = listener_dict[pool['listener_id']]
                    pool['listeners'] = [pool['listener']]
                for member in pool.get('members', []):
                    if not member.get('pool'):
                        member['pool'] = pool
                    self.member.delete_cascade(ctx, member, dummy_completor)
                if pool.get('healthmonitor'):
                    pool['healthmonitor']['pool'] = pool
                    self.healthmonitor.delete_cascade(
                        ctx, pool['healthmonitor'], dummy_completor)
                self.pool.delete_cascade(ctx, pool, dummy_completor)
        except Exception as e:
            LOG.error('NSX driver loadbalancer_delete_cascade failed to '
                      'delete sub-object %s', e)
            completor(success=False)
            return False

        # Delete the loadbalancer itself with the completor that marks all
        # as deleted
        try:
            self.loadbalancer.delete_cascade(
                ctx, loadbalancer, self.get_completor_func(
                    constants.LOADBALANCERS,
                    loadbalancer,
                    delete=True, cascade=True))
        except Exception as e:
            LOG.error('NSX driver loadbalancer_delete_cascade failed %s', e)
            completor(success=False)
            return False
        return True

    @log_helpers.log_method_call
    def loadbalancer_delete(self, ctxt, loadbalancer, cascade=False):
        if cascade:
            return self.loadbalancer_delete_cascade(ctxt, loadbalancer)

        ctx = neutron_context.Context(None, loadbalancer['project_id'])
        completor = self.get_completor_func(constants.LOADBALANCERS,
                                            loadbalancer, delete=True)
        try:
            self.loadbalancer.delete(ctx, loadbalancer, completor)
        except Exception as e:
            LOG.error('NSX driver loadbalancer_delete failed %s', e)
            completor(success=False)
            return False
        return True

    @log_helpers.log_method_call
    def loadbalancer_update(self, ctxt, old_loadbalancer, new_loadbalancer):
        ctx = neutron_context.Context(None, old_loadbalancer['project_id'])
        completor = self.get_completor_func(constants.LOADBALANCERS,
                                            new_loadbalancer)
        try:
            self.loadbalancer.update(ctx, old_loadbalancer, new_loadbalancer,
                                     completor)
        except Exception as e:
            LOG.error('NSX driver loadbalancer_update failed %s', e)
            completor(success=False)
            return False
        return True

    # Listener
    @log_helpers.log_method_call
    def listener_create(self, ctxt, listener, cert):
        ctx = neutron_context.Context(None, listener['project_id'])
        completor = self.get_completor_func(constants.LISTENERS,
                                            listener)
        try:
            self.listener.create(ctx, listener, completor,
                                 certificate=cert)
        except Exception as e:
            LOG.error('NSX driver listener_create failed %s', e)
            completor(success=False)
            return False
        return True

    @log_helpers.log_method_call
    def listener_delete(self, ctxt, listener):
        ctx = neutron_context.Context(None, listener['project_id'])
        completor = self.get_completor_func(constants.LISTENERS,
                                            listener, delete=True)
        try:
            self.listener.delete(ctx, listener, completor)
        except Exception as e:
            LOG.error('NSX driver listener_delete failed %s', e)
            completor(success=False)
            return False
        return True

    @log_helpers.log_method_call
    def listener_update(self, ctxt, old_listener, new_listener, cert):
        ctx = neutron_context.Context(None, old_listener['project_id'])
        completor = self.get_completor_func(constants.LISTENERS,
                                            new_listener)
        try:
            self.listener.update(ctx, old_listener, new_listener,
                                 completor, certificate=cert)
        except Exception as e:
            LOG.error('NSX driver listener_update failed %s', e)
            completor(success=False)
            return False
        return True

    # Pool
    @log_helpers.log_method_call
    def pool_create(self, ctxt, pool):
        ctx = neutron_context.Context(None, pool['project_id'])
        completor = self.get_completor_func(constants.POOLS,
                                            pool)
        try:
            self.pool.create(ctx, pool, completor)
        except Exception as e:
            LOG.error('NSX driver pool_create failed %s', e)
            completor(success=False)
            return False
        return True

    @log_helpers.log_method_call
    def pool_delete(self, ctxt, pool):
        delete_result = {'value': True}

        def dummy_completor(success=True):
            delete_result['value'] = success

        ctx = neutron_context.Context(None, pool['project_id'])

        # Octavia removes pool HMs while pool is deleted
        if pool.get('healthmonitor'):
            pool['healthmonitor']['pool'] = pool
            try:
                self.healthmonitor.delete_cascade(
                    ctx, pool['healthmonitor'], dummy_completor)
            except Exception as e:
                delete_result['value'] = False
                LOG.error('NSX driver pool_delete failed to delete HM %s', e)

        for member in pool.get('members', []):
            try:
                if not member.get('pool'):
                    member['pool'] = pool
                self.member.delete_cascade(ctx, member, dummy_completor)
            except Exception as e:
                delete_result['value'] = False
                LOG.error('NSX driver pool_delete failed to delete member'
                          ' %s %s', member['id'], e)

        completor = self.get_completor_func(constants.POOLS,
                                            pool, delete=True)
        try:
            self.pool.delete(ctx, pool, completor)
        except Exception as e:
            LOG.error('NSX driver pool_delete failed %s', e)
            delete_result['value'] = False

        if not delete_result['value']:
            completor(success=False)
        return delete_result['value']

    @log_helpers.log_method_call
    def pool_update(self, ctxt, old_pool, new_pool):
        ctx = neutron_context.Context(None, old_pool['project_id'])
        completor = self.get_completor_func(constants.POOLS,
                                            new_pool)
        try:
            self.pool.update(ctx, old_pool, new_pool, completor)
        except Exception as e:
            LOG.error('NSX driver pool_update failed %s', e)
            completor(success=False)
            return False
        return True

    # Member
    @log_helpers.log_method_call
    def member_create(self, ctxt, member):
        ctx = neutron_context.Context(None, member['project_id'])
        completor = self.get_completor_func(constants.MEMBERS,
                                            member)
        try:
            self.member.create(ctx, member, completor)
        except Exception as e:
            LOG.error('NSX driver member_create failed %s', e)
            completor(success=False)
            return False
        return True

    @log_helpers.log_method_call
    def member_delete(self, ctxt, member):
        ctx = neutron_context.Context(None, member['project_id'])
        completor = self.get_completor_func(constants.MEMBERS,
                                            member, delete=True)
        try:
            self.member.delete(ctx, member, completor)
        except Exception as e:
            LOG.error('NSX driver member_delete failed %s', e)
            completor(success=False)
            return False
        return True

    @log_helpers.log_method_call
    def member_update(self, ctxt, old_member, new_member):
        ctx = neutron_context.Context(None, old_member['project_id'])
        completor = self.get_completor_func(constants.MEMBERS,
                                            new_member)
        try:
            self.member.update(ctx, old_member, new_member, completor)
        except Exception as e:
            LOG.error('NSX driver member_update failed %s', e)
            completor(success=False)
            return False
        return True

    # Health Monitor
    @log_helpers.log_method_call
    def healthmonitor_create(self, ctxt, healthmonitor):
        ctx = neutron_context.Context(None, healthmonitor['project_id'])
        completor = self.get_completor_func(constants.HEALTHMONITORS,
                                            healthmonitor)
        try:
            self.healthmonitor.create(ctx, healthmonitor, completor)
        except Exception as e:
            LOG.error('NSX driver healthmonitor_create failed %s', e)
            completor(success=False)
            return False
        return True

    @log_helpers.log_method_call
    def healthmonitor_delete(self, ctxt, healthmonitor):
        ctx = neutron_context.Context(None, healthmonitor['project_id'])
        completor = self.get_completor_func(constants.HEALTHMONITORS,
                                            healthmonitor, delete=True)
        try:
            self.healthmonitor.delete(ctx, healthmonitor, completor)
        except Exception as e:
            LOG.error('NSX driver healthmonitor_delete failed %s', e)
            completor(success=False)
            return False
        return True

    @log_helpers.log_method_call
    def healthmonitor_update(self, ctxt, old_healthmonitor, new_healthmonitor):
        ctx = neutron_context.Context(None, old_healthmonitor['project_id'])
        completor = self.get_completor_func(constants.HEALTHMONITORS,
                                            new_healthmonitor)
        try:
            self.healthmonitor.update(ctx, old_healthmonitor,
                                      new_healthmonitor, completor)
        except Exception as e:
            LOG.error('NSX driver healthmonitor_update failed %s', e)
            completor(success=False)
            return False
        return True

    # L7 Policy
    @log_helpers.log_method_call
    def l7policy_create(self, ctxt, l7policy):
        ctx = neutron_context.Context(None, l7policy['project_id'])
        completor = self.get_completor_func(constants.L7POLICIES,
                                            l7policy)
        try:
            self.l7policy.create(ctx, l7policy, completor)
        except Exception as e:
            LOG.error('NSX driver l7policy_create failed %s', e)
            completor(success=False)
            return False
        return True

    @log_helpers.log_method_call
    def l7policy_delete(self, ctxt, l7policy):
        ctx = neutron_context.Context(None, l7policy['project_id'])
        completor = self.get_completor_func(constants.L7POLICIES,
                                            l7policy, delete=True)
        try:
            self.l7policy.delete(ctx, l7policy, completor)
        except Exception as e:
            LOG.error('NSX driver l7policy_delete failed %s', e)
            completor(success=False)
            return False
        return True

    @log_helpers.log_method_call
    def l7policy_update(self, ctxt, old_l7policy, new_l7policy):
        ctx = neutron_context.Context(None, old_l7policy['project_id'])
        completor = self.get_completor_func(constants.L7POLICIES,
                                            new_l7policy)
        try:
            self.l7policy.update(ctx, old_l7policy, new_l7policy, completor)
        except Exception as e:
            LOG.error('NSX driver l7policy_update failed %s', e)
            completor(success=False)
            return False
        return True

    # L7 Rule
    @log_helpers.log_method_call
    def l7rule_create(self, ctxt, l7rule):
        ctx = neutron_context.Context(None, l7rule['project_id'])
        completor = self.get_completor_func(constants.L7RULES, l7rule)
        try:
            self.l7rule.create(ctx, l7rule, completor)
        except Exception as e:
            LOG.error('NSX driver l7rule_create failed %s', e)
            completor(success=False)
            return False
        return True

    @log_helpers.log_method_call
    def l7rule_delete(self, ctxt, l7rule):
        ctx = neutron_context.Context(None, l7rule['project_id'])
        completor = self.get_completor_func(constants.L7RULES, l7rule,
                                            delete=True)
        try:
            self.l7rule.delete(ctx, l7rule, completor)
        except Exception as e:
            LOG.error('NSX driver l7rule_delete failed %s', e)
            completor(success=False)
            return False
        return True

    @log_helpers.log_method_call
    def l7rule_update(self, ctxt, old_l7rule, new_l7rule):
        ctx = neutron_context.Context(None, old_l7rule['project_id'])
        completor = self.get_completor_func(constants.L7RULES, new_l7rule)
        try:
            self.l7rule.update(ctx, old_l7rule, new_l7rule, completor)
        except Exception as e:
            LOG.error('NSX driver l7rule_update failed %s', e)
            completor(success=False)
            return False
        return True


class NSXOctaviaStatisticsCollector(object):
    def __init__(self, core_plugin, listener_stats_getter,
                 loadbalancer_status_getter=None):
        LOG.info("NSXOctaviaStatisticsCollector starting with interval of "
                 "%s seconds", cfg.CONF.octavia_stats_interval)
        self.core_plugin = core_plugin
        self.listener_stats_getter = listener_stats_getter
        self.loadbalancer_status_getter = loadbalancer_status_getter
        if cfg.CONF.octavia_stats_interval:
            eventlet.spawn_n(self.thread_runner,
                             cfg.CONF.octavia_stats_interval)

    def thread_runner(self, interval):
        LOG.info("NSXOctaviaStatisticsCollector thread_runner is running")
        while True:
            time.sleep(interval)
            try:
                self.collect()
            except Exception as e:
                LOG.error("Octavia stats collect failed with %s", e)

    def collect(self):
        if not self.core_plugin.octavia_listener:
            LOG.warning("Octavia stats collector cannot run with plugin %s",
                        self.core_plugin)
            return

        endpoint = self.core_plugin.octavia_listener.endpoints[0]
        context = neutron_context.get_admin_context()

        listeners_stats = self.listener_stats_getter(
            context, self.core_plugin)
        if listeners_stats:
            # Avoid sending empty stats
            stats = {'listeners': listeners_stats}
            endpoint.update_listener_statistics(stats)

        if self.loadbalancer_status_getter:
            loadbalancer_status = self.loadbalancer_status_getter(
                context, self.core_plugin)
            endpoint.update_loadbalancer_status(loadbalancer_status)
