# Copyright 2019 VMware, Inc.
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

from vmware_nsx._i18n import _
from vmware_nsx.services.lbaas import lb_const
from vmware_nsx.services.lbaas.nsx_p.implementation import lb_const as p_const
from vmware_nsx.services.lbaas.nsx_v3.implementation import lb_utils
from vmware_nsxlib.v3 import load_balancer as nsxlib_lb
from vmware_nsxlib.v3.policy import constants as p_constants
from vmware_nsxlib.v3.policy import utils as p_utils
from vmware_nsxlib.v3 import utils

LOG = logging.getLogger(__name__)
ADV_RULE_NAME = 'LB external VIP advertisement'


def get_rule_match_conditions(policy):
    match_conditions = []
    # values in rule have already been validated in LBaaS API,
    # we won't need to valid anymore in driver, and just get
    # the LB rule mapping from the dict.
    for rule in policy['rules']:
        match_type = lb_const.LB_RULE_MATCH_TYPE[rule['compare_type']]
        if rule['type'] == lb_const.L7_RULE_TYPE_COOKIE:
            header_value = rule['key'] + '=' + rule['value']
            match_conditions.append(
                {'type': 'LBHttpRequestHeaderCondition',
                 'match_type': match_type,
                 'header_name': 'Cookie',
                 'header_value': header_value})
        elif rule['type'] == lb_const.L7_RULE_TYPE_FILE_TYPE:
            match_conditions.append(
                {'type': 'LBHttpRequestUriCondition',
                 'match_type': match_type,
                 'uri': '*.' + rule['value']})
        elif rule['type'] == lb_const.L7_RULE_TYPE_HEADER:
            match_conditions.append(
                {'type': 'LBHttpRequestHeaderCondition',
                 'match_type': match_type,
                 'header_name': rule['key'],
                 'header_value': rule['value']})
        elif rule['type'] == lb_const.L7_RULE_TYPE_HOST_NAME:
            match_conditions.append(
                {'type': 'LBHttpRequestHeaderCondition',
                 'match_type': match_type,
                 'header_name': 'Host',
                 'header_value': rule['value']})
        elif rule['type'] == lb_const.L7_RULE_TYPE_PATH:
            match_conditions.append(
                {'type': 'LBHttpRequestUriCondition',
                 'match_type': match_type,
                 'uri': rule['value']})
        else:
            msg = (_('l7rule type %(type)s is not supported in LBaaS') %
                   {'type': rule['type']})
            raise n_exc.BadRequest(resource='lbaas-l7rule', msg=msg)
    return match_conditions


def get_rule_actions(nsxpolicy, l7policy):
    if l7policy['action'] == lb_const.L7_POLICY_ACTION_REDIRECT_TO_POOL:
        if l7policy['redirect_pool_id']:
            lb_pool_id = l7policy['redirect_pool_id']
            lb_pool_path = nsxpolicy.load_balancer.lb_pool.get_path(lb_pool_id)
            actions = [{'type': p_const.LB_SELECT_POOL_ACTION,
                        'pool_id': lb_pool_path}]
        else:
            msg = _('Failed to get LB pool binding from nsx db')
            raise n_exc.BadRequest(resource='lbaas-l7rule-create',
                                   msg=msg)
    elif l7policy['action'] == lb_const.L7_POLICY_ACTION_REDIRECT_TO_URL:
        actions = [{'type': p_const.LB_HTTP_REDIRECT_ACTION,
                    'redirect_status': lb_const.LB_HTTP_REDIRECT_STATUS,
                    'redirect_url': l7policy['redirect_url']}]
    elif l7policy['action'] == lb_const.L7_POLICY_ACTION_REJECT:
        actions = [{'type': p_const.LB_REJECT_ACTION,
                    'reply_status': lb_const.LB_HTTP_REJECT_STATUS}]
    else:
        msg = (_('Invalid l7policy action: %(action)s') %
               {'action': l7policy['action']})
        raise n_exc.BadRequest(resource='lbaas-l7rule-create',
                               msg=msg)
    return actions


def convert_l7policy_to_lb_rule(nsxpolicy, policy):
    return {
        'match_conditions': get_rule_match_conditions(policy),
        'actions': get_rule_actions(nsxpolicy, policy),
        'phase': lb_const.LB_RULE_HTTP_FORWARDING,
        'match_strategy': 'ALL'
    }


def remove_rule_from_policy(rule):
    l7rules = rule['policy']['rules']
    rule['policy']['rules'] = [r for r in l7rules if r['id'] != rule['id']]


def update_rule_in_policy(rule):
    remove_rule_from_policy(rule)
    rule['policy']['rules'].append(rule)


def update_router_lb_vip_advertisement(context, core_plugin, router_id):
    router = core_plugin.get_router(context.elevated(), router_id)

    # Add a rule to advertise external vips on the router
    external_subnets = core_plugin._find_router_gw_subnets(
        context.elevated(), router)
    external_cidrs = [s['cidr'] for s in external_subnets]
    if external_cidrs:
        core_plugin.nsxpolicy.tier1.add_advertisement_rule(
            router_id,
            ADV_RULE_NAME,
            p_constants.ADV_RULE_PERMIT,
            p_constants.ADV_RULE_OPERATOR_GE,
            [p_constants.ADV_RULE_TIER1_LB_VIP],
            external_cidrs)


def get_monitor_policy_client(lb_client, hm):
    if hm['type'] == lb_const.LB_HEALTH_MONITOR_TCP:
        return lb_client.lb_monitor_profile_tcp
    elif hm['type'] == lb_const.LB_HEALTH_MONITOR_HTTP:
        return lb_client.lb_monitor_profile_http
    elif hm['type'] == lb_const.LB_HEALTH_MONITOR_HTTPS:
        return lb_client.lb_monitor_profile_https
    elif hm['type'] == lb_const.LB_HEALTH_MONITOR_PING:
        return lb_client.lb_monitor_profile_icmp
    else:
        msg = (_('Cannot create health monitor %(monitor)s with '
                 'type %(type)s') % {'monitor': hm['id'],
                                     'type': hm['type']})
        raise n_exc.InvalidInput(error_message=msg)


def get_tags(plugin, resource_id, resource_type, project_id, project_name):
    return lb_utils.get_tags(plugin, resource_id, resource_type,
                             project_id, project_name)


def build_persistence_profile_tags(pool_tags, listener):
    tags = pool_tags[:]
    # With octavia loadbalancer name might not be among data passed
    # down to the driver
    lb_data = listener.get('loadbalancer')
    if lb_data:
        tags.append({
            'scope': lb_const.LB_LB_NAME,
            'tag': lb_data['name'][:utils.MAX_TAG_LEN]})
    tags.append({
        'scope': lb_const.LB_LB_TYPE,
        'tag': listener['loadbalancer_id']})
    tags.append({
        'scope': lb_const.LB_LISTENER_TYPE,
        'tag': listener['id']})
    return tags


def delete_persistence_profile(nsxpolicy, lb_persistence_profile_path):
    lb_client = nsxpolicy.load_balancer
    pp_client = lb_client.lb_persistence_profile
    persistence_profile_id = p_utils.path_to_id(lb_persistence_profile_path)
    if persistence_profile_id:
        pp_client.delete(persistence_profile_id)


def setup_session_persistence(nsxpolicy, pool, pool_tags, switch_type,
                              listener, vs_data):
    sp = pool.get('session_persistence')
    pers_type = None
    cookie_name = None
    cookie_mode = None
    lb_client = nsxpolicy.load_balancer
    pp_client = None
    if not sp:
        LOG.debug("No session persistence info for pool %s", pool['id'])
    elif sp['type'] == lb_const.LB_SESSION_PERSISTENCE_HTTP_COOKIE:
        pp_client = lb_client.lb_cookie_persistence_profile
        pers_type = nsxlib_lb.PersistenceProfileTypes.COOKIE
        pers_id_suffix = 'cookie'
        cookie_name = sp.get('cookie_name')
        if not cookie_name:
            cookie_name = lb_const.SESSION_PERSISTENCE_DEFAULT_COOKIE_NAME
        cookie_mode = "INSERT"
    elif sp['type'] == lb_const.LB_SESSION_PERSISTENCE_APP_COOKIE:
        pp_client = lb_client.lb_cookie_persistence_profile
        pers_type = nsxlib_lb.PersistenceProfileTypes.COOKIE
        pers_id_suffix = 'cookie'
        # In this case cookie name is mandatory
        cookie_name = sp['cookie_name']
        cookie_mode = "REWRITE"
    else:
        pp_client = lb_client.lb_source_ip_persistence_profile
        pers_type = nsxlib_lb.PersistenceProfileTypes.SOURCE_IP
        pers_id_suffix = 'sourceip'
    if pers_type:
        # There is a profile to create or update
        pp_kwargs = {
            'name': "persistence_%s" % utils.get_name_and_uuid(
                pool['name'] or 'pool', pool['id'], maxlen=235),
            'tags': lb_utils.build_persistence_profile_tags(
                pool_tags, listener)
        }
        if cookie_name:
            pp_kwargs['cookie_name'] = cookie_name
            pp_kwargs['cookie_mode'] = cookie_mode

    profile_path = vs_data.get('lb_persistence_profile_path', '')
    persistence_profile_id = p_utils.path_to_id(profile_path)
    if persistence_profile_id and not switch_type:
        # NOTE: removal of the persistence profile must be executed
        # after the virtual server has been updated
        if pers_type:
            # Update existing profile
            LOG.debug("Updating persistence profile %(profile_id)s for "
                      "listener %(listener_id)s with pool %(pool_id)s",
                      {'profile_id': persistence_profile_id,
                       'listener_id': listener['id'],
                       'pool_id': pool['id']})
            pp_client.update(persistence_profile_id, **pp_kwargs)
            return persistence_profile_id, None
        else:
            # Prepare removal of persistence profile
            return (None, functools.partial(delete_persistence_profile,
                                            nsxpolicy, profile_path))
    elif pers_type:
        # Create persistence profile
        pp_id = "%s_%s" % (pool['id'], pers_id_suffix)
        pp_kwargs['persistence_profile_id'] = pp_id
        pp_client.create_or_overwrite(**pp_kwargs)
        LOG.debug("Created persistence profile %(profile_id)s for "
                  "listener %(listener_id)s with pool %(pool_id)s",
                  {'profile_id': pp_id,
                   'listener_id': listener['id'],
                   'pool_id': pool['id']})
        if switch_type:
            # There is aso a persistence profile to remove!
            return (pp_id, functools.partial(delete_persistence_profile,
                                             nsxpolicy, profile_path))

        return pp_id, None
    return None, None
