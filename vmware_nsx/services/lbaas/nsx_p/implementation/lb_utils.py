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

import netaddr

from neutron_lib import exceptions as n_exc
from oslo_log import log as logging

from vmware_nsx._i18n import _
from vmware_nsx.common import locking
from vmware_nsx.services.lbaas import lb_const
from vmware_nsx.services.lbaas.nsx_p.implementation import lb_const as p_const
from vmware_nsx.services.lbaas.nsx_v3.implementation import lb_utils
from vmware_nsxlib.v3 import exceptions as nsxlib_exc
from vmware_nsxlib.v3 import load_balancer as nsxlib_lb
from vmware_nsxlib.v3 import nsx_constants
from vmware_nsxlib.v3.policy import constants as p_constants
from vmware_nsxlib.v3.policy import utils as p_utils
from vmware_nsxlib.v3 import utils

LOG = logging.getLogger(__name__)
ADV_RULE_NAME = 'LB external VIP advertisement'
SERVICE_LB_TAG_SCOPE = 'loadbalancer_id'
#TODO(asarfaty): allow more LBs on the same router by setting multiple
# ids in the same tag
SERVICE_LB_TAG_MAX = 20

VIP_GRP_ID = '%s-vip'
MAX_SOURCES_IN_RULE = 128
MAX_DESC_LEN = 1024


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


def get_router_from_network(context, plugin, subnet_id):
    return lb_utils.get_router_from_network(context, plugin, subnet_id)


def build_persistence_profile_tags(pool_tags, listener):
    tags = pool_tags[:]
    # With octavia loadbalancer name might not be among data passed
    # down to the driver
    lb_data = listener.get('loadbalancer')
    if lb_data and lb_data.get('name'):
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
            # There is also a persistence profile to remove!
            return (pp_id, functools.partial(delete_persistence_profile,
                                             nsxpolicy, profile_path))

        return pp_id, None
    return None, None


def get_router_nsx_lb_service(nsxpolicy, router_id):
    tags_to_search = [{'scope': lb_const.LR_ROUTER_TYPE, 'tag': router_id}]
    router_lb_services = nsxpolicy.search_by_tags(
        tags_to_search,
        nsxpolicy.load_balancer.lb_service.entry_def.resource_type()
    )['results']
    non_delete_services = [srv for srv in router_lb_services
                           if not srv.get('marked_for_delete')]
    if non_delete_services:
        return non_delete_services[0]


def get_lb_nsx_lb_service(nsxpolicy, lb_id, try_old=False):
    tags_to_search = [{'scope': SERVICE_LB_TAG_SCOPE, 'tag': lb_id}]
    lb_services = nsxpolicy.search_by_tags(
        tags_to_search,
        nsxpolicy.load_balancer.lb_service.entry_def.resource_type()
    )['results']
    non_delete_services = [srv for srv in lb_services
                           if not srv.get('marked_for_delete')]
    if non_delete_services:
        return non_delete_services[0]

    if try_old:
        # old Lb service might just have the LB id.
        try:
            lb_service = nsxpolicy.load_balancer.lb_service.get(lb_id)
        except nsxlib_exc.ResourceNotFound:
            LOG.error("Did not find LB %s service by tags or ID", lb_id)
        else:
            LOG.warning("Found LB service by Lb ID %s. Tags are not updated "
                        "properly", lb_id)
            return lb_service


def get_service_lb_name(lb, router_id=None):
    if router_id:
        return utils.get_name_and_uuid('rtr', router_id)
    else:
        return utils.get_name_and_uuid(lb.get('name') or 'lb', lb.get('id'))


def get_service_lb_tag(lb_id):
    return {'scope': SERVICE_LB_TAG_SCOPE, 'tag': lb_id}


def add_service_tag_callback(lb_id, only_first=False):
    """Return a callback that will validate and add a tag to the lb service"""
    def _update_calback(body):
        count = 0
        for tag in body.get('tags', []):
            if tag.get('scope') == SERVICE_LB_TAG_SCOPE:
                if only_first:
                    msg = _("A loadbalancer tag is already attached to the"
                            " service")
                    raise n_exc.BadRequest(
                        resource='lbaas-loadbalancer-create', msg=msg)
                if tag.get('tag') == lb_id:
                    # No need to update
                    return
                count = count + 1
        if count >= SERVICE_LB_TAG_MAX:
            msg = _("Too many loadbalancers on the same router")
            raise n_exc.BadRequest(resource='lbaas-loadbalancer-create',
                                   msg=msg)
        if 'tags' in body:
            body['tags'].append(get_service_lb_tag(lb_id))
        else:
            body['tags'] = [get_service_lb_tag(lb_id)]

    return _update_calback


def remove_service_tag_callback(lb_id):
    """Return a callback that will remove the tag from the lb service
    If it is the last tag raise an error so that the service can be deleted
    """
    def _update_calback(body):
        count = 0
        match_tag = None
        for tag in body.get('tags', []):
            if tag.get('scope') == SERVICE_LB_TAG_SCOPE:
                count = count + 1
                if tag.get('tag') == lb_id:
                    match_tag = tag
        if match_tag:
            if count <= 1:
                msg = _("This LB service should be deleted")
                raise n_exc.BadRequest(resource='lbaas-loadbalancer-delete',
                                       msg=msg)
            else:
                body['tags'].remove(match_tag)

    return _update_calback


def get_lb_rtr_lock(router_id):
    return locking.LockManager.get_lock('lb-router-%s' % str(router_id))


def _get_negated_allowed_cidrs(allowed_cidrs, is_ipv4=True):
    # Add the zero-ip so it will not be in the negated list as NSX will fail
    allowed_cidrs.append('0.0.0.0/32' if is_ipv4 else '::/128')
    allowed_set = netaddr.IPSet(allowed_cidrs)
    all_cidr = '0.0.0.0/0' if is_ipv4 else '::/0'
    all_set = netaddr.IPSet([all_cidr])
    negate_set = all_set - allowed_set

    # Translate to cidr, ignoring unsupported cidrs.
    negate_cidrs = [str(cidr) for cidr in negate_set.iter_cidrs()]
    # split into max len (128) lists.(%s)
    negated_list = [negate_cidrs[i:i + MAX_SOURCES_IN_RULE]
                    for i in range(0, len(negate_cidrs), MAX_SOURCES_IN_RULE)]
    return negated_list


def get_lb_vip_address(core_plugin, context, loadbalancer):
    # If loadbalancer vip_port already has floating ip, use floating
    # IP as the virtual server VIP address. Else, use the loadbalancer
    # vip_address directly on virtual server.
    filters = {'port_id': [loadbalancer['vip_port_id']]}
    floating_ips = core_plugin.get_floatingips(context,
                                               filters=filters)
    if floating_ips:
        return floating_ips[0]['floating_ip_address']
    return loadbalancer['vip_address']


def get_lb_router_id(core_plugin, context, loadbalancer):
    # First try to get it from the vip subnet
    router_id = get_router_from_network(
        context, core_plugin, loadbalancer['vip_subnet_id'])
    if router_id:
        return router_id

    # Try from the LB service
    service = get_lb_nsx_lb_service(
        core_plugin.nsxpolicy, loadbalancer['id'], try_old=True)
    if service and service.get('connectivity_path'):
        return p_utils.path_to_id(service['connectivity_path'])


def set_allowed_cidrs_fw(core_plugin, context, loadbalancer, listeners):
    nsxpolicy = core_plugin.nsxpolicy
    lb_vip_address = get_lb_vip_address(
        core_plugin, context, loadbalancer)
    vip_group_id = VIP_GRP_ID % loadbalancer['id']
    is_ipv4 = bool(':' not in lb_vip_address)

    # Find out if the GW policy exists or not
    try:
        nsxpolicy.gateway_policy.get(
            p_constants.DEFAULT_DOMAIN,
            map_id=loadbalancer['id'], silent=True)
    except nsxlib_exc.ResourceNotFound:
        gw_exist = False
    else:
        gw_exist = True

    # list all the relevant listeners
    fw_listeners = []
    for listener in listeners:
        if listener.get('allowed_cidrs'):
            fw_listeners.append({
                'id': listener.get('listener_id', listener.get('id')),
                'port': listener['protocol_port'],
                'protocol': listener['protocol'],
                'allowed_cidrs': listener['allowed_cidrs'],
                'negate_cidrs': _get_negated_allowed_cidrs(
                    listener['allowed_cidrs'],
                    is_ipv4=is_ipv4)})

    if not fw_listeners:
        # Delete the GW policy if it exists
        if gw_exist:
            nsxpolicy.gateway_policy.delete(
                p_constants.DEFAULT_DOMAIN,
                map_id=loadbalancer['id'])
            # Delete related services
            tags_to_search = [{'scope': lb_const.LB_LB_TYPE,
                               'tag': loadbalancer['id']}]
            services = nsxpolicy.search_by_tags(
                tags_to_search,
                nsxpolicy.service.parent_entry_def.resource_type()
            )['results']
            for srv in services:
                if not srv.get('marked_for_delete'):
                    nsxpolicy.service.delete(srv['id'])
            # Delete the vip group
            nsxpolicy.group.delete(p_constants.DEFAULT_DOMAIN,
                                   vip_group_id)

        return

    # Find the router to apply the rules on from the LB service
    router_id = get_lb_router_id(core_plugin, context, loadbalancer)
    if not router_id:
        LOG.info("No router found for LB %s allowed cidrs",
                 loadbalancer['id'])
        return

    # Create a group for the vip address (to make it easier to update)
    expr = nsxpolicy.group.build_ip_address_expression(
        [lb_vip_address])
    tags = nsxpolicy.build_v3_tags_payload(
        loadbalancer, resource_type=lb_const.LB_LB_TYPE,
        project_name=context.tenant_name)
    nsxpolicy.group.create_or_overwrite_with_conditions(
        "LB_%s_vip" % loadbalancer['id'],
        p_constants.DEFAULT_DOMAIN, group_id=vip_group_id,
        conditions=[expr], tags=tags)
    vip_group_path = nsxpolicy.group.entry_def(
        domain_id=p_constants.DEFAULT_DOMAIN,
        group_id=vip_group_id).get_resource_full_path()

    # Create the list of rules
    rules = []
    for listener in fw_listeners:
        ip_version = netaddr.IPAddress(lb_vip_address).version
        # Create the service for this listener
        srv_tags = nsxpolicy.build_v3_tags_payload(
            loadbalancer, resource_type=lb_const.LB_LB_TYPE,
            project_name=context.tenant_name)
        srv_tags.append({
            'scope': lb_const.LB_LISTENER_TYPE,
            'tag': listener['id']})
        srv_name = "LB Listener %s" % listener['id']
        protocol = (nsx_constants.UDP if
                    listener['protocol'] == lb_const.LB_PROTOCOL_UDP
                    else nsx_constants.TCP)
        nsxpolicy.service.create_or_overwrite(
                srv_name,
                service_id=listener['id'],
                description="Service for listener %s" % listener['id'],
                protocol=protocol,
                dest_ports=[listener['port']],
                tags=srv_tags)

        # Build the rules for this listener (128 sources each)
        rule_index = 0
        for cidr_list in listener['negate_cidrs']:
            rule_name = "Allowed cidrs for listener %s" % listener['id']
            rule_id = listener['id']
            if len(listener['negate_cidrs']) > 1:
                rule_name = rule_name + " (part %s of %s)" % (
                    rule_index, len(listener['negate_cidrs']))
                rule_id = rule_id + "-%s" % rule_index
            description = "Allow only %s" % listener['allowed_cidrs']
            if len(description) >= MAX_DESC_LEN:
                description = "Allow only configured allowed-cidrs"
            rules.append(nsxpolicy.gateway_policy.build_entry(
                rule_name,
                p_constants.DEFAULT_DOMAIN, loadbalancer['id'],
                rule_id,
                description=description,
                action=nsx_constants.FW_ACTION_DROP,
                ip_protocol=(nsx_constants.IPV4 if ip_version == 4
                             else nsx_constants.IPV6),
                dest_groups=[vip_group_path],
                source_groups=cidr_list,
                service_ids=[listener['id']],
                scope=[nsxpolicy.tier1.get_path(router_id)],
                direction=nsx_constants.IN,
                plain_groups=True))
            rule_index = rule_index + 1

    # Create / update the GW policy
    if gw_exist:
        # only update the rules of this policy
        nsxpolicy.gateway_policy.update_entries(
            p_constants.DEFAULT_DOMAIN,
            loadbalancer['id'], rules,
            category=p_constants.CATEGORY_LOCAL_GW)
    else:
        policy_name = "LB %s allowed cidrs" % loadbalancer['id']
        description = ("Allowed CIDRs rules for loadbalancer %s" %
                       loadbalancer['id'])
        tags = nsxpolicy.build_v3_tags_payload(
            loadbalancer, resource_type=lb_const.LB_LB_TYPE,
            project_name=context.tenant_name)
        nsxpolicy.gateway_policy.create_with_entries(
            policy_name, p_constants.DEFAULT_DOMAIN,
            map_id=loadbalancer['id'],
            description=description,
            tags=tags,
            entries=rules,
            category=p_constants.CATEGORY_LOCAL_GW)
