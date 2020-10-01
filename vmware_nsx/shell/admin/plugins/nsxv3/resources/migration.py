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
import sys
import time

import logging
import paramiko
import tenacity

from neutron.extensions import securitygroup as ext_sg
from neutron_fwaas.db.firewall.v2 import firewall_db_v2
from neutron_lib.callbacks import registry
from neutron_lib import context
from oslo_config import cfg

from vmware_nsx.common import utils as nsx_utils
from vmware_nsx.db import db
from vmware_nsx.db import nsx_models
from vmware_nsx.plugins.nsx_p import plugin as p_plugin
from vmware_nsx.plugins.nsx_v3 import cert_utils
from vmware_nsx.plugins.nsx_v3 import plugin as v3_plugin
from vmware_nsx.plugins.nsx_v3 import utils as v3_plugin_utils
from vmware_nsx.services.fwaas.nsx_p import fwaas_callbacks_v2
from vmware_nsx.services.lbaas import lb_const
from vmware_nsx.services.lbaas.nsx_p.implementation import lb_utils
from vmware_nsx.shell.admin.plugins.common import constants
from vmware_nsx.shell.admin.plugins.common import utils as admin_utils
from vmware_nsx.shell.admin.plugins.nsxp.resources import utils as p_utils
from vmware_nsx.shell.admin.plugins.nsxv3.resources import utils
from vmware_nsx.shell import resources as shell

from vmware_nsxlib.v3 import core_resources as nsx_resources
from vmware_nsxlib.v3 import exceptions as nsxlib_exc
from vmware_nsxlib.v3 import load_balancer as nsxlib_lb
from vmware_nsxlib.v3 import nsx_constants
from vmware_nsxlib.v3.policy import constants as policy_constants
from vmware_nsxlib.v3.policy import core_resources as policy_resources
from vmware_nsxlib.v3.policy import utils as policy_utils

LOG = logging.getLogger(__name__)

POLICY_API_STATUS_FAILED = 'FAILED'
POLICY_API_STATUS_SUCCESS = 'SUCCESS'
POLICY_API_STATUS_IN_PROGRESS = 'PAUSING'
POLICY_API_STATUS_PAUSED = 'PAUSED'
POLICY_API_STATUS_READY = 'NOT_STARTED'

STATUS_ALLOW_MIGRATION_REQ = set([
    POLICY_API_STATUS_SUCCESS,
    POLICY_API_STATUS_READY
])

MIGRATE_LIMIT_NO_LIMIT = 0
MIGRATE_LIMIT_TIER0 = 1
MIGRATE_LIMIT_TIER0_PORTS = 1000
MIGRATE_LIMIT_TIER1 = 1000
MIGRATE_LIMIT_TIER1_PORTS = 1000
MIGRATE_LIMIT_NAT = 1500
MIGRATE_LIMIT_DHCP_SERVER = 1500
MIGRATE_LIMIT_MD_PROXY = 1500
MIGRATE_LIMIT_SWITCH_PROFILE = 1500
MIGRATE_LIMIT_LOGICAL_SWITCH = 500
MIGRATE_LIMIT_LOGICAL_PORT = 1500
MIGRATE_LIMIT_NS_GROUP = 2000
MIGRATE_LIMIT_DFW_SECTION = 3000
MIGRATE_LIMIT_LB_SERVICE = 2000
MIGRATE_LIMIT_LB_VIRTUAL_SERVER = 2000
MIGRATE_LIMIT_LB_MONITOR = 1500
MIGRATE_LIMIT_LB_POOL = 1500
MIGRATE_LIMIT_LB_APP_PROFILE = 2000
MIGRATE_LIMIT_LB_PER_PROFILE = 2000
MIGRATE_LIMIT_CERT = 1500

COMPONENT_STATUS_ALREADY_MIGRATED = 1
COMPONENT_STATUS_OK = 2

ROLLBACK_DATA = []
EDGE_FW_SEQ = 1
DFW_SEQ = 1
NSX_ROUTER_SECTIONS = []
SERVICE_UP_RETRIES = 30


def start_migration_process(nsxlib):
    """Notify the manager that the migration process is starting"""
    return nsxlib.client.url_post(
        "migration/mp-to-policy/workflow?action=INITIATE", None)


def end_migration_process(nsxlib):
    """Notify the manager that the migration process has ended"""
    return nsxlib.client.url_post(
        "migration/mp-to-policy/workflow?action=DONE", None)


def send_migration_request(nsxlib, body):
    return nsxlib.client.url_post("migration/mp-to-policy", body)


def send_rollback_request(nsxlib, body):
    #TODO(asarfaty): Rollback can take very long, especially for firewall
    # sections. In this case backup-restore might be better
    return nsxlib.client.url_post("migration/mp-to-policy/rollback", body)


def send_migration_plan_action(nsxlib, action):
    return nsxlib.client.url_post("migration/plan?action=%s" % action, None)


def get_migration_status(nsxlib, silent=False):
    return nsxlib.client.get("migration/status-summary",
                             silent=silent)


def change_migration_service_status(start=True, nsxlib=None):
    """Enable/Disable the migration service on the NSX manager
    using SSH command
    """
    # TODO(asarfaty): Is there an api for that? or use sshpass
    action = 'start' if start else 'stop'
    command = "%s service migration-coordinator" % action
    LOG.info("Going to %s the migration service on the NSX manager by "
             "SSHing the manager and running '%s'", action, command)
    host = cfg.CONF.nsx_v3.nsx_api_managers[0]
    user = cfg.CONF.nsx_v3.nsx_api_user[0]
    passwd = cfg.CONF.nsx_v3.nsx_api_password[0]

    ssh = paramiko.SSHClient()
    ssh.load_system_host_keys()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, username=user, password=passwd)
    ssh.exec_command(command)

    if start and nsxlib:
        LOG.info("Waiting for the service to be up...")
        start_time = time.time()

        @tenacity.retry(reraise=True,
                        retry=tenacity.retry_if_exception_type(Exception),
                        wait=tenacity.wait_exponential(multiplier=0.5, max=2),
                        stop=tenacity.stop_after_attempt(SERVICE_UP_RETRIES))
        def get_migration_status_with_retry(nsxlib):
            get_migration_status(nsxlib, silent=True)

        try:
            get_migration_status_with_retry(nsxlib)
        except Exception:
            raise Exception("The migration service did not get up after %s "
                            "retries" % SERVICE_UP_RETRIES)

        elapsed_time = time.time() - start_time
        LOG.info("The service is up (waited %s seconds)", elapsed_time)


def ensure_migration_state_ready(nsxlib, with_abort=False):
    try:
        status = get_migration_status(nsxlib, silent=True)
    except Exception as e:
        if with_abort:
            change_migration_service_status(start=True, nsxlib=nsxlib)
            return ensure_migration_state_ready(nsxlib)
        LOG.debug("Failed to get migration status: %s", e)
        return False

    if status["overall_migration_status"] not in STATUS_ALLOW_MIGRATION_REQ:
        LOG.error("Migration status not ready: %s", status)
        if with_abort:
            send_migration_plan_action(nsxlib, 'abort')
            return ensure_migration_state_ready(
                nsxlib, with_abort=with_abort)
        return False

    return True


def verify_component_status(nsxlib, component_number):
    status = get_migration_status(nsxlib)
    if (status['component_status'][component_number]['status'] ==
            POLICY_API_STATUS_FAILED):
        # If it's a duplicate migration request, pass the verification
        if ('is duplicate or already migrated' in
                status['component_status'][component_number]['details'] and
            component_number == 0):
            # Success that indicates resource migration is already done
            return COMPONENT_STATUS_ALREADY_MIGRATED
        # bad state. abort, mark as fail, and go to next request
        raise Exception("The migration server returned with FAILURE status. "
                        "Details: %s", status)
    # Success
    return COMPONENT_STATUS_OK


def wait_on_overall_migration_status_to_pause(nsxlib):
    while True:
        status = get_migration_status(nsxlib)
        migration_status = status.get('overall_migration_status')
        if (migration_status == POLICY_API_STATUS_PAUSED or
            migration_status == POLICY_API_STATUS_SUCCESS):
            break
        time.sleep(1)


def printable_resource_name(resource):
    name = resource.get('display_name')
    if name:
        try:
            name = str(name)
        except UnicodeEncodeError:
            name = name.encode('ascii', 'ignore')
    res_id = resource.get('id')
    if name == res_id:
        return name
    return "%s (%s)" % (name, resource.get('id'))


def get_resource_migration_data(nsxlib_resource, neutron_id_tags,
                                resource_type, resource_condition=None,
                                printable_name=None, policy_resource_get=None,
                                policy_id_callback=None,
                                metadata_callback=None,
                                skip_policy_path_check=False,
                                nsxlib_list_args=None):
    if not printable_name:
        printable_name = resource_type
    LOG.debug("Getting data for MP %s", printable_name)

    if nsxlib_list_args:
        resources = nsxlib_resource.list(**nsxlib_list_args)
    else:
        resources = nsxlib_resource.list()
    if not isinstance(resources, list):
        # The nsxlib resources list return inconsistent type of result
        resources = resources.get('results', [])
    policy_ids = []
    entries = []
    for resource in resources:
        name_and_id = printable_resource_name(resource)
        policy_id = resource['id']
        # Go over tags and find the neutron id
        neutron_id = None
        found_policy_path = False
        for tag in resource.get('tags', []):
            if tag['scope'] == 'policyPath':
                # This is already a policy resource
                found_policy_path = True
            if neutron_id_tags and tag['scope'] in neutron_id_tags:
                neutron_id = tag['tag']
        if not skip_policy_path_check and found_policy_path:
            LOG.debug("Skipping %s %s as it is already a policy "
                      "resource", printable_name, name_and_id)
            continue
        if neutron_id_tags:
            if not neutron_id:
                # Not a neutron resource
                LOG.debug("Skipping %s %s as it is not a neutron resource",
                          printable_name, name_and_id)
                continue
            policy_id = neutron_id
        if resource_condition:
            if not resource_condition(resource):
                LOG.debug("Skipping %s %s as it does not match the neutron "
                          "condition", printable_name, name_and_id)
                continue
        if policy_id_callback:
            # Callback to change the policy id
            policy_id = policy_id_callback(resource, policy_id)
        if policy_id and policy_resource_get:
            # filter out resources that already exit on policy!
            try:
                policy_resource_get(policy_id, silent=True)
            except nsxlib_exc.ResourceNotFound:
                pass
            else:
                LOG.debug("Skipping %s %s as it already exists on the "
                          "policy backend", printable_name, name_and_id)
                continue

        # Make sure not to migrate multiple resources to the same policy-id
        if policy_id:
            if policy_id in policy_ids:
                msg = (_("Cannot migrate %s %s to policy-id %s: Another %s "
                         "has the same designated policy-id. One of those is "
                         "probably a neutron orphaned. Please delete it and "
                         "try migration again.") % (printable_name,
                         name_and_id, policy_id, printable_name))
                raise Exception(msg)
            policy_ids.append(policy_id)

        LOG.debug("Adding data for %s %s, policy-id %s",
                  printable_name, name_and_id, policy_id)
        entry = {'manager_id': resource['id']}
        if policy_id:
            entry['policy_id'] = policy_id
        if metadata_callback:
            metadata_callback(entry, policy_id, resource)
        entries.append(entry)
    return entries


def migrate_objects(nsxlib, data, use_admin=False):
    if not ensure_migration_state_ready(nsxlib):
        raise Exception("The migration server is not ready")

    migration_body = {"migration_data": [data]}

    # Update the principal identity for the policy resources
    # use 'admin' for predefined objects, and the opestack configured
    # user/identity for openstack resources
    if use_admin:
        user = 'admin'
    elif cfg.CONF.nsx_v3.nsx_use_client_auth:
        user = cert_utils.NSX_OPENSTACK_IDENTITY
    else:
        user = cfg.CONF.nsx_v3.nsx_api_user[0]
    migration_body['setup_details'] = {
        'principal_identity': user}

    LOG.info("Migrating %d %s objects with principal_identity %s",
             len(data['resource_ids']), data['type'], user)
    LOG.debug("Migration body : %s", migration_body)

    send_migration_request(nsxlib, migration_body)
    # send the start action
    send_migration_plan_action(nsxlib, 'start')

    # wait until the overall_migration_status is SUCCESS
    wait_on_overall_migration_status_to_pause(nsxlib)

    # verify first component status
    success_code = verify_component_status(nsxlib, 0)
    if success_code == COMPONENT_STATUS_ALREADY_MIGRATED:
        return True

    # send the continue action
    send_migration_plan_action(nsxlib, 'continue')

    # wait until the overall_migration_status is SUCCESS
    wait_on_overall_migration_status_to_pause(nsxlib)

    # verify second component status (Will raise in case of error)
    try:
        verify_component_status(nsxlib, 1)
    except Exception as e:
        raise e
    else:
        global ROLLBACK_DATA
        # rollback should be done in the reverse order
        ROLLBACK_DATA = [data] + ROLLBACK_DATA

    return True


def migrate_resource(nsxlib, resource_type, entries,
                     limit=MIGRATE_LIMIT_NO_LIMIT,
                     count_internals=False, use_admin=False):
    # Call migrate_resource with the part of resources we need by the limit
    if not entries:
        LOG.info("No %s to migrate", resource_type)
        return

    LOG.info("Going to migrate %d %s objects in groups of max %s",
             len(entries), resource_type, limit)
    start_time = time.time()

    if limit == MIGRATE_LIMIT_NO_LIMIT:
        migrate_objects(nsxlib, {'type': resource_type,
                                 'resource_ids': entries},
                        use_admin=use_admin)
    else:
        if count_internals:
            # Limit the total number of resources, including internal ones
            counter = 0
            entries_to_migrate = []
            for index in range(0, len(entries)):
                addition_size = 1 + len(entries[index].get('linked_ids', []))
                if addition_size > limit:
                    # Unsupported size of resource
                    raise Exception("%s size is over the allowed limit of "
                                    "%s" % (resource_type, limit))
                if counter + addition_size > limit:
                    # Migrate what was accumulated so far
                    migrate_objects(nsxlib,
                                    {'type': resource_type,
                                     'resource_ids': entries_to_migrate},
                                    use_admin=use_admin)
                    # Start a new accumulation
                    counter = addition_size
                    entries_to_migrate = [entries[index]]
                else:
                    # Keep accumulating
                    counter = counter + addition_size
                    entries_to_migrate.append(entries[index])
            if entries_to_migrate:
                # Migrate the left overs
                migrate_objects(nsxlib,
                                {'type': resource_type,
                                 'resource_ids': entries_to_migrate},
                                use_admin=use_admin)
        else:
            for index in range(0, len(entries), limit):
                migrate_objects(nsxlib,
                                {'type': resource_type,
                                 'resource_ids': entries[index:index + limit]},
                                use_admin=use_admin)

    elapsed_time = time.time() - start_time
    LOG.info("Migrating %d %s objects took %s seconds",
             len(entries), resource_type, elapsed_time)


def get_configured_values(plugin, az_attribute):
    values = []
    for az in plugin.get_azs_list():
        az_values = getattr(az, az_attribute)
        if isinstance(az_values, list):
            values.extend(az_values)
        else:
            values.append(az_values)
    return values


def get_neurton_tier0s(plugin):
    return get_configured_values(plugin, '_default_tier0_router')


def migrate_tier0s(nsxlib, nsxpolicy, plugin):
    # First prepare a list of neutron related tier0s from the config
    neutron_t0s = get_neurton_tier0s(plugin)
    # Add tier0s used specifically in external networks
    ctx = context.get_admin_context()
    with ctx.session.begin(subtransactions=True):
        bindings = ctx.session.query(
            nsx_models.TzNetworkBinding).filter_by(
            binding_type='l3_ext').all()
        for bind in bindings:
            if bind.phy_uuid not in neutron_t0s:
                neutron_t0s.append(bind.phy_uuid)

    def cond(resource):
        return (resource.get('router_type', '') == 'TIER0' and
                resource.get('id') in neutron_t0s)

    entries = get_resource_migration_data(
        nsxlib.logical_router, None,
        'TIER0', resource_condition=cond,
        policy_resource_get=nsxpolicy.tier0.get,
        nsxlib_list_args={'router_type': nsx_constants.ROUTER_TYPE_TIER0})
    migrate_resource(nsxlib, 'TIER0', entries, MIGRATE_LIMIT_TIER0,
                     use_admin=True)
    migrated_tier0s = [entry['manager_id'] for entry in entries]

    # Create a list of public switches connected to the tier0s to migrate later
    public_switches = []
    for tier0 in neutron_t0s:
        uplink_port = nsxlib.logical_router_port.get_tier0_uplink_port(tier0)
        if uplink_port:
            # Get the external LS id from the uplink port
            port_id = uplink_port['linked_logical_switch_port_id']['target_id']
            port = nsxlib.logical_port.get(port_id)
            public_switches.append(port['logical_switch_id'])

    return public_switches, migrated_tier0s


def is_neutron_resource(resource):
    # Return True if the resource has the neutron marking tag
    for tag in resource.get('tags', []):
        if tag.get('scope') == 'os-api-version':
            return True
    return False


def migrate_switch_profiles(nsxlib, nsxpolicy, plugin):
    """Return all types of neutron switching profiles"""

    # Build a condition for each type of switching profiles.
    # Note(asarfaty): system owned profiles should also be migrated as they are
    # missing from policy

    # Include switch profiles that are in the nsx.ini
    conf_profiles = get_configured_values(plugin, 'switching_profiles')

    # Add other switch profiles that might be used by neutron ports in the past
    port_profiles = set()
    ports = nsxlib.logical_port.list()['results']
    for port in ports:
        # Check that it is a neutron port
        if not is_neutron_resource(port):
            continue
        for prof in port.get('switching_profile_ids', []):
            port_profiles.add(prof['value'])

    # Black list neuron & system profiles that should not be migrated
    names_black_list = [v3_plugin_utils.NSX_V3_DHCP_PROFILE_NAME,
                        'ServiceInsertion_MacManagement_Profile']

    def get_cond(resource_type):
        def cond(resource):
            return (resource.get('resource_type') == resource_type and
                    resource.get('display_name') not in names_black_list and
                    (resource.get('id') in conf_profiles or
                     resource.get('id') in port_profiles or
                     resource.get('_system_owned', True) or
                     is_neutron_resource(resource)))
        return cond

    def get_policy_id_callback(res, policy_id):
        # In case of plugin init profiles: give it the id the policy plugin
        # will use
        mapping = {v3_plugin.NSX_V3_MAC_LEARNING_PROFILE_NAME:
                   p_plugin.MAC_DISCOVERY_PROFILE_ID,
                   v3_plugin_utils.NSX_V3_PSEC_PROFILE_NAME:
                   p_plugin.SPOOFGUARD_PROFILE_ID}

        if mapping.get(res.get('display_name')):
            return mapping[res['display_name']]

        # QoS profiles should get the neutron policy id
        for tag in res.get('tags', []):
            if tag['scope'] == 'os-neutron-qos-id':
                policy_id = tag['tag']

        return policy_id

    entries = get_resource_migration_data(
        nsxlib.switching_profile, None,
        'SPOOFGUARD_PROFILES',
        resource_condition=get_cond(
            nsx_resources.SwitchingProfileTypes.SPOOF_GUARD),
        policy_resource_get=nsxpolicy.spoofguard_profile.get,
        policy_id_callback=get_policy_id_callback)
    migrate_resource(nsxlib, 'SPOOFGUARD_PROFILES', entries,
                     MIGRATE_LIMIT_SWITCH_PROFILE)

    entries = get_resource_migration_data(
        nsxlib.switching_profile, None,
        'MACDISCOVERY_PROFILES',
        resource_condition=get_cond(
            nsx_resources.SwitchingProfileTypes.MAC_LEARNING),
        policy_resource_get=nsxpolicy.mac_discovery_profile.get,
        policy_id_callback=get_policy_id_callback)
    migrate_resource(nsxlib, 'MACDISCOVERY_PROFILES', entries,
                     MIGRATE_LIMIT_SWITCH_PROFILE)

    entries = get_resource_migration_data(
        nsxlib.switching_profile, None,
        'SEGMENT_SECURITY_PROFILES',
        resource_condition=get_cond(
            nsx_resources.SwitchingProfileTypes.SWITCH_SECURITY),
        policy_resource_get=nsxpolicy.segment_security_profile.get,
        policy_id_callback=get_policy_id_callback)
    migrate_resource(nsxlib, 'SEGMENT_SECURITY_PROFILES', entries,
                     MIGRATE_LIMIT_SWITCH_PROFILE)

    entries = get_resource_migration_data(
        nsxlib.switching_profile, None,
        'QOS_PROFILES',
        resource_condition=get_cond(
            nsx_resources.SwitchingProfileTypes.QOS),
        policy_resource_get=nsxpolicy.qos_profile.get,
        policy_id_callback=get_policy_id_callback)
    migrate_resource(nsxlib, 'QOS_PROFILES', entries,
                     MIGRATE_LIMIT_SWITCH_PROFILE)

    entries = get_resource_migration_data(
        nsxlib.switching_profile, None,
        'IPDISCOVERY_PROFILES',
        resource_condition=get_cond(
            nsx_resources.SwitchingProfileTypes.IP_DISCOVERY),
        policy_resource_get=nsxpolicy.ip_discovery_profile.get,
        policy_id_callback=get_policy_id_callback)
    migrate_resource(nsxlib, 'IPDISCOVERY_PROFILES', entries,
                     MIGRATE_LIMIT_SWITCH_PROFILE)


def migrate_md_proxies(nsxlib, nsxpolicy, plugin):
    neutron_md = get_configured_values(plugin, '_native_md_proxy_uuid')

    # Add other mdproxies that might be used by neutron networks in the past
    ports = nsxlib.logical_port.list()['results']
    for port in ports:
        # Check that it is a neutron port
        if not is_neutron_resource(port):
            continue
        if (port.get('attachment') and
            port['attachment'].get('attachment_type') == 'METADATA_PROXY'):
            mdproxy_id = port['attachment'].get('id')
            if mdproxy_id not in neutron_md:
                neutron_md.append(port['attachment'].get('id'))

    # make sure to migrate all certificates used by those MD proxies
    certificates = []
    for md_id in neutron_md:
        md_resource = nsxlib.native_md_proxy.get(md_id)
        certificates.extend(md_resource.get('metadata_server_ca_ids', []))

    if certificates:
        def cert_cond(resource):
            return resource.get('id') in certificates

        entries = get_resource_migration_data(
            nsxlib.trust_management, None,
            'CERTIFICATE',
            resource_condition=cert_cond,
            policy_resource_get=nsxpolicy.certificate.get)
        migrate_resource(nsxlib, 'CERTIFICATE', entries,
                         MIGRATE_LIMIT_CERT)

    # Now migrate the MD proxies
    def cond(resource):
        return resource.get('id') in neutron_md

    entries = get_resource_migration_data(
        nsxlib.native_md_proxy, None,
        'METADATA_PROXY',
        resource_condition=cond,
        policy_resource_get=nsxpolicy.md_proxy.get)
    migrate_resource(nsxlib, 'METADATA_PROXY', entries,
                     MIGRATE_LIMIT_MD_PROXY, use_admin=True)


def migrate_networks(nsxlib, nsxpolicy, plugin, public_switches):

    # Get a list of nsx-net provider networks to migrate
    # Those networks have no tags, and should keep the same id in policy
    nsx_networks = []
    ctx = context.get_admin_context()
    with ctx.session.begin(subtransactions=True):
        bindings = ctx.session.query(
            nsx_models.TzNetworkBinding).filter_by(
            binding_type=nsx_utils.NsxV3NetworkTypes.NSX_NETWORK).all()
        for bind in bindings:
            nsx_networks.append(bind.phy_uuid)

    def cond(resource):
        return (resource.get('id', '') in nsx_networks or
                resource.get('id', '') in public_switches or
                is_neutron_resource(resource))

    def get_policy_id(resource, policy_id):
        if resource['id'] in nsx_networks:
            # Keep original ID
            return resource['id']
        if resource['id'] in public_switches:
            # Keep original ID
            return resource['id']
        for tag in resource.get('tags', []):
            # Use the neutron ID
            if tag['scope'] == 'os-neutron-net-id':
                return tag['tag']

    def add_metadata(entry, policy_id, resource):
        # Add dhcp-v4 static bindings
        network_id = None
        for tag in resource.get('tags', []):
            # Use the neutron ID
            if tag['scope'] == 'os-neutron-net-id':
                network_id = tag['tag']
                break
        if not network_id:
            return
        metadata = []
        ctx = context.get_admin_context()
        port_filters = {'network_id': [network_id]}
        network_ports = plugin.get_ports(ctx, filters=port_filters)
        for port in network_ports:
            bindings = db.get_nsx_dhcp_bindings(ctx.session, port['id'])
            if bindings:
                # Should be only 1
                metadata.append({
                    'key': 'v4-static-binding%s' % bindings[0].nsx_binding_id,
                    'value': port['id'] + '-ipv4'})
        entry['metadata'] = metadata

    entries = get_resource_migration_data(
        nsxlib.logical_switch, [],
        'LOGICAL_SWITCH',
        resource_condition=cond,
        policy_resource_get=nsxpolicy.segment.get,
        policy_id_callback=get_policy_id,
        metadata_callback=add_metadata)
    migrate_resource(nsxlib, 'LOGICAL_SWITCH', entries,
                     MIGRATE_LIMIT_LOGICAL_SWITCH)


def migrate_ports(nsxlib, nsxpolicy, plugin):
    # For nsx networks support, keep a mapping of neutron id and MP id
    nsx_networks = {}
    ctx = context.get_admin_context()
    with ctx.session.begin(subtransactions=True):
        bindings = ctx.session.query(
            nsx_models.TzNetworkBinding).filter_by(
            binding_type='nsx-net').all()
        for bind in bindings:
            nsx_networks[bind.network_id] = bind.phy_uuid

    def get_policy_port(port_id, silent=False):
        # Get the segment id from neutron
        ctx = context.get_admin_context()
        neutron_port = plugin.get_port(ctx, port_id)
        net_id = neutron_port['network_id']
        if net_id in nsx_networks:
            segment_id = nsx_networks[net_id]
        else:
            segment_id = net_id
        return nsxpolicy.segment_port.get(segment_id, port_id, silent=silent)

    def add_metadata(entry, policy_id, resource):
        # Add binding maps with 'DEFAULT' key
        entry['metadata'] = [{'key': 'security-profile-binding-maps-id',
                              'value': policy_resources.DEFAULT_MAP_ID},
                             {'key': 'discovery-profile-binding-maps-id',
                              'value': policy_resources.DEFAULT_MAP_ID},
                             {'key': 'qos-profile-binding-maps-id',
                              'value': policy_resources.DEFAULT_MAP_ID}]

    entries = get_resource_migration_data(
        nsxlib.logical_port, ['os-neutron-port-id'],
        'LOGICAL_PORT',
        policy_resource_get=get_policy_port,
        metadata_callback=add_metadata)
    migrate_resource(nsxlib, 'LOGICAL_PORT', entries,
                     MIGRATE_LIMIT_LOGICAL_PORT)


def migrate_routers(nsxlib, nsxpolicy):

    entries = get_resource_migration_data(
        nsxlib.logical_router,
        ['os-neutron-router-id'],
        'TIER1',
        policy_resource_get=nsxpolicy.tier1.get,
        nsxlib_list_args={'router_type': nsx_constants.ROUTER_TYPE_TIER1})
    migrate_resource(nsxlib, 'TIER1', entries, MIGRATE_LIMIT_TIER1)
    migrated_routers = [entry['manager_id'] for entry in entries]
    return migrated_routers


def _get_subnet_by_cidr(subnets, cidr):
    for subnet in subnets:
        if subnet['cidr'] == cidr:
            return subnet['id']


def migrate_routers_config(nsxlib, nsxpolicy, plugin, migrated_routers):
    """Migrate advanced configuration of neutron Tier-1s
    This will use the list of Tier-1s migrated earlier
    """
    # Migrate all the centralized router ports and static routes for tier1
    # routers without specifying ids
    def get_policy_id(resource, policy_id):
        # No policy id needed here
        return

    def cond(resource):
        # Import ports only for the routers that were currently migrated
        # because there is no easy way to verify what was already migrated
        return resource['id'] in migrated_routers

    def add_metadata(entry, policy_id, resource):
        # Add router interfaces Ids
        ctx = context.get_admin_context()
        metadata = []
        mp_rtr_id = resource['id']
        router_ports = nsxlib.logical_router_port.get_by_router_id(mp_rtr_id)
        for port in router_ports:
            if 'linked_logical_switch_port_id' in port:
                lsp_id = port['linked_logical_switch_port_id']['target_id']
                lsp = nsxlib.logical_port.get(lsp_id)
                ls_id = lsp['logical_switch_id']
                if ls_id:
                    neutron_net_ids = plugin._get_neutron_net_ids_by_nsx_id(
                        ctx, ls_id)
                    if neutron_net_ids:
                        # Should be only 1
                        metadata.append({'key': port['id'],
                                         'value': neutron_net_ids[0]})
        # Add static routes ids
        static_routes = nsxlib.logical_router.list_static_routes(
            mp_rtr_id)['results']
        for route in static_routes:
            policy_id = "%s-%s" % (route['network'].replace('/', '_'),
                                   route['next_hops'][0]['ip_address'])
            metadata.append({'key': route['id'],
                             'value': policy_id})

        # Add locale-service id as <routerid>-0
        policy_id = None
        for tag in resource.get('tags', []):
            if tag['scope'] == 'os-neutron-router-id':
                policy_id = tag['tag']
        if policy_id:
            metadata.append({'key': 'localeServiceId',
                             'value': "%s-0" % policy_id})

        entry['metadata'] = metadata

    entries = get_resource_migration_data(
        nsxlib.logical_router,
        ['os-neutron-router-id'],
        'TIER1_LOGICAL_ROUTER_PORT',
        policy_id_callback=get_policy_id,
        resource_condition=cond,
        metadata_callback=add_metadata,
        skip_policy_path_check=True,
        nsxlib_list_args={'router_type': nsx_constants.ROUTER_TYPE_TIER1})
    migrate_resource(nsxlib, 'TIER1_LOGICAL_ROUTER_PORT', entries,
                     MIGRATE_LIMIT_TIER1_PORTS)

    # Migrate NAT rules per neutron tier1
    entries = []
    tier1s = nsxlib.logical_router.list(
        router_type=nsx_constants.ROUTER_TYPE_TIER1)['results']
    ctx = context.get_admin_context()
    for tier1 in tier1s:
        # skip routers that were not migrated in this script call
        tier1_mp_id = tier1['id']
        if tier1_mp_id not in migrated_routers:
            continue
        # skip non-neutron routers
        tier1_neutron_id = None
        for tag in tier1.get('tags', []):
            if tag['scope'] == 'os-neutron-router-id':
                tier1_neutron_id = tag['tag']
                break
        if not tier1_neutron_id:
            continue
        # Migrate each existing NAT rule, with the parameters the policy
        # plugin would have set
        router_subnets = plugin._load_router_subnet_cidrs_from_db(
            ctx, tier1_neutron_id)
        nat_rules = nsxlib.logical_router.list_nat_rules(
            tier1_mp_id)['results']
        for rule in nat_rules:
            # NO_DNAT rules for subnets
            if rule['action'] == 'NO_DNAT':
                seq_num = p_plugin.NAT_RULE_PRIORITY_GW
                cidr = rule['match_destination_network']
                subnet_id = _get_subnet_by_cidr(router_subnets, cidr)
                if not subnet_id:
                    LOG.error("Could not find subnet with cidr %s matching "
                              "NO_DNAT rule %s tier1 %s",
                              cidr, rule['id'], tier1_neutron_id)
                    continue
                policy_id = 'ND-' + subnet_id
            # SNAT rules for subnet or fip
            elif rule['action'] == 'SNAT':
                cidr = rule['match_source_network']
                if '/' in cidr:
                    seq_num = p_plugin.NAT_RULE_PRIORITY_GW
                    subnet_id = _get_subnet_by_cidr(router_subnets, cidr)
                    if not subnet_id:
                        LOG.error("Could not find subnet with cidr %s "
                                  "matching SNAT rule %s tier1 %s",
                                  cidr, rule['id'], tier1_neutron_id)
                        continue
                    policy_id = 'S-' + subnet_id
                else:
                    # FIP rule
                    seq_num = p_plugin.NAT_RULE_PRIORITY_FIP
                    fip_ip = rule['translated_network']
                    filters = {'floating_ip_address': [fip_ip]}
                    fips = plugin.get_floatingips(ctx, filters)
                    if not fips:
                        LOG.error("Could not find FIP with ip %s matching "
                                  "SNAT rule %s tier1 %s",
                                  fip_ip, rule['id'], tier1_neutron_id)
                        continue
                    policy_id = 'S-' + fips[0]['id']
            # DNAT rules for fip
            elif rule['action'] == 'DNAT':
                # FIP rule
                seq_num = p_plugin.NAT_RULE_PRIORITY_FIP
                fip_ip = rule['match_destination_network']
                filters = {'floating_ip_address': [fip_ip]}
                fips = plugin.get_floatingips(ctx, filters)
                if not fips:
                    LOG.error("Could not find FIP with ip %s matching DNAT "
                              "rule %s tier1 %s",
                              fip_ip, rule['id'], tier1_neutron_id)
                    continue
                policy_id = 'D-' + fips[0]['id']
            else:
                LOG.error("Unknown NAT action %s for rule %s tier1 %s",
                          rule['action'], rule['id'], tier1_neutron_id)
                continue

            entry = {'manager_id': rule['id'],
                     'policy_id': policy_id,
                     'metadata': [{'key': 'SEQUENCE_NUMBER',
                                   'value': seq_num}],
                     'linked_ids': [{'key': 'TIER1',
                                     'value': tier1_mp_id}]}
            entries.append(entry)
    migrate_resource(nsxlib, 'NAT', entries,
                     MIGRATE_LIMIT_NAT)


def migrate_tier0_config(nsxlib, nsxpolicy, tier0s):
    """Migrate ports and config for the already migrated Tier0s"""

    entries = []
    for tier0 in tier0s:
        uplink_ports = nsxlib.logical_router_port.get_tier0_uplink_ports(tier0)
        for uplink_port in uplink_ports:
            entries.append({'manager_id': uplink_port['id']})

    migrate_resource(nsxlib, 'TIER0_LOGICAL_ROUTER_PORT', entries,
                     MIGRATE_LIMIT_TIER0_PORTS, use_admin=True)

    def get_policy_id(resource, policy_id):
        # No policy id needed here
        return

    def cond(resource):
        # Import config only for the routers that were currently migrated
        # because there is no easy way to verify what was already migrated
        return resource['id'] in tier0s

    entries = get_resource_migration_data(
        nsxlib.logical_router, [],
        'TIER0_LOGICAL_ROUTER_CONFIG',
        policy_id_callback=get_policy_id,
        resource_condition=cond,
        skip_policy_path_check=True,
        nsxlib_list_args={'router_type': nsx_constants.ROUTER_TYPE_TIER0})
    migrate_resource(nsxlib, 'TIER0_LOGICAL_ROUTER_CONFIG', entries,
                     MIGRATE_LIMIT_TIER0, use_admin=True)


def migrate_groups(nsxlib, nsxpolicy):
    """Migrate NS groups of neutron defined security groups and predefined at
    plugin init
    """
    def get_policy_id_callback(res, policy_id):
        # In case of plugin init groups: give it the id the policy plugin
        # will use
        if res.get('display_name') == \
            v3_plugin.NSX_V3_FW_DEFAULT_NS_GROUP:
            return p_plugin.NSX_P_DEFAULT_GROUP

        if res.get('display_name') == \
            v3_plugin.NSX_V3_EXCLUDED_PORT_NSGROUP_NAME:
            return p_plugin.NSX_P_EXCLUDE_LIST_GROUP

        return policy_id

    def get_policy_group(group_id, silent=False):
        return nsxpolicy.group.get(policy_constants.DEFAULT_DOMAIN, group_id,
                                   silent=silent)

    entries = get_resource_migration_data(
        nsxlib.ns_group,
        ['os-neutron-secgr-id', 'os-neutron-id'],
        'NS_GROUP',
        policy_resource_get=get_policy_group,
        policy_id_callback=get_policy_id_callback)
    migrate_resource(nsxlib, 'NS_GROUP', entries, MIGRATE_LIMIT_NS_GROUP)


def dfw_migration_cond(resource):
    return (resource.get('enforced_on') == 'VIF' and
            resource.get('category') == 'Default' and
            resource.get('section_type') == 'LAYER3' and
            not resource.get('is_default') and
            # Migrate only DFW sections only and no edge FW sections
            'applied_tos' in resource and
            resource['applied_tos'][0].get('target_type', '') == 'NSGroup')


def migrate_dfw_sections(nsxlib, nsxpolicy, plugin):
    def get_policy_id_callback(res, policy_id):
        # In case of plugin init section: give it the id the policy plugin
        # will use
        if res.get('display_name') == \
            v3_plugin.NSX_V3_FW_DEFAULT_SECTION:
            return p_plugin.NSX_P_DEFAULT_SECTION

        return policy_id

    def add_metadata(entry, policy_id, resource):
        # Add category, sequence, domain, and rule ids
        ctx = context.get_admin_context()
        category = p_plugin.NSX_P_REGULAR_SECTION_CATEGORY
        if policy_id == p_plugin.NSX_P_DEFAULT_SECTION:
            category = p_plugin.NSX_P_DEFAULT_SECTION_CATEGORY
        else:
            try:
                sg = plugin.get_security_group(ctx, policy_id)
            except ext_sg.SecurityGroupNotFound:
                LOG.warning("Neutron SG %s was not found. Section %s may be "
                            "an orphaned", policy_id, resource['id'])
                provider = False
            else:
                provider = sg.get('provider')
            if provider:
                category = p_plugin.NSX_P_PROVIDER_SECTION_CATEGORY

        global DFW_SEQ
        metadata = [{'key': "category", 'value': category},
                    {'key': "sequence", 'value': str(DFW_SEQ)}]
        DFW_SEQ = DFW_SEQ + 1

        # Add the rules
        rules = nsxlib.firewall_section.get_rules(resource['id'])['results']
        linked_ids = []
        seq = 1
        for rule in rules:
            linked_ids.append({'key': rule['id'], 'value': str(seq)})
            if policy_id == p_plugin.NSX_P_DEFAULT_SECTION:
                # Default section rule ids are their seq numbers
                linked_ids.append({'key': "%s-policyid" % rule['id'],
                                   'value': seq})
            else:
                # The display name of the MP rule is the neutron id, and this
                # will become the policy id
                linked_ids.append({'key': "%s-policyid" % rule['id'],
                                   'value': rule['display_name']})
            seq = seq + 1
        entry['metadata'] = metadata
        entry['linked_ids'] = linked_ids

    def get_policy_section(sec_id, silent=False):
        return nsxpolicy.comm_map.get(policy_constants.DEFAULT_DOMAIN, sec_id,
                                      silent=silent)

    entries = get_resource_migration_data(
        nsxlib.firewall_section,
        ['os-neutron-secgr-id', 'os-neutron-id'],
        'DFW_SECTION', resource_condition=dfw_migration_cond,
        policy_resource_get=get_policy_section,
        policy_id_callback=get_policy_id_callback,
        metadata_callback=add_metadata)
    migrate_resource(nsxlib, 'DFW_SECTION', entries,
                     MIGRATE_LIMIT_DFW_SECTION,
                     count_internals=False)


def migrate_edge_firewalls(nsxlib, nsxpolicy, plugin):
    # -- Migrate edge firewall sections:
    # The MP plugin uses the default MP edge firewall section, while the policy
    # plugin uses a non default one, so regular migration cannot be used.
    # Instead, create new edge firewall sections, and remove rules from the MP
    # default sections

    # This is a hack to use the v3 plugin with the policy fwaas driver
    class MigrationNsxpFwaasCallbacks(fwaas_callbacks_v2.NsxpFwaasCallbacksV2):
        def __init__(self, with_rpc):
            super(MigrationNsxpFwaasCallbacks, self).__init__(with_rpc)
            # Make sure fwaas is considered as enabled
            self.fwaas_enabled = True

        def _get_port_firewall_group_id(self, ctx, port_id):
            # Override this api because directory.get_plugin does not work from
            # admin utils context.
            driver_db = firewall_db_v2.FirewallPluginDb()
            return driver_db.get_fwg_attached_to_port(ctx, port_id)

    fwaas_callbacks = MigrationNsxpFwaasCallbacks(False)
    plugin.nsxpolicy = nsxpolicy
    ctx = context.get_admin_context()
    routers = plugin.get_routers(ctx)
    global NSX_ROUTER_SECTIONS
    for rtr in routers:
        nsx_router_id = db.get_nsx_router_id(ctx.session, rtr['id'])
        nsx_rtr = nsxlib.logical_router.get(nsx_router_id)
        for sec in nsx_rtr.get('firewall_sections', []):
            section_id = sec['target_id']
            section = nsxlib.firewall_section.get(section_id)
            if section['display_name'] != 'Default LR Layer3 Section':
                continue
            rules = nsxlib.firewall_section.get_rules(section_id)['results']
            if len(rules) <= 1:
                continue
            # Non default rules exist. need to migrate this section
            router_db = plugin._get_router(ctx, rtr['id'])
            ports = plugin._get_router_interfaces(ctx, rtr['id'])
            fwaas_callbacks.update_router_firewall(
                ctx, rtr['id'], router_db, ports)
            LOG.debug("Created GW policy for router %s", rtr['id'])

            # delete rule from the default mp section at the end of the loop
            # so the new section will have time to realize
            NSX_ROUTER_SECTIONS.append({'id': section_id,
                                        'default_rule': rules[-1],
                                        'router_id': rtr['id']})


def migrate_dhcp_servers(nsxlib, nsxpolicy):
    # Each MP DHCP server will be migrated to a policy DHCP server config
    # which will be used by a segment later. It will get the neutron network id
    entries = get_resource_migration_data(
        nsxlib.dhcp_server,
        ['os-neutron-net-id'],
        'DHCP_SERVER',
        policy_resource_get=nsxpolicy.dhcp_server_config.get)
    migrate_resource(nsxlib, 'DHCP_SERVER', entries,
                     MIGRATE_LIMIT_DHCP_SERVER)


def migrate_lb_resources(nsxlib, nsxpolicy):
    migrate_lb_certificates(nsxlib, nsxpolicy)
    migrate_lb_monitors(nsxlib, nsxpolicy)
    migrate_lb_pools(nsxlib, nsxpolicy)
    migrate_lb_profiles(nsxlib, nsxpolicy)
    migrate_lb_listeners(nsxlib, nsxpolicy)
    migrate_lb_services(nsxlib, nsxpolicy)


def migrate_lb_certificates(nsxlib, nsxpolicy):
    entries = get_resource_migration_data(
        nsxlib.trust_management,
        [lb_const.LB_LISTENER_TYPE],
        'CERTIFICATE',
        policy_resource_get=nsxpolicy.certificate.get)
    migrate_resource(nsxlib, 'CERTIFICATE', entries,
                     MIGRATE_LIMIT_CERT)


def _migrate_lb_resource(nsxlib, nsxpolicy, neutron_tag, api_name,
                         migration_name, limit,
                         policy_api_name=None,
                         policy_id_callback=None):
    if not policy_api_name:
        policy_api_name = api_name
    entries = get_resource_migration_data(
        getattr(nsxlib.load_balancer, api_name),
        [neutron_tag],
        migration_name,
        policy_resource_get=getattr(nsxpolicy.load_balancer,
                                    policy_api_name).get,
        policy_id_callback=policy_id_callback)
    migrate_resource(nsxlib, migration_name, entries, limit)


def migrate_lb_listeners(nsxlib, nsxpolicy):
    _migrate_lb_resource(nsxlib, nsxpolicy,
                         lb_const.LB_LISTENER_TYPE,
                         'virtual_server',
                         'LB_VIRTUAL_SERVER',
                         MIGRATE_LIMIT_LB_VIRTUAL_SERVER)


def migrate_lb_pools(nsxlib, nsxpolicy):
    _migrate_lb_resource(nsxlib, nsxpolicy,
                         lb_const.LB_POOL_TYPE,
                         'pool',
                         'LB_POOL',
                         MIGRATE_LIMIT_LB_POOL,
                         policy_api_name='lb_pool')


def migrate_lb_monitors(nsxlib, nsxpolicy):
    _migrate_lb_resource(nsxlib, nsxpolicy,
                         lb_const.LB_HM_TYPE,
                         'monitor',
                         'LB_MONITOR',
                         MIGRATE_LIMIT_LB_MONITOR,
                         policy_api_name='lb_monitor_profile_http')


def migrate_lb_profiles(nsxlib, nsxpolicy):
    _migrate_lb_resource(nsxlib, nsxpolicy,
                         lb_const.LB_LISTENER_TYPE,
                         'application_profile',
                         'LB_APPLICATION_PROFILE',
                         MIGRATE_LIMIT_LB_APP_PROFILE,
                         policy_api_name='lb_http_profile')

    def get_policy_id_callback(res, policy_id):
        # The input policy id is the pool id
        # Need to add a suffix regarding the type of persistence
        if (res.get('resource_type') ==
            nsxlib_lb.PersistenceProfileTypes.SOURCE_IP):
            return "%s_%s" % (policy_id, 'sourceip')
        return "%s_%s" % (policy_id, 'cookie')

    _migrate_lb_resource(nsxlib, nsxpolicy,
                         lb_const.LB_POOL_TYPE,
                         'persistence_profile',
                         'LB_PERSISTENCE_PROFILE',
                         MIGRATE_LIMIT_LB_PER_PROFILE,
                         policy_api_name='lb_persistence_profile',
                         policy_id_callback=get_policy_id_callback)


def migrate_lb_services(nsxlib, nsxpolicy):

    def get_policy_id_callback(res, policy_id):
        # LB service is shared between few octavia loadbalancers
        # so the policy id is not the LB id, and those should be  marked
        # in the tags of the policy resource.
        # Keep the same id as MP so later we can search the MP DB
        # and update the tags
        return res['id']

    entries = get_resource_migration_data(
        nsxlib.load_balancer.service,
        ['os-api-version'],
        'LB_SERVICE',
        policy_resource_get=nsxpolicy.load_balancer.lb_service.get,
        policy_id_callback=get_policy_id_callback)
    migrate_resource(nsxlib, 'LB_SERVICE', entries,
                     MIGRATE_LIMIT_LB_SERVICE)


def migrate_t_resources_2_p(nsxlib, nsxpolicy, plugin):
    """Create policy resources for all MP resources used by neutron"""

    # Initialize the migration process
    if not ensure_migration_state_ready(nsxlib, with_abort=True):
        return False

    try:
        LOG.info("Starting resources migration")

        start_migration_process(nsxlib)

        # Migration order derives from the dependencies between resources
        public_switches, tier0s = migrate_tier0s(nsxlib, nsxpolicy, plugin)
        migrate_md_proxies(nsxlib, nsxpolicy, plugin)
        migrate_switch_profiles(nsxlib, nsxpolicy, plugin)
        migrate_groups(nsxlib, nsxpolicy)
        migrate_dhcp_servers(nsxlib, nsxpolicy)
        mp_routers = migrate_routers(nsxlib, nsxpolicy)
        migrate_networks(nsxlib, nsxpolicy, plugin, public_switches)
        migrate_ports(nsxlib, nsxpolicy, plugin)
        migrate_routers_config(nsxlib, nsxpolicy, plugin, mp_routers)
        migrate_tier0_config(nsxlib, nsxpolicy, tier0s)
        migrate_lb_resources(nsxlib, nsxpolicy)

        # Migrate firewall sections last as those take the longest to rollback
        # in case of error
        migrate_dfw_sections(nsxlib, nsxpolicy, plugin)
        migrate_edge_firewalls(nsxlib, nsxpolicy, plugin)

        # Finalize the migration (cause policy realization)
        end_migration_process(nsxlib)

        # Stop the migration service
        change_migration_service_status(start=False)

        return True

    except Exception as e:
        # Migration failed - abort it
        LOG.error("Exception occurred while making the request: %s", e)
        try:
            LOG.info("Aborting the current request")
            try:
                send_migration_plan_action(nsxlib, 'abort')
            except Exception as e:
                LOG.error("Abort migration failed: %s", e)

            global ROLLBACK_DATA
            if ROLLBACK_DATA:
                LOG.info("Rolling migration back %s", ROLLBACK_DATA)
                send_rollback_request(nsxlib,
                                      {'migration_data': ROLLBACK_DATA})
            # Finalize the migration (Also needed after rollback)
            end_migration_process(nsxlib)
            # Stop the migration service
            change_migration_service_status(start=False)
        except Exception as e:
            LOG.error("Rollback failed: %s", e)
        return False


def _get_network_nsx_segment_id(ctx, net_id):
    bindings = db.get_network_bindings(ctx.session, net_id)
    if (bindings and
        bindings[0].binding_type ==
        nsx_utils.NsxV3NetworkTypes.NSX_NETWORK):
        # return the ID of the NSX network
        return bindings[0].phy_uuid
    return net_id


def _delete_segment_profiles_bindings(nsxpolicy, segment_id):
    found = False
    sec_profiles = nsxpolicy.segment_security_profile_maps.list(segment_id)
    for profile in sec_profiles:
        found = True
        nsxpolicy.segment_security_profile_maps.delete(
            segment_id, profile['id'])

    qos_profiles = nsxpolicy.segment_qos_profile_maps.list(segment_id)
    for profile in qos_profiles:
        found = True
        nsxpolicy.segment_qos_profile_maps.delete(
            segment_id, profile['id'])

    discovery_profiles = nsxpolicy.segment_discovery_profile_maps.list(
        segment_id)
    for profile in discovery_profiles:
        found = True
        nsxpolicy.segment_discovery_profile_maps.delete(
            segment_id, profile['id'])

    if found:
        LOG.debug("Removed profiles mappings from segment %s", segment_id)


def post_migration_actions(nsxlib, nsxpolicy, nsxpolicy_admin, plugin):
    """Update created policy resources that does not match the policy plugins'
    expectations.
    """
    LOG.info("Starting post-migration actions")
    ctx = context.get_admin_context()

    # -- Update Lb tags on loadbalancer service
    pol_lb_services = nsxpolicy.load_balancer.lb_service.list()
    for lb_srv in pol_lb_services:
        # Verify this is a neutron resource
        if not is_neutron_resource(lb_srv):
            continue
        # Check if it already has the LB id tag
        migrated = False
        for tag in lb_srv.get('tags', []):
            if tag['scope'] == lb_utils.SERVICE_LB_TAG_SCOPE:
                migrated = True
                break
        if migrated:
            continue

        # Find the loadbalancers using this service from the DB
        lb_mapping = db.get_nsx_lbaas_loadbalancer_binding_by_service(
            ctx.session, lb_srv['id'])
        if lb_mapping:
            if 'tags' not in lb_srv:
                lb_srv['tags'] = []
            loadbalancers = [lb_map.loadbalancer_id for lb_map in lb_mapping]
            for lb_id in loadbalancers:
                lb_srv['tags'].append({'scope': lb_utils.SERVICE_LB_TAG_SCOPE,
                                       'tag': lb_id})
            nsxpolicy.load_balancer.lb_service.update(
                lb_srv['id'], tags=lb_srv['tags'])
            LOG.debug("Added tags to LB service %s", lb_srv['id'])

    # -- Update Lb L7 rules names
    mp_lb_rules = nsxlib.load_balancer.rule.list()['results']
    for mp_rule in mp_lb_rules:
        l7pol_id = None
        listener_id = None
        for tag in mp_rule.get('tags', []):
            if tag['scope'] == lb_const.LB_L7POLICY_TYPE:
                l7pol_id = tag['tag']
            if tag['scope'] == 'policyPath':
                listener_id = policy_utils.path_to_id(tag['tag'])

        if not l7pol_id or not listener_id:
            continue
        pol_vs = nsxpolicy.load_balancer.virtual_server.get(listener_id)
        pol_rules = pol_vs['rules']
        for pol_rule in pol_rules:
            if pol_rule['display_name'] == mp_rule['id']:
                new_name = nsx_utils.get_name_and_uuid('policy', l7pol_id)
                pol_rule['display_name'] = new_name
                nsxpolicy.load_balancer.virtual_server.update_lb_rules(
                    listener_id, pol_rules)
                LOG.debug("Updated L7 policy %s name on the virtual server",
                          l7pol_id)
                break

    # -- Create DHCP server configs to be used in neutron config
    # (The migration does not migrate MP DHCP profiles)
    neutron_dhcp = get_configured_values(plugin, '_native_dhcp_profile_uuid')
    for mp_dhcp in neutron_dhcp:
        # check if it was already migrated
        try:
            nsxpolicy.dhcp_server_config.get(mp_dhcp, silent=True)
        except Exception:
            # Create it
            mp_obj = nsxlib.native_dhcp_profile.get(mp_dhcp)
            # This should be created with the admin principal identity
            nsxpolicy_admin.dhcp_server_config.create_or_overwrite(
                mp_obj['display_name'],
                config_id=mp_dhcp,
                description=mp_obj.get('description', ''),
                edge_cluster_path=nsxpolicy.edge_cluster.get_path(
                    mp_obj['edge_cluster_id']))
            LOG.debug("Created DHCP server config %s for plugin config",
                      mp_dhcp)

    # -- Update Policy segments:
    # Set subnets GW for networks without linked routers
    # And remove unused segment profiles mappings
    networks = plugin.get_networks(ctx)
    for net in networks:
        if net.get('router:external'):
            continue
        seg_id = _get_network_nsx_segment_id(ctx, net['id'])
        if seg_id == net['id']:
            # This is not an nsx-net. Delete the bindings
            _delete_segment_profiles_bindings(nsxpolicy, seg_id)

        if plugin._get_network_router_ids(ctx, net['id']):
            continue
        # verify that this network has a dhcp subnet
        subnets = plugin.get_subnets_by_network(ctx, net['id'])
        for subnet in subnets:
            if subnet['ip_version'] == 4 and subnet['enable_dhcp']:
                # Update backend subnet
                segment = nsxpolicy.segment.get(seg_id)
                subnets = segment.get('subnets', [])
                if subnets and len(subnets) == 1 and subnet['gateway_ip']:
                    cidr_prefix = int(subnet['cidr'].split('/')[1])
                    gw = "%s/%s" % (subnet['gateway_ip'], cidr_prefix)
                    subnets[0]['gateway_address'] = gw
                nsxpolicy.segment.update(seg_id, subnets=subnets)
                LOG.debug("Updated gateway of network %s", net['id'])
                break

    # -- Delete MP edge firewall rules
    for section in NSX_ROUTER_SECTIONS:
        # make sure the policy section was already realized
        # with runtime_status=SUCESS
        nsxpolicy.gateway_policy.wait_until_state_sucessful(
            policy_constants.DEFAULT_DOMAIN, section['router_id'],
            max_attempts=600, with_refresh=True)
        nsxlib.firewall_section.update(
            section['id'], rules=[section['default_rule']])
        LOG.debug("Deleted MP edge FW section %s rules", section['id'])

    LOG.info("Post-migration actions done.")


def pre_migration_checks(nsxlib, plugin):
    """Check for unsupported configuration that will fail the migration"""
    nsx_version = nsxlib.get_version()
    if not nsx_utils.is_nsx_version_3_1_0(nsx_version):
        LOG.error("Pre migration check failed: Migration not supported for "
                  "NSX %s", nsx_version)
        return False

    # Cannot migrate with unsupported services
    service_plugins = cfg.CONF.service_plugins
    for srv_plugin in service_plugins:
        if 'vpnaas' in srv_plugin:
            LOG.error("Pre migration check failed: VPNaaS is not supported. "
                      "Please delete its configuration and disable it, before "
                      "running migration again.")
            return False
        if 'l2gw' in srv_plugin:
            LOG.error("Pre migration check failed: L2GW is not supported. "
                      "Please delete its configuration and disable it, before "
                      "running migration again.")
            return False

    # Tier0 with disabled BGP config
    neutron_t0s = get_neurton_tier0s(plugin)
    for tier0 in neutron_t0s:
        bgp_conf = nsxlib.logical_router.get_bgp_config(tier0)
        if not bgp_conf['enabled']:
            # Verify there are no neighbors configured
            if nsxlib.logical_router.get_bgp_neighbors(tier0)['result_count']:
                LOG.error("Pre migration check failed: Tier0 %s has BGP "
                          "neighbors but BGP is disabled. Please remove the "
                          "neighbors or enable BGP and try again.", tier0)
                return False

    # DHCP relay is unsupported
    if plugin._availability_zones_data.dhcp_relay_configured():
        LOG.error("Pre migration check failed: DHCP relay configuration "
                  "cannot be migrated. Please remove it from the plugin "
                  "configuration and from all NSX logical router ports and "
                  "try again.")
        return False

    return True


@admin_utils.output_header
def MP2Policy_pre_migration_check(resource, event, trigger, **kwargs):
    """Verify if the current configuration can be migrated to Policy"""
    nsxlib = utils.get_connected_nsxlib()
    with utils.NsxV3PluginWrapper() as plugin:
        if not pre_migration_checks(nsxlib, plugin):
            # Failed
            LOG.error("T2P migration cannot run. Please fix the configuration "
                      "and try again\n\n")
            sys.exit(1)


def _get_nsxlib_from_config(verbose):
    """Update the current config and return a working nsxlib
    or exit with error
    """

    if (not len(cfg.CONF.nsx_v3.nsx_api_user) or
        not len(cfg.CONF.nsx_v3.nsx_api_password)):
        LOG.error("T2P migration cannot run. Please provide nsx_api_user and "
                  "nsx_api_password in the configuration.")
        sys.exit(1)

    retriables = [nsxlib_exc.APITransactionAborted,
                  nsxlib_exc.ServerBusy]

    # Initialize the nsxlib objects, using just one of the managers because
    # the migration will be enabled only on one
    nsx_api_managers = copy.copy(cfg.CONF.nsx_v3.nsx_api_managers)
    nsx_api_user = copy.copy(cfg.CONF.nsx_v3.nsx_api_user)
    nsx_api_password = copy.copy(cfg.CONF.nsx_v3.nsx_api_password)

    for ind in range(len(nsx_api_managers)):
        # update the config to use this one manager only
        cfg.CONF.set_override(
            'nsx_api_managers', [nsx_api_managers[ind]], 'nsx_v3')
        if len(nsx_api_user) > ind:
            cfg.CONF.set_override(
                'nsx_api_user', [nsx_api_user[ind]], 'nsx_v3')
        else:
            cfg.CONF.set_override(
                'nsx_api_user', [nsx_api_user[0]], 'nsx_v3')
        if len(nsx_api_password) > ind:
            cfg.CONF.set_override(
                'nsx_api_password', [nsx_api_password[ind]], 'nsx_v3')
        else:
            cfg.CONF.set_override(
                'nsx_api_password', [nsx_api_password[0]], 'nsx_v3')
            utils.reset_global_nsxlib()
        nsxlib = utils.get_connected_nsxlib(verbose=verbose,
                                            allow_overwrite_header=True,
                                            retriable_exceptions=retriables)
        try:
            # test connectivity
            nsxlib.get_version()
        except Exception:
            LOG.warning("Failed to connect to NSX manager %s",
                        nsx_api_managers[ind])
        else:
            # Found a working manager
            return nsxlib

    LOG.error("T2P migration failed. Cannot connect to NSX with managers %s",
              nsx_api_managers)
    sys.exit(1)


@admin_utils.output_header
def MP2Policy_migration(resource, event, trigger, **kwargs):
    """Migrate NSX resources and neutron DB from NSX-T (MP) to Policy"""

    verbose = kwargs.get('verbose', False)
    if verbose:
        # Add DEBUG logs as well
        LOG.setLevel(logging.DEBUG)
    else:
        LOG.setLevel(logging.INFO)

    if kwargs.get('property'):
        # Add logfile
        properties = admin_utils.parse_multi_keyval_opt(kwargs['property'])
        logfile = properties.get('logfile', None)
        if logfile:
            f_handler = logging.FileHandler(logfile)
            f_formatter = logging.Formatter(
                '%(asctime)s %(levelname)s %(message)s')
            f_handler.setFormatter(f_formatter)
            LOG.addHandler(f_handler)

    nsxlib = _get_nsxlib_from_config(verbose)
    nsxpolicy = p_utils.get_connected_nsxpolicy(
        conf_path=cfg.CONF.nsx_v3, verbose=verbose)

    if cfg.CONF.nsx_v3.nsx_use_client_auth:
        # Also create a policy manager with admin user to manipulate
        # admin-defined resources which should not have neutron principal
        # identity
        nsxpolicy_admin = p_utils.get_connected_nsxpolicy(
            conf_path=cfg.CONF.nsx_v3,
            use_basic_auth=True,
            nsx_username=cfg.CONF.nsx_v3.nsx_api_user,
            nsx_password=cfg.CONF.nsx_v3.nsx_api_password,
            verbose=verbose)
    else:
        nsxpolicy_admin = nsxpolicy

    with utils.NsxV3PluginWrapper(verbose=verbose) as plugin:
        # Make sure FWaaS was initialized
        plugin.init_fwaas_for_admin_utils()

        start_time = time.time()
        if not pre_migration_checks(nsxlib, plugin):
            # Failed
            LOG.error("T2P migration cannot run. Please fix the configuration "
                      "and try again\n\n")
            sys.exit(1)
        elapsed_time = time.time() - start_time
        LOG.debug("Pre-migration took %s seconds", elapsed_time)

        start_time = time.time()
        if not migrate_t_resources_2_p(nsxlib, nsxpolicy, plugin):
            # Failed
            LOG.error("T2P migration failed. Aborting\n\n")
            sys.exit(1)
        elapsed_time = time.time() - start_time
        LOG.debug("Migration took %s seconds", elapsed_time)

        start_time = time.time()
        post_migration_actions(nsxlib, nsxpolicy, nsxpolicy_admin, plugin)
        elapsed_time = time.time() - start_time
        LOG.debug("Post-migration took %s seconds", elapsed_time)

    LOG.info("T2P migration completed successfully\n\n")


@admin_utils.output_header
def MP2Policy_cleanup_db_mappings(resource, event, trigger, **kwargs):
    """Delete all entries from nsx-t mapping tables in DB"""
    confirm = admin_utils.query_yes_no(
        "Are you sure you want to delete all MP plugin mapping DB tables?",
        default="no")
    if not confirm:
        LOG.info("Deletion aborted by user")
        return

    ctx = context.get_admin_context()
    mp_mapping_tables = [nsx_models.NeutronNsxFirewallSectionMapping,
                         nsx_models.NeutronNsxSecurityGroupMapping,
                         nsx_models.NeutronNsxRuleMapping,
                         nsx_models.NeutronNsxPortMapping,
                         nsx_models.NeutronNsxRouterMapping,
                         nsx_models.NeutronNsxServiceBinding,
                         nsx_models.NeutronNsxDhcpBinding,
                         nsx_models.QosPolicySwitchProfile,
                         nsx_models.NsxLbaasLoadbalancer,
                         nsx_models.NsxLbaasListener,
                         nsx_models.NsxLbaasPool,
                         nsx_models.NsxLbaasMonitor,
                         nsx_models.NsxLbaasL7Rule,
                         nsx_models.NsxLbaasL7Policy]
    for table in mp_mapping_tables:
        ctx.session.query(table).delete()

    LOG.info("Deleted all MP plugin mapping DB tables.")


registry.subscribe(MP2Policy_migration,
                   constants.NSX_MIGRATE_T_P,
                   shell.Operations.IMPORT.value)

registry.subscribe(MP2Policy_pre_migration_check,
                   constants.NSX_MIGRATE_T_P,
                   shell.Operations.VALIDATE.value)

registry.subscribe(MP2Policy_cleanup_db_mappings,
                   constants.NSX_MIGRATE_T_P,
                   shell.Operations.CLEAN_ALL.value)
