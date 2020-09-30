# Copyright 2019 VMware, Inc.
# All Rights Reserved
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import excutils

from neutron_lib import constants
from neutron_lib import context as n_context

from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.services.vpnaas.common_v3 import ipsec_driver as common_driver
from vmware_nsx.services.vpnaas.common_v3 import ipsec_utils
from vmware_nsx.services.vpnaas.nsxp import ipsec_validator
from vmware_nsxlib.v3 import exceptions as nsx_lib_exc
from vmware_nsxlib.v3 import nsx_constants as consts
from vmware_nsxlib.v3.policy import constants as policy_constants

LOG = logging.getLogger(__name__)
IPSEC = 'ipsec'


class NSXpIPsecVpnDriver(common_driver.NSXcommonIPsecVpnDriver):

    def __init__(self, service_plugin):
        validator = ipsec_validator.IPsecNsxPValidator(service_plugin)
        super(NSXpIPsecVpnDriver, self).__init__(service_plugin, validator)

        self._nsxpolicy = self._core_plugin.nsxpolicy
        self._nsx_vpn = self._nsxpolicy.ipsec_vpn

    def _get_service_local_cidr_group(self, context, vpnservice, cidrs):
        """Create/Override the group for the local cidrs of a vpnservice
        used for the edge firewall rules allowing the vpn traffic.
        Return the group id, which is the same as the service id.
        """
        group_id = vpnservice['id']
        expr = self._nsxpolicy.group.build_ip_address_expression(cidrs)
        tags = self._nsxpolicy.build_v3_tags_payload(
            vpnservice,
            resource_type='os-vpn-service-id',
            project_name=context.tenant_name)
        self._nsxpolicy.group.create_or_overwrite_with_conditions(
            "Local group for VPN service %s" % vpnservice['id'],
            policy_constants.DEFAULT_DOMAIN, group_id=group_id,
            conditions=[expr], tags=tags)
        return group_id

    def _delete_service_local_cidr_group(self, vpnservice):
        try:
            self._nsxpolicy.group.delete(
                policy_constants.DEFAULT_DOMAIN, group_id=vpnservice['id'])
        except nsx_lib_exc.ResourceNotFound:
            # If there is no FWaaS on the router it may not have been created
            LOG.debug("Cannot delete local CIDR group for vpnservice %s as "
                      "it was not found", vpnservice['id'])

    def _get_connection_local_cidr_group_name(self, connection):
        return 'local_%s' % connection['id']

    def _get_connection_local_cidr_group(self, context, connection, cidrs):
        """Create/Override the group for the local cidrs of a connection
        used for the edge firewall rules allowing the vpn traffic.
        Return the group id, which is the same as the connection id.
        """
        group_id = self._get_connection_local_cidr_group_name(connection)
        expr = self._nsxpolicy.group.build_ip_address_expression(cidrs)
        tags = self._nsxpolicy.build_v3_tags_payload(
            connection,
            resource_type='os-vpn-connection-id',
            project_name=context.tenant_name)
        self._nsxpolicy.group.create_or_overwrite_with_conditions(
            "Local group for VPN connection %s" % connection['id'],
            policy_constants.DEFAULT_DOMAIN, group_id=group_id,
            conditions=[expr], tags=tags)
        return group_id

    def _delete_connection_local_cidr_group(self, connection):
        try:
            group_id = self._get_connection_local_cidr_group_name(connection)
            self._nsxpolicy.group.delete(
                policy_constants.DEFAULT_DOMAIN, group_id=group_id)
        except nsx_lib_exc.ResourceNotFound:
            # If there is no FWaaS on the router it may not have been created
            LOG.debug("Cannot delete local CIDR group for connection %s as "
                      "it was not found", connection['id'])

    def _get_connection_peer_cidr_group_name(self, connection):
        return 'peer_%s' % connection['id']

    def _get_peer_cidr_group(self, context, conn):
        """Create/Override the group for the peer cidrs of a connection
        used for the edge firewall rules allowing the vpn traffic.
        Return the group id, which is the same as the connection id.
        """
        group_ips = self.validator._get_peer_cidrs(context, conn)
        group_id = self._get_connection_peer_cidr_group_name(conn)
        expr = self._nsxpolicy.group.build_ip_address_expression(group_ips)
        tags = self._nsxpolicy.build_v3_tags_payload(
            conn,
            resource_type='os-vpn-connection-id',
            project_name=context.tenant_name)
        self._nsxpolicy.group.create_or_overwrite_with_conditions(
            "Peer group for VPN connection %s" % conn['id'],
            policy_constants.DEFAULT_DOMAIN, group_id=group_id,
            conditions=[expr], tags=tags)
        return group_id

    def _delete_peer_cidr_group(self, conn):
        try:
            group_id = self._get_connection_peer_cidr_group_name(conn)
            self._nsxpolicy.group.delete(
                policy_constants.DEFAULT_DOMAIN, group_id=group_id)
        except nsx_lib_exc.ResourceNotFound:
            # If there is no FWaaS on the router it may not have been created
            LOG.debug("Cannot delete peer CIDR group for connection %s as "
                      "it was not found", conn['id'])

    def _generate_ipsecvpn_firewall_rules(self, plugin_type, context,
                                          router_id=None):
        """Return the firewall rules needed to allow vpn traffic"""
        fw_rules = []
        # get all the active services of this router
        filters = {'router_id': [router_id],
                   'status': [constants.ACTIVE]}
        services = self.vpn_plugin.get_vpnservices(
            context.elevated(), filters=filters)
        if not services:
            return fw_rules
        for srv in services:
            subnet_id = None
            if srv['subnet_id']:
                subnet_id = srv['subnet_id']
                subnet = self.l3_plugin.get_subnet(
                    context.elevated(), subnet_id)
                local_cidrs = [subnet['cidr']]
                local_group = self._get_service_local_cidr_group(
                    context, srv, local_cidrs)
            # get all the non-errored connections of this service
            filters = {'vpnservice_id': [srv['id']],
                       'status': [constants.ACTIVE, constants.DOWN]}
            connections = self.vpn_plugin.get_ipsec_site_connections(
                context.elevated(), filters=filters)
            for conn in connections:
                if not subnet_id:
                    # Get local endpoint from group
                    local_cidrs = self.validator._get_local_cidrs(
                        context.elevated(), conn)
                    local_group = self._get_connection_local_cidr_group(
                        context, conn, local_cidrs)
                peer_group = self._get_peer_cidr_group(
                    context.elevated(), conn)
                fw_rules.append(self._nsxpolicy.gateway_policy.build_entry(
                    'VPN connection ' + conn['id'],
                    policy_constants.DEFAULT_DOMAIN, router_id,
                    action=consts.FW_ACTION_ALLOW,
                    dest_groups=[peer_group],
                    source_groups=[local_group],
                    scope=[self._nsxpolicy.tier1.get_path(router_id)],
                    direction=consts.IN_OUT))

        return fw_rules

    def _update_firewall_rules(self, context, vpnservice, conn, delete=False):
        LOG.debug("Updating vpn firewall rules for router %s",
                  vpnservice['router_id'])
        self._core_plugin.update_router_firewall(
            context, vpnservice['router_id'])

        # if it is during delete - try to delete the group of this connection
        if delete:
            self._delete_peer_cidr_group(conn)
            self._delete_connection_local_cidr_group(conn)

    def update_router_advertisement(self, context, router_id):
        """Advertise the local subnets of all the services on the router"""

        # Do nothing in case of a router with no GW or no-snat router
        # (as it is already advertised)
        rtr = self.l3_plugin.get_router(context, router_id)
        if (not rtr.get('external_gateway_info') or
            not rtr['external_gateway_info'].get('enable_snat', True)):
            return

        LOG.debug("Updating router advertisement rules for router %s",
                  router_id)
        rules = []

        # get all the active services of this router
        filters = {'router_id': [router_id],
                   'status': [constants.ACTIVE]}
        services = self.vpn_plugin.get_vpnservices(
            context.elevated(), filters=filters)
        rule_name_pref = 'VPN advertisement service'
        has_connections = False
        for srv in services:
            # use only services with non-errored connections
            filters = {'vpnservice_id': [srv['id']],
                       'status': [constants.ACTIVE, constants.DOWN]}
            connections = self.vpn_plugin.get_ipsec_site_connections(
                context.elevated(), filters=filters)
            if not connections:
                continue
            has_connections = True
            if srv['subnet_id']:
                subnet = self.l3_plugin.get_subnet(
                    context.elevated(), srv['subnet_id'])
                local_cidrs = [subnet['cidr']]
            else:
                # get all connections local endpoints cidrs
                local_cidrs = []
                for conn in connections:
                    local_cidrs.extend(
                        self.validator._get_local_cidrs(
                            context.elevated(), conn))
            rules.append(self._nsxpolicy.tier1.build_advertisement_rule(
                "%s %s" % (rule_name_pref, srv['id']),
                policy_constants.ADV_RULE_PERMIT,
                policy_constants.ADV_RULE_OPERATOR_GE,
                [policy_constants.ADV_RULE_TIER1_IPSEC_LOCAL_ENDPOINT],
                local_cidrs))

        self._nsxpolicy.tier1.update_advertisement_rules(
            router_id, rules, name_prefix=rule_name_pref)

        # Also update the ipsec endpoints advertisement
        self._nsxpolicy.tier1.update_route_advertisement(
            router_id, ipsec_endpoints=has_connections)

    def _nsx_tags(self, context, object):
        return self._nsxpolicy.build_v3_tags_payload(
            object, resource_type='os-vpn-connection-id',
            project_name=context.tenant_name)

    def _create_ike_profile(self, context, connection):
        """Create an ike profile for a connection
        Creating/overwriting IKE profile based on the openstack ike policy
        upon connection creation.
        There is no driver callback for profiles creation so it has to be
        done on connection creation.
        """
        ike_policy_id = connection['ikepolicy_id']
        ikepolicy = self.vpn_plugin.get_ikepolicy(context, ike_policy_id)
        tags = self._nsxpolicy.build_v3_tags_payload(
            ikepolicy, resource_type='os-vpn-ikepol-id',
            project_name=context.tenant_name)
        try:
            profile_id = self._nsx_vpn.ike_profile.create_or_overwrite(
                ikepolicy['name'] or ikepolicy['id'],
                profile_id=ikepolicy['id'],
                description=ikepolicy['description'],
                encryption_algorithms=[ipsec_utils.ENCRYPTION_ALGORITHM_MAP[
                    ikepolicy['encryption_algorithm']]],
                digest_algorithms=[ipsec_utils.AUTH_ALGORITHM_MAP_P[
                    ikepolicy['auth_algorithm']]],
                ike_version=ipsec_utils.IKE_VERSION_MAP[
                    ikepolicy['ike_version']],
                dh_groups=[ipsec_utils.PFS_MAP_P[ikepolicy['pfs']]],
                sa_life_time=ikepolicy['lifetime']['value'],
                tags=tags)
        except nsx_lib_exc.ManagerError as e:
            msg = _("Failed to create an ike profile: %s") % e
            raise nsx_exc.NsxPluginException(err_msg=msg)
        return profile_id

    def _delete_ike_profile(self, ikeprofile_id):
        try:
            self._nsx_vpn.ike_profile.delete(ikeprofile_id)
        except nsx_lib_exc.ResourceInUse:
            # Still in use by another connection
            LOG.info("IKE profile %s cannot be deleted yet, because "
                     "another connection still uses it", ikeprofile_id)

    def _create_ipsec_profile(self, context, connection):
        """Create a tunnel profile for a connection
        Creating/overwriting tunnel profile based on the openstack ipsec policy
        upon connection creation.
        There is no driver callback for profiles creation so it has to be
        done on connection creation.
        """
        ipsec_policy_id = connection['ipsecpolicy_id']
        ipsecpolicy = self.vpn_plugin.get_ipsecpolicy(
            context, ipsec_policy_id)
        tags = self._nsxpolicy.build_v3_tags_payload(
            ipsecpolicy, resource_type='os-vpn-ipsecpol-id',
            project_name=context.tenant_name)

        try:
            profile_id = self._nsx_vpn.tunnel_profile.create_or_overwrite(
                ipsecpolicy['name'] or ipsecpolicy['id'],
                profile_id=ipsecpolicy['id'],
                description=ipsecpolicy['description'],
                encryption_algorithms=[ipsec_utils.ENCRYPTION_ALGORITHM_MAP[
                    ipsecpolicy['encryption_algorithm']]],
                digest_algorithms=[ipsec_utils.AUTH_ALGORITHM_MAP_P[
                    ipsecpolicy['auth_algorithm']]],
                dh_groups=[ipsec_utils.PFS_MAP_P[ipsecpolicy['pfs']]],
                sa_life_time=ipsecpolicy['lifetime']['value'],
                tags=tags)
        except nsx_lib_exc.ManagerError as e:
            msg = _("Failed to create a tunnel profile: %s") % e
            raise nsx_exc.NsxPluginException(err_msg=msg)
        return profile_id

    def _delete_ipsec_profile(self, ipsecprofile_id):
        try:
            self._nsx_vpn.tunnel_profile.delete(ipsecprofile_id)
        except nsx_lib_exc.ResourceInUse:
            # Still in use by another connection
            LOG.info("Tunnel profile %s cannot be deleted yet, because "
                     "another connection still uses it", ipsecprofile_id)

    def _create_dpd_profile(self, context, connection):
        """Create a DPD profile for a connection
        Creating/overwriting DPD profile based on the openstack ipsec
        connection configuration upon connection creation.
        There is no driver callback for profiles creation so it has to be
        done on connection creation.
        """
        # TODO(asarfaty) consider reusing profiles based on values
        dpd_info = connection['dpd']
        try:
            profile_id = self._nsx_vpn.dpd_profile.create_or_overwrite(
                self._get_dpd_profile_name(connection),
                profile_id=connection['id'],
                description='neutron dpd profile %s' % connection['id'],
                dpd_probe_interval=dpd_info.get('timeout'),
                enabled=bool(dpd_info.get('action') == 'hold'),
                tags=self._nsx_tags(context, connection))
        except nsx_lib_exc.ManagerError as e:
            msg = _("Failed to create a DPD profile: %s") % e
            raise nsx_exc.NsxPluginException(err_msg=msg)

        return profile_id

    def _delete_dpd_profile(self, dpdprofile_id):
        self._nsx_vpn.dpd_profile.delete(dpdprofile_id)

    def _update_dpd_profile(self, connection):
        dpd_info = connection['dpd']
        self._nsx_vpn.dpd_profile.update(
            connection['id'],
            name=self._get_dpd_profile_name(connection),
            dpd_probe_interval=dpd_info.get('timeout'),
            enabled=bool(dpd_info.get('action') == 'hold'))

    def _create_local_endpoint(self, context, connection, vpnservice):
        """Creating/overwrite an NSX local endpoint for a logical router

        This endpoint can be reused by other connections, and will be deleted
        when the router vpn service is deleted.
        """
        # use the router GW as the local ip
        router_id = vpnservice['router']['id']
        local_addr = vpnservice['external_v4_ip']

        # Add the neutron router-id to the tags to help search later
        tags = self._nsxpolicy.build_v3_tags_payload(
            {'id': router_id, 'project_id': vpnservice['project_id']},
            resource_type='os-neutron-router-id',
            project_name=context.tenant_name)

        try:
            ep_client = self._nsx_vpn.local_endpoint
            local_endpoint_id = ep_client.create_or_overwrite(
                'Local endpoint for OS VPNaaS on router %s' % router_id,
                router_id,
                router_id,
                endpoint_id=router_id,
                local_address=local_addr,
                tags=tags)
        except nsx_lib_exc.ManagerError as e:
            msg = _("Failed to create a local endpoint: %s") % e
            raise nsx_exc.NsxPluginException(err_msg=msg)

        return local_endpoint_id

    def _delete_local_endpoint(self, vpnservice):
        router_id = vpnservice['router']['id']
        ctx = n_context.get_admin_context()
        port = self._find_vpn_service_port(ctx, router_id)
        if port:
            self._nsx_vpn.local_endpoint.delete(
                router_id, router_id, router_id)
            self.l3_plugin.delete_port(ctx, port['id'], force_delete_vpn=True)

    def _get_session_rules(self, context, connection):
        peer_cidrs = self.validator._get_peer_cidrs(context, connection)
        local_cidrs = self.validator._get_local_cidrs(context, connection)
        rule = self._nsx_vpn.session.build_rule(
            connection['name'] or connection['id'], connection['id'],
            source_cidrs=local_cidrs, destination_cidrs=peer_cidrs)
        return [rule]

    def _create_session(self, context, connection, vpnservice, local_ep_id,
                        ikeprofile_id, ipsecprofile_id, dpdprofile_id,
                        rules, enabled=True):
        try:
            router_id = vpnservice['router_id']
            session_id = self._nsx_vpn.session.create_or_overwrite(
                connection['name'] or connection['id'],
                tier1_id=router_id,
                vpn_service_id=router_id,
                session_id=connection['id'],
                description=connection['description'],
                peer_address=connection['peer_address'],
                peer_id=connection['peer_id'],
                psk=connection['psk'],
                rules=rules,
                dpd_profile_id=dpdprofile_id,
                ike_profile_id=ikeprofile_id,
                tunnel_profile_id=ipsecprofile_id,
                local_endpoint_id=local_ep_id,
                enabled=enabled,
                tags=self._nsx_tags(context, connection))
        except nsx_lib_exc.ManagerError as e:
            msg = _("Failed to create a session: %s") % e
            raise nsx_exc.NsxPluginException(err_msg=msg)

        return session_id

    def _update_session(self, connection, vpnservice, rules=None,
                        enabled=True):
        router_id = vpnservice['router_id']
        args = {'enabled': enabled}
        if rules is not None:
            args['rules'] = rules
        self._nsx_vpn.session.update(
            router_id, router_id, connection['id'],
            name=connection['name'] or connection['id'],
            description=connection['description'],
            peer_address=connection['peer_address'],
            peer_id=connection['peer_id'],
            psk=connection['psk'],
            **args)

    def get_ipsec_site_connection_status(self, context, ipsec_site_conn_id):
        # find out the router-id of this connection
        conn = self.vpn_plugin._get_ipsec_site_connection(
            context, ipsec_site_conn_id)
        vpnservice_id = conn.vpnservice_id
        vpnservice = self.service_plugin._get_vpnservice(
            context, vpnservice_id)
        router_id = vpnservice['router_id']
        # Get the NSX detailed status
        try:
            status_result = self._nsx_vpn.session.get_status(
                router_id, router_id, ipsec_site_conn_id)
            if status_result and 'results' in status_result:
                status = status_result['results'][0].get('runtime_status', '')
                # NSX statuses are UP, DOWN, DEGRADE
                # VPNaaS connection status should be ACTIVE or DOWN
                if status == 'UP':
                    return 'ACTIVE'
                if status == 'DOWN' or status == 'DEGRADED':
                    return 'DOWN'
        except nsx_lib_exc.ResourceNotFound:
            LOG.debug("Status for VPN session %s was not found",
                      ipsec_site_conn_id)

    def _delete_session(self, vpnservice, session_id):
        router_id = vpnservice['router_id']
        self._nsx_vpn.session.delete(router_id, router_id, session_id)

    def create_ipsec_site_connection(self, context, ipsec_site_conn):
        LOG.debug('Creating ipsec site connection %(conn_info)s.',
                  {"conn_info": ipsec_site_conn})
        # Note(asarfaty) the plugin already calls the validator
        # which also validated the policies and service

        ikeprofile_id = None
        ipsecprofile_id = None
        dpdprofile_id = None
        session_id = None
        vpnservice_id = ipsec_site_conn['vpnservice_id']
        vpnservice = self.service_plugin._get_vpnservice(
            context, vpnservice_id)
        ipsec_id = ipsec_site_conn["id"]

        try:
            # create the ike profile
            ikeprofile_id = self._create_ike_profile(
                context, ipsec_site_conn)
            LOG.debug("Created NSX ike profile %s", ikeprofile_id)

            # create the ipsec profile
            ipsecprofile_id = self._create_ipsec_profile(
                context, ipsec_site_conn)
            LOG.debug("Created NSX ipsec profile %s", ipsecprofile_id)

            # create the dpd profile
            dpdprofile_id = self._create_dpd_profile(
                context, ipsec_site_conn)
            LOG.debug("Created NSX dpd profile %s", dpdprofile_id)

            # create or reuse a local endpoint using the vpn service
            local_ep_id = self._create_local_endpoint(
                context, ipsec_site_conn, vpnservice)

            # Finally: create the session with policy rules
            rules = self._get_session_rules(context, ipsec_site_conn)
            connection_enabled = (vpnservice['admin_state_up'] and
                                  ipsec_site_conn['admin_state_up'])
            self._create_session(
                context, ipsec_site_conn, vpnservice,
                local_ep_id, ikeprofile_id,
                ipsecprofile_id, dpdprofile_id, rules,
                enabled=connection_enabled)

            self._update_status(context, vpnservice_id, ipsec_id,
                                constants.ACTIVE)

        except nsx_exc.NsxPluginException:
            with excutils.save_and_reraise_exception():
                self._update_status(context, vpnservice_id, ipsec_id,
                                    constants.ERROR)
                # delete the NSX objects that were already created
                # Do not delete reused objects: service, local endpoint
                if session_id:
                    self._delete_session(vpnservice, session_id)
                if dpdprofile_id:
                    self._delete_dpd_profile(dpdprofile_id)
                if ipsecprofile_id:
                    self._delete_ipsec_profile(ipsecprofile_id)
                if ikeprofile_id:
                    self._delete_ike_profile(ikeprofile_id)

        # update router firewall rules
        self._update_firewall_rules(context, vpnservice, ipsec_site_conn)

        # update router advertisement rules
        self.update_router_advertisement(context, vpnservice['router_id'])

    def delete_ipsec_site_connection(self, context, ipsec_site_conn):
        LOG.debug('Deleting ipsec site connection %(site)s.',
                  {"site": ipsec_site_conn})

        vpnservice_id = ipsec_site_conn['vpnservice_id']
        vpnservice = self.service_plugin._get_vpnservice(
            context, vpnservice_id)

        self._delete_session(vpnservice, ipsec_site_conn['id'])
        self._delete_dpd_profile(ipsec_site_conn['id'])
        self._delete_ipsec_profile(ipsec_site_conn['ipsecpolicy_id'])
        self._delete_ike_profile(ipsec_site_conn['ikepolicy_id'])

        # update router firewall rules
        self._update_firewall_rules(context, vpnservice, ipsec_site_conn,
                                    delete=True)

        # update router advertisement rules
        self.update_router_advertisement(context, vpnservice['router_id'])

    def update_ipsec_site_connection(self, context, old_ipsec_conn,
                                     ipsec_site_conn):
        LOG.debug('Updating ipsec site connection new %(site)s.',
                  {"site": ipsec_site_conn})
        LOG.debug('Updating ipsec site connection old %(site)s.',
                  {"site": old_ipsec_conn})

        # Note(asarfaty) the plugin already calls the validator
        # which also validated the policies and service
        # Note(asarfaty): the VPN plugin does not allow changing ike/tunnel
        # policy or the service of a connection during update.
        vpnservice_id = old_ipsec_conn['vpnservice_id']
        vpnservice = self.service_plugin._get_vpnservice(
            context, vpnservice_id)

        # check if the dpd configuration changed
        old_dpd = old_ipsec_conn['dpd']
        new_dpd = ipsec_site_conn['dpd']
        if (old_dpd['action'] != new_dpd['action'] or
            old_dpd['timeout'] != new_dpd['timeout'] or
            old_ipsec_conn['name'] != ipsec_site_conn['name']):
            self._update_dpd_profile(ipsec_site_conn)

        rules = self._get_session_rules(context, ipsec_site_conn)
        connection_enabled = (vpnservice['admin_state_up'] and
                              ipsec_site_conn['admin_state_up'])

        try:
            self._update_session(ipsec_site_conn, vpnservice, rules,
                                 enabled=connection_enabled)
        except nsx_lib_exc.ManagerError as e:
            self._update_status(context, vpnservice_id,
                                ipsec_site_conn['id'],
                                constants.ERROR)
            msg = _("Failed to update VPN session %(id)s: %(error)s") % {
                    "id": ipsec_site_conn['id'], "error": e}
            raise nsx_exc.NsxPluginException(err_msg=msg)

        if (ipsec_site_conn['peer_cidrs'] != old_ipsec_conn['peer_cidrs'] or
            ipsec_site_conn['peer_ep_group_id'] !=
            old_ipsec_conn['peer_ep_group_id']):
            # Update firewall
            self._update_firewall_rules(context, vpnservice, ipsec_site_conn)

        # No service updates. No need to update router advertisement rules

    def _create_vpn_service(self, context, vpnservice):
        """Create or overwrite tier1 vpn service
        The service is created on the TIER1 router attached to the service
        The NSX can keep only one service per tier1 router so we reuse it
        """
        router_id = vpnservice['router_id']
        tags = self._nsxpolicy.build_v3_tags_payload(
            {'id': router_id, 'project_id': vpnservice['project_id']},
            resource_type='os-neutron-router-id',
            project_name=context.tenant_name)

        self._nsx_vpn.service.create_or_overwrite(
            'Neutron VPN service for T1 router ' + router_id,
            router_id,
            vpn_service_id=router_id,
            enabled=True,
            ike_log_level=ipsec_utils.DEFAULT_LOG_LEVEL,
            tags=tags)

    def _should_delete_nsx_service(self, context, vpnservice):
        # Check that no neutron vpn-service is configured for the same router
        router_id = vpnservice['router_id']
        filters = {'router_id': [router_id]}
        services = self.vpn_plugin.get_vpnservices(
            context.elevated(), filters=filters)
        if not services:
            return True

    def _delete_vpn_service(self, context, vpnservice):
        router_id = vpnservice['router_id']
        try:
            self._nsx_vpn.service.delete(router_id, router_id)
        except Exception as e:
            LOG.error("Failed to delete VPN service %s: %s",
                      router_id, e)

        # check if service router should be deleted
        if not self._core_plugin.service_router_has_services(
                context.elevated(), router_id):
            self._core_plugin.delete_service_router(router_id)

    def create_vpnservice(self, context, new_vpnservice):
        LOG.info('Creating VPN service %(vpn)s', {'vpn': new_vpnservice})
        vpnservice_id = new_vpnservice['id']
        vpnservice = self.service_plugin._get_vpnservice(context,
                                                         vpnservice_id)
        try:
            self.validator.validate_vpnservice(context, vpnservice)
            local_address = self._get_service_local_address(
                context.elevated(), vpnservice)
        except Exception:
            with excutils.save_and_reraise_exception():
                # Rolling back change on the neutron
                self.service_plugin.delete_vpnservice(context, vpnservice_id)

        vpnservice['external_v4_ip'] = local_address
        self.service_plugin.set_external_tunnel_ips(context,
                                                    vpnservice_id,
                                                    v4_ip=local_address)

        # Make sure this tier1 has service router
        router_id = vpnservice['router_id']
        if not self._core_plugin.verify_sr_at_backend(context, router_id):
            self._core_plugin.create_service_router(context, router_id)

        # create the NSX vpn service
        try:
            self._create_vpn_service(context, vpnservice)
        except nsx_lib_exc.ManagerError as e:
            self._update_status(context, vpnservice_id, None, constants.ERROR)
            msg = _("Failed to create vpn service: %s") % e
            raise nsx_exc.NsxPluginException(err_msg=msg)

        # update neutron vpnservice status to active
        self._update_status(context, vpnservice_id, None, constants.ACTIVE)

    def update_vpnservice(self, context, old_vpnservice, vpnservice):
        # Only handle the case of admin-state-up changes
        if old_vpnservice['admin_state_up'] != vpnservice['admin_state_up']:
            # update all relevant connections
            filters = {'vpnservice_id': [vpnservice['id']]}
            connections = self.vpn_plugin.get_ipsec_site_connections(
                context, filters=filters)
            for conn in connections:
                connection_enabled = (vpnservice['admin_state_up'] and
                                      conn['admin_state_up'])
                self._update_session(conn, vpnservice,
                                     enabled=connection_enabled)

    def delete_vpnservice(self, context, vpnservice):
        if self._should_delete_nsx_service(context, vpnservice):
            self._delete_local_endpoint(vpnservice)
            self._delete_vpn_service(context, vpnservice)
        self._delete_service_local_cidr_group(vpnservice)

    def validate_router_gw_info(self, context, router_id, gw_info):
        """Upon router gw update verify no overlapping subnets to advertise"""
        # check if this router has a vpn service
        admin_con = context.elevated()
        # get all relevant services, except those waiting to be deleted or in
        # ERROR state
        filters = {'router_id': [router_id],
                   'status': [constants.ACTIVE, constants.PENDING_CREATE,
                              constants.INACTIVE, constants.PENDING_UPDATE]}
        services = self.vpn_plugin.get_vpnservices(admin_con, filters=filters)
        if not services:
            # This is a non-vpn router. if snat was disabled, should check
            # there is no overlapping with vpn connections advertised
            if (gw_info and
                not gw_info.get('enable_snat',
                                cfg.CONF.enable_snat_by_default)):
                # get router subnets
                subnets = self._core_plugin._find_router_subnets_cidrs(
                    context, router_id)
                # find all vpn services with connections
                if not self._check_subnets_overlap_with_all_conns(
                    admin_con, subnets):
                    raise common_driver.RouterWithOverlapNoSnat(
                        router_id=router_id)
