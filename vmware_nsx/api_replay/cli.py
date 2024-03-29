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

import argparse

from vmware_nsx.api_replay import client

DEFAULT_DOMAIN_ID = 'default'
DEFAULT_LOGFILE = 'nsx_migration.log'


class ApiReplayCli(object):

    def __init__(self):
        args = self._setup_argparse()

        # args validation
        if not args.dest_os_endpoint_url:
            # auth params are mandatory
            if (not args.dest_os_project_name or
                not args.dest_os_username or
                not args.dest_os_password or
                not args.dest_os_username or
                not args.dest_os_auth_url):
                print("missing destination mandatory auth parameters")
                return

        client.ApiReplayClient(
            source_os_tenant_name=args.source_os_project_name,
            source_os_tenant_domain_id=args.source_os_project_domain_id,
            source_os_username=args.source_os_username,
            source_os_user_domain_id=args.source_os_user_domain_id,
            source_os_password=args.source_os_password,
            source_os_auth_url=args.source_os_auth_url,
            dest_os_tenant_name=args.dest_os_project_name,
            dest_os_tenant_domain_id=args.dest_os_project_domain_id,
            dest_os_username=args.dest_os_username,
            dest_os_user_domain_id=args.dest_os_user_domain_id,
            dest_os_password=args.dest_os_password,
            dest_os_auth_url=args.dest_os_auth_url,
            dest_os_endpoint_url=args.dest_os_endpoint_url,
            dest_plugin=args.dest_plugin,
            enable_barbican=args.enable_barbican,
            use_old_keystone=args.use_old_keystone,
            octavia_os_tenant_name=args.octavia_os_project_name,
            octavia_os_tenant_domain_id=args.octavia_os_project_domain_id,
            octavia_os_username=args.octavia_os_username,
            octavia_os_user_domain_id=args.octavia_os_user_domain_id,
            octavia_os_password=args.octavia_os_password,
            octavia_os_auth_url=args.octavia_os_auth_url,
            neutron_conf=args.neutron_conf,
            ext_net_map=args.external_networks_map,
            net_vni_map=args.networks_vni_map,
            int_vni_map=args.internal_networks_vni_map,
            vif_ids_map=args.vif_ids_map,
            logfile=args.logfile,
            max_retry=args.max_retry,
            cert_file=args.cert_file)

    def _setup_argparse(self):
        parser = argparse.ArgumentParser()

        # Arguments required to connect to source
        # neutron which we will fetch all of the data from.
        parser.add_argument(
            "--source-os-username",
            required=True,
            help="The source os-username to use to "
                 "gather neutron resources with.")
        parser.add_argument(
            "--source-os-user-domain-id",
            default=DEFAULT_DOMAIN_ID,
            help="The source os-user-domain-id to use to "
                 "gather neutron resources with.")
        parser.add_argument(
            "--source-os-project-name",
            required=True,
            help="The source os-project-name to use to "
                 "gather neutron resource with.")
        parser.add_argument(
            "--source-os-project-domain-id",
            default=DEFAULT_DOMAIN_ID,
            help="The source os-project-domain-id to use to "
                 "gather neutron resource with.")
        parser.add_argument(
            "--source-os-password",
            required=True,
            help="The password for this user.")
        parser.add_argument(
            "--source-os-auth-url",
            required=True,
            help="They keystone api endpoint for this user.")

        # Arguments required to connect to the dest neutron which
        # we will recreate all of these resources over.
        parser.add_argument(
            "--dest-os-username",
            help="The dest os-username to use to"
                 "gather neutron resources with.")
        parser.add_argument(
            "--dest-os-user-domain-id",
            default=DEFAULT_DOMAIN_ID,
            help="The dest os-user-domain-id to use to"
                 "gather neutron resources with.")
        parser.add_argument(
            "--dest-os-project-name",
            help="The dest os-project-name to use to "
                 "gather neutron resource with.")
        parser.add_argument(
            "--dest-os-project-domain-id",
            default=DEFAULT_DOMAIN_ID,
            help="The dest os-project-domain-id to use to "
                 "gather neutron resource with.")
        parser.add_argument(
            "--dest-os-password",
            help="The password for this user.")
        parser.add_argument(
            "--dest-os-auth-url",
            help="The keystone api endpoint for this user.")
        parser.add_argument(
            "--dest-os-endpoint-url",
            help="The destination neutron api endpoint. If provided noauth "
                 "calls will be made")
        parser.add_argument(
            "--dest-plugin",
            default='nsx-p',
            help="The core plugin of the destination nsx-t/nsx-p.")

        parser.add_argument(
            "--use-old-keystone",
            default=False,
            action='store_true',
            help="Use old keystone client for source authentication.")
        parser.add_argument(
            "--cert-file",
            default="",
            help="certificate file for the authentication.")

        # Arguments required to connect to the octavia client (read only)
        parser.add_argument(
            "--octavia-os-username",
            help="The octavia os-username to use to "
                 "gather loadbalancers resources with.")
        parser.add_argument(
            "--octavia-os-user-domain-id",
            default=DEFAULT_DOMAIN_ID,
            help="The octavia os-user-domain-id to use to "
                 "gather loadbalancers resources with.")
        parser.add_argument(
            "--octavia-os-project-name",
            help="The octavia os-project-name to use to "
                 "gather loadbalancers resource with.")
        parser.add_argument(
            "--octavia-os-project-domain-id",
            default=DEFAULT_DOMAIN_ID,
            help="The octavia os-project-domain-id to use to "
                 "gather loadbalancers resource with.")
        parser.add_argument(
            "--octavia-os-password",
            help="The password for this octavia user.")
        parser.add_argument(
            "--octavia-os-auth-url",
            help="They keystone api endpoint for this octavia user.")

        parser.add_argument(
            "--logfile",
            default=DEFAULT_LOGFILE,
            help="Output logfile.")

        parser.add_argument(
            "--neutron_conf",
            default='/etc/neutron/neutron.conf',
            help="neutron config file path.")

        parser.add_argument(
            "--external-networks-map",
            help="Path to a json file mapping external network neutron ID "
                 "to tier0 ID.")
        parser.add_argument(
            "--networks-vni-map",
            help="Path to a json file mapping neutron network ID to its "
                 "backend vni.")
        parser.add_argument(
            "--internal-networks-vni-map",
            help="Path to a json file mapping internal network ID "
                 "to its backend vni.")
        parser.add_argument(
            "--vif-ids-map",
            help="Path to a json file mapping compute ports ids to the "
                 "expected vif ids.")

        parser.add_argument(
            "--max-retry",
            default=10,
            help="Maximum number of retrying different operations.")
        parser.add_argument(
            "--enable-barbican",
            default=False,
            action='store_true',
            help="Meh")

        # NOTE: this will return an error message if any of the
        # require options are missing.
        return parser.parse_args()


def main():
    ApiReplayCli()
