# Copyright 2020 VMware, Inc.
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
import os
import random
import re

from oslo_config import cfg
from oslo_context import context as context_utils
from oslo_log import log as logging
from oslo_utils import fileutils

from neutron import version as n_version
from neutron_lib.api import validators
from neutron_lib import context as q_context

from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.plugins.nsx_v3 import cert_utils
from vmware_nsxlib import v3
from vmware_nsxlib.v3 import client_cert
from vmware_nsxlib.v3 import config
from vmware_nsxlib.v3 import policy

LOG = logging.getLogger(__name__)

OS_NEUTRON_ID_SCOPE = 'os-neutron-id'
PORT_SG_SCOPE = 'os-security-group'

NSX_NEUTRON_PLUGIN = 'NSX Neutron plugin'


def get_DbCertProvider(conf_path):
    class DbCertProvider(client_cert.ClientCertProvider):
        """Write cert data from DB to file and delete after use

           New provider object with random filename is created for each
           request.
           This is not most efficient, but the safest way to avoid race
           conditions, since backend connections can occur both before and
           after neutron fork, and several concurrent requests can occupy the
           same thread.
           Note that new cert filename for each request does not result in new
           connection for each request (at least for now..)
        """
        EXPIRATION_ALERT_DAYS = 30          # days prior to expiration

        def __init__(self):
            super(DbCertProvider, self).__init__(None)
            random.seed()
            self._filename = '/tmp/.' + str(random.randint(1, 10000000))
            self.conf_path = conf_path

        def _check_expiration(self, expires_in_days):
            if expires_in_days > self.EXPIRATION_ALERT_DAYS:
                return

            if expires_in_days < 0:
                LOG.error("Client certificate has expired %d days ago.",
                          expires_in_days * -1)
            else:
                LOG.warning("Client certificate expires in %d days. "
                            "Once expired, service will become unavailable.",
                            expires_in_days)

        def __enter__(self):
            try:
                context = q_context.get_admin_context()
                db_storage_driver = cert_utils.DbCertificateStorageDriver(
                    context, self.conf_path.nsx_client_cert_pk_password)
                with client_cert.ClientCertificateManager(
                    cert_utils.NSX_OPENSTACK_IDENTITY,
                    None,
                    db_storage_driver) as cert_manager:
                    if not cert_manager.exists():
                        msg = _("Unable to load from nsx-db")
                        raise nsx_exc.ClientCertificateException(err_msg=msg)

                    filename = self._filename
                    if not os.path.exists(os.path.dirname(filename)):
                        if len(os.path.dirname(filename)) > 0:
                            fileutils.ensure_tree(os.path.dirname(filename))
                    cert_manager.export_pem(filename)

                    expires_in_days = cert_manager.expires_in_days()
                    self._check_expiration(expires_in_days)
            except Exception as e:
                self._on_exit()
                raise e

            return self

        def _on_exit(self):
            if os.path.isfile(self._filename):
                os.remove(self._filename)

            self._filename = None

        def __exit__(self, type, value, traceback):
            self._on_exit()

        def filename(self):
            return self._filename

    return DbCertProvider


def get_client_cert_provider(conf_path=cfg.CONF.nsx_v3):
    if not conf_path.nsx_use_client_auth:
        return None

    if conf_path.nsx_client_cert_storage.lower() == 'none':
        # Admin is responsible for providing cert file, the plugin
        # should not touch it
        return client_cert.ClientCertProvider(
                conf_path.nsx_client_cert_file)

    if conf_path.nsx_client_cert_storage.lower() == 'nsx-db':
        # Cert data is stored in DB, and written to file system only
        # when new connection is opened, and deleted immediately after.
        return get_DbCertProvider(conf_path)

    return None


def get_nsxlib_wrapper(nsx_username=None, nsx_password=None, basic_auth=False,
                       plugin_conf=None, allow_overwrite_header=False,
                       retriable_exceptions=None):
    if not plugin_conf:
        plugin_conf = cfg.CONF.nsx_v3

    client_cert_provider = None
    if not basic_auth:
        # if basic auth requested, dont use cert file even if provided
        client_cert_provider = get_client_cert_provider(conf_path=plugin_conf)

    exception_config = config.ExceptionConfig()
    if retriable_exceptions:
        exception_config.retriables = retriable_exceptions
    nsxlib_config = config.NsxLibConfig(
        username=nsx_username or plugin_conf.nsx_api_user,
        password=nsx_password or plugin_conf.nsx_api_password,
        client_cert_provider=client_cert_provider,
        retries=plugin_conf.http_retries,
        insecure=plugin_conf.insecure,
        ca_file=plugin_conf.ca_file,
        concurrent_connections=plugin_conf.concurrent_connections,
        http_timeout=plugin_conf.http_timeout,
        http_read_timeout=plugin_conf.http_read_timeout,
        conn_idle_timeout=plugin_conf.conn_idle_timeout,
        http_provider=None,
        max_attempts=plugin_conf.retries,
        nsx_api_managers=plugin_conf.nsx_api_managers,
        plugin_scope=OS_NEUTRON_ID_SCOPE,
        plugin_tag=NSX_NEUTRON_PLUGIN,
        plugin_ver=n_version.version_info.release_string(),
        dns_nameservers=cfg.CONF.nsx_v3.nameservers,
        dns_domain=cfg.CONF.nsx_v3.dns_domain,
        allow_overwrite_header=allow_overwrite_header,
        exception_config=exception_config)
    return v3.NsxLib(nsxlib_config)


def get_nsxpolicy_wrapper(nsx_username=None, nsx_password=None,
                          basic_auth=False, conf_path=None,
                          retriable_exceptions=None):
    if not conf_path:
        conf_path = cfg.CONF.nsx_p
    client_cert_provider = None
    if not basic_auth:
        # if basic auth requested, dont use cert file even if provided
        client_cert_provider = get_client_cert_provider(
            conf_path=conf_path)

    exception_config = config.ExceptionConfig()
    if retriable_exceptions:
        exception_config.retriables = retriable_exceptions

    nsxlib_config = config.NsxLibConfig(
        username=nsx_username or conf_path.nsx_api_user,
        password=nsx_password or conf_path.nsx_api_password,
        client_cert_provider=client_cert_provider,
        retries=conf_path.http_retries,
        insecure=conf_path.insecure,
        ca_file=conf_path.ca_file,
        concurrent_connections=conf_path.concurrent_connections,
        http_timeout=conf_path.http_timeout,
        http_read_timeout=conf_path.http_read_timeout,
        conn_idle_timeout=conf_path.conn_idle_timeout,
        http_provider=None,
        max_attempts=conf_path.retries,
        nsx_api_managers=conf_path.nsx_api_managers,
        plugin_scope=OS_NEUTRON_ID_SCOPE,
        plugin_tag=NSX_NEUTRON_PLUGIN,
        plugin_ver=n_version.version_info.release_string(),
        dns_nameservers=conf_path.nameservers,
        dns_domain=conf_path.dns_domain,
        exception_config=exception_config,
        allow_passthrough=(conf_path.allow_passthrough
                           if hasattr(conf_path, 'allow_passthrough')
                           else False),
        realization_max_attempts=(conf_path.realization_max_attempts
                                  if hasattr(conf_path,
                                             'realization_max_attempts')
                                  else 50),
        realization_wait_sec=(conf_path.realization_wait_sec
                              if hasattr(conf_path, 'realization_wait_sec')
                              else 1))
    return policy.NsxPolicyLib(nsxlib_config)


def inject_headers():
    ctx = context_utils.get_current()
    if ctx:
        ctx_dict = ctx.to_dict()
        # Remove unsupported characters from the user-id
        user_id = ctx_dict.get('user_identity')
        re.sub('[^A-Za-z0-9]+', '', user_id)
        return {'X-NSX-EUSER': user_id,
                'X-NSX-EREQID': ctx_dict.get('request_id')}
    return {}


def get_network_dns_domain(az, network):
    dns_domain = None
    if network.get('dns_domain'):
        net_dns = network['dns_domain']
        if isinstance(net_dns, str):
            dns_domain = net_dns
        elif hasattr(net_dns, "dns_domain"):
            dns_domain = net_dns.dns_domain
    if not dns_domain or not validators.is_attr_set(dns_domain):
        dns_domain = az.dns_domain
    return dns_domain


def build_dhcp_server_config(nsxlib, project_name, network, subnet, port, az):

    name = nsxlib.native_dhcp.build_server_name(
        network['name'], network['id'])

    net_tags = nsxlib.build_v3_tags_payload(
        network, resource_type='os-neutron-net-id',
        project_name=project_name)

    dns_domain = get_network_dns_domain(az, network)

    dns_nameservers = subnet['dns_nameservers']
    if not dns_nameservers or not validators.is_attr_set(dns_nameservers):
        dns_nameservers = az.nameservers

    # There must be exactly one fixed ip matching given subnet
    fixed_ip_addr = [fip['ip_address'] for fip in port['fixed_ips']
                     if fip['subnet_id'] == subnet['id']]
    return nsxlib.native_dhcp.build_server(
        name,
        ip_address=fixed_ip_addr[0],
        cidr=subnet['cidr'],
        gateway_ip=subnet['gateway_ip'],
        host_routes=subnet['host_routes'],
        dns_domain=dns_domain,
        dns_nameservers=dns_nameservers,
        dhcp_profile_id=az._native_dhcp_profile_uuid,
        tags=net_tags)
