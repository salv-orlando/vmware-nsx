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
from neutron_lib import exceptions as n_exc
from oslo_log import log as logging

from vmware_nsx._i18n import _
from vmware_nsx.services.lbaas import lb_const

LOG = logging.getLogger(__name__)


def validate_session_persistence(pool, listener, completor):
    sp = pool.get('session_persistence')
    LOG.debug("validate_session_persistence called with session_persistence "
              "%s", sp)
    if not listener or not sp:
        # safety first!
        return
    # L4 listeners only allow source IP persistence
    # (HTTPS is also considers L4 listener)
    if ((listener['protocol'] == lb_const.LB_PROTOCOL_TCP or
         listener['protocol'] == lb_const.LB_PROTOCOL_HTTPS) and
        sp['type'] != lb_const.LB_SESSION_PERSISTENCE_SOURCE_IP):
        completor(success=False)
        msg = (_("Invalid session persistence type %(sp_type)s for "
                 "pool on listener %(lst_id)s with %(proto)s protocol") %
               {'sp_type': sp['type'],
                'lst_id': listener['id'],
                'proto': listener['protocol']})
        raise n_exc.BadRequest(resource='lbaas-pool', msg=msg)


def session_persistence_type_changed(pool, old_pool):
    cookie_pers_types = (lb_const.LB_SESSION_PERSISTENCE_HTTP_COOKIE,
                         lb_const.LB_SESSION_PERSISTENCE_APP_COOKIE)
    sp = pool.get('session_persistence')
    if not sp:
        return False
    if old_pool:
        oldsp = old_pool.get('session_persistence')
        if not oldsp:
            return False
        if ((sp['type'] == lb_const.LB_SESSION_PERSISTENCE_SOURCE_IP and
             oldsp['type'] in cookie_pers_types) or
                (sp['type'] in cookie_pers_types and
                 oldsp['type'] == lb_const.LB_SESSION_PERSISTENCE_SOURCE_IP)):
            return True
    return False


def get_listener_cert_ref(listener):
    return listener.get('default_tls_container_id',
                        listener.get('default_tls_container_ref'))
