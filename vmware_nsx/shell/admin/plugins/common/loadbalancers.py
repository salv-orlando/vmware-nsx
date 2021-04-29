# Copyright 2021 VMware, Inc.
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

from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging as messaging

from vmware_nsx.services.lbaas.octavia import constants as octavia_const
from vmware_nsx.shell.admin.plugins.common import utils as admin_utils

LOG = logging.getLogger(__name__)


@admin_utils.output_header
def set_loadbalancer_status_error(resource, event, trigger, **kwargs):
    usage_msg = ("Loadbalancer id should be specified with "
                 "--property loadbalancer-id=<id>")
    if not kwargs.get('property'):
        LOG.error(usage_msg)
        return
    properties = admin_utils.parse_multi_keyval_opt(kwargs['property'])
    lb_id = properties.get('loadbalancer-id')
    if not lb_id:
        LOG.error("Need to specify loadbalancer-id. "
                  "Add --property loadbalancer-id=<id>")
        return

    status_dict = {
        octavia_const.LOADBALANCERS: [{
            'id': lb_id,
            octavia_const.PROVISIONING_STATUS: octavia_const.ERROR}]}
    kw = {'status': status_dict}

    topic = octavia_const.DRIVER_TO_OCTAVIA_TOPIC
    transport = messaging.get_rpc_transport(cfg.CONF)
    target = messaging.Target(topic=topic, exchange="common",
                              namespace='control', fanout=False,
                              version='1.0')
    client = messaging.RPCClient(transport, target)
    client.cast({}, 'update_loadbalancer_status', **kw)
