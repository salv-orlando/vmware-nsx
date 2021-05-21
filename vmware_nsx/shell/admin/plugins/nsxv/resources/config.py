# Copyright 2017 VMware, Inc.  All rights reserved.
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

import sys

from neutron_lib.callbacks import registry
from oslo_config import cfg
from oslo_log import log as logging
from oslo_vmware import vim_util

from vmware_nsx.dvs import dvs
from vmware_nsx.plugins.nsx_v.vshield.common import exceptions
from vmware_nsx.shell.admin.plugins.common import constants
from vmware_nsx.shell.admin.plugins.common import utils as admin_utils
from vmware_nsx.shell.admin.plugins.nsxv.resources import utils
from vmware_nsx.shell import resources as shell

LOG = logging.getLogger(__name__)


@admin_utils.output_header
def validate_configuration(resource, event, trigger, **kwargs):
    """Validate the nsxv configuration"""
    try:
        utils.NsxVPluginWrapper()
    except exceptions.Forbidden:
        LOG.error("Configuration validation failed: wrong VSM credentials "
                  "for %s", cfg.CONF.nsxv.manager_uri)
    except Exception as e:
        LOG.error("Configuration validation failed: %s", e)
    else:
        LOG.info("Configuration validation succeeded")


def check_clusters(resource, event, trigger, **kwargs):
    clusters_str = ""
    if kwargs.get('property'):
        properties = admin_utils.parse_multi_keyval_opt(kwargs['property'])
        clusters_str = properties.get('clusters', None)

    if not clusters_str:
        LOG.error("No cluster to look for was specified")
        return

    clusters = clusters_str.split(",")
    mgr = dvs.VCManagerBase()
    session = mgr.get_vc_session()
    data = session.invoke_api(vim_util, 'get_objects', session.vim,
                              'ClusterComputeResource', 100)
    while data:
        for item in data.objects:
            if item.obj.value in clusters[:]:
                clusters.remove(item.obj.value)
        data = vim_util.continue_retrieval(session.vim, data)
    if not clusters:
        LOG.info("Clusters %s found on VC backend", clusters_str)
    else:
        LOG.error("Clusters %s not found on VC backend", ",".join(clusters))
        sys.exit(1)


registry.subscribe(validate_configuration,
                   constants.CONFIG,
                   shell.Operations.VALIDATE.value)

registry.subscribe(check_clusters,
                   constants.CONFIG,
                   shell.Operations.CHECK_COMPUTE_CLUSTERS.value)
