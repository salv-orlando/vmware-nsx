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

from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import excutils

from neutron.services.trunk.drivers import base
from neutron_lib.api.definitions import portbindings
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants
from neutron_lib.services.trunk import constants as trunk_consts

from vmware_nsx._i18n import _
from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.common import utils as nsx_utils
from vmware_nsx.extensions import projectpluginmap
from vmware_nsxlib.v3 import exceptions as nsxlib_exc
from vmware_nsxlib.v3.policy import constants as p_constants
from vmware_nsxlib.v3 import utils as nsxlib_utils

LOG = logging.getLogger(__name__)

SUPPORTED_INTERFACES = (
    portbindings.VIF_TYPE_OVS,
)
SUPPORTED_SEGMENTATION_TYPES = (
    trunk_consts.SEGMENTATION_TYPE_VLAN,
)

DRIVER_NAME = 'vmware_nsxp_trunk'
TRUNK_ID_TAG_NAME = 'os-neutron-trunk-id'


class NsxpTrunkHandler(object):
    def __init__(self, plugin_driver):
        self.plugin_driver = plugin_driver

    def _get_port_tags_and_network(self, context, port_id):
        _, tags, net = self._get_port_compute_tags_and_net(context, port_id)
        return tags, net

    def _get_port_compute_tags_and_net(self, context, port_id):
        port = self.plugin_driver.get_port(context, port_id)
        segment_id = self.plugin_driver._get_network_nsx_segment_id(
            context, port['network_id'])
        lport = self.plugin_driver.nsxpolicy.segment_port.get(
            segment_id, port_id)
        is_compute = port.get('device_owner', '').startswith(
            constants.DEVICE_OWNER_COMPUTE_PREFIX)
        return is_compute, segment_id, lport.get('tags', [])

    def _update_tags(self, port_id, tags, tags_update, is_delete=False):
        if is_delete:
            tags = [tag for tag in tags if tag not in tags_update]
        else:
            for tag in tags:
                for tag_u in tags_update:
                    if tag_u['scope'] == tag['scope']:
                        tag['tag'] = tag_u['tag']
                        tags_update.remove(tag_u)
                        break

            tags.extend(
                [tag for tag in tags_update if tag not in tags])
            if len(tags) > nsxlib_utils.MAX_TAGS:
                LOG.warning("Cannot add external tags to port %s: "
                            "too many tags", port_id)
        return tags

    def _set_subports(self, context, parent_port_id, subports):
        for subport in subports:
            # Update port with parent port for backend.

            # Set properties for VLAN trunking
            if subport.segmentation_type == nsx_utils.NsxV3NetworkTypes.VLAN:
                seg_id = subport.segmentation_id
            else:
                msg = (_("Cannot create a subport %s with no segmentation"
                         " id") % subport.port_id)
                LOG.error(msg)
                raise nsx_exc.NsxPluginException(err_msg=msg)

            tags_update = [{'scope': TRUNK_ID_TAG_NAME,
                            'tag': subport.trunk_id}]

            segment_id, tags = self._get_port_tags_and_network(
                context, subport.port_id)

            tags = self._update_tags(
                subport.port_id, tags, tags_update, is_delete=False)

            # Update logical port in the backend to set/unset parent port
            try:
                self.plugin_driver.nsxpolicy.segment_port.attach(
                    segment_id,
                    subport.port_id,
                    p_constants.ATTACHMENT_CHILD,
                    subport.port_id,
                    context_id=parent_port_id,
                    traffic_tag=seg_id,
                    tags=tags)

            except nsxlib_exc.ManagerError as e:
                with excutils.save_and_reraise_exception():
                    LOG.error("Unable to update subport for attachment "
                              "type. Exception is %s", e)

    def _unset_subports(self, context, subports):
        for subport in subports:
            # Update port and remove parent port attachment in the backend
            # Unset the parent port properties from child port

            tags_update = [{'scope': TRUNK_ID_TAG_NAME,
                            'tag': subport.trunk_id}]

            is_compute, segment_id, tags = self._get_port_compute_tags_and_net(
                context, subport.port_id)

            tags = self._update_tags(
                subport.port_id, tags, tags_update, is_delete=True)

            # Update logical port in the backend to set/unset parent port
            vif_id = None
            if is_compute:
                vif_id = subport.port_id
            try:
                self.plugin_driver.nsxpolicy.segment_port.detach(
                    segment_id, subport.port_id, vif_id=vif_id, tags=tags)

            except nsxlib_exc.ManagerError as e:
                with excutils.save_and_reraise_exception():
                    LOG.error("Unable to update subport for attachment "
                              "type. Exception is %s", e)

    def trunk_created(self, context, trunk):
        tags_update = [{'scope': TRUNK_ID_TAG_NAME, 'tag': trunk.id}]
        segment_id, tags = self._get_port_tags_and_network(
            context, trunk.port_id)

        tags = self._update_tags(
            trunk.port_id, tags, tags_update, is_delete=False)

        try:
            self.plugin_driver.nsxpolicy.segment_port.attach(
                    segment_id,
                    trunk.port_id,
                    vif_id=trunk.port_id,
                    attachment_type=p_constants.ATTACHMENT_PARENT,
                    tags=tags)
        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.error("Parent port attachment for trunk %(trunk)s failed "
                          "with error %(e)s", {'trunk': trunk.id, 'e': e})

        if trunk.sub_ports:
            self.subports_added(context, trunk, trunk.sub_ports)

    def trunk_deleted(self, context, trunk):
        tags_update = [{'scope': TRUNK_ID_TAG_NAME, 'tag': trunk.id}]

        is_compute, segment_id, tags = self._get_port_compute_tags_and_net(
            context, trunk.port_id)

        tags = self._update_tags(
            trunk.port_id, tags, tags_update, is_delete=True)

        try:
            vif_id = None
            if is_compute:
                vif_id = trunk.port_id
            self.plugin_driver.nsxpolicy.segment_port.detach(
                segment_id, trunk.port_id, vif_id=vif_id, tags=tags)
        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.error("Parent port detachment for trunk %(trunk)s failed "
                          "with error %(e)s", {'trunk': trunk.id, 'e': e})

        self.subports_deleted(context, trunk, trunk.sub_ports)

    def subports_added(self, context, trunk, subports):
        try:
            self._set_subports(context, trunk.port_id, subports)
            trunk.update(status=trunk_consts.TRUNK_ACTIVE_STATUS)
        except (nsxlib_exc.ManagerError, nsxlib_exc.ResourceNotFound):
            trunk.update(status=trunk_consts.TRUNK_ERROR_STATUS)

    def subports_deleted(self, context, trunk, subports):
        try:
            self._unset_subports(context, subports)
        except (nsxlib_exc.ManagerError, nsxlib_exc.ResourceNotFound):
            trunk.update(status=trunk_consts.TRUNK_ERROR_STATUS)

    def trunk_event(self, resource, event, trunk_plugin, payload):
        if event == events.AFTER_CREATE:
            self.trunk_created(payload.context, payload.current_trunk)
        elif event == events.AFTER_DELETE:
            self.trunk_deleted(payload.context, payload.original_trunk)

    def subport_event(self, resource, event, trunk_plugin, payload):
        if event == events.AFTER_CREATE:
            self.subports_added(
                payload.context, payload.original_trunk, payload.subports)
        elif event == events.AFTER_DELETE:
            self.subports_deleted(
                payload.context, payload.original_trunk, payload.subports)


class NsxpTrunkDriver(base.DriverBase):
    """Driver to implement neutron's trunk extensions."""

    @property
    def is_loaded(self):
        try:
            plugin_type = self.plugin_driver.plugin_type()
            return plugin_type == projectpluginmap.NsxPlugins.NSX_P
        except cfg.NoSuchOptError:
            return False

    @classmethod
    def create(cls, plugin_driver):
        cls.plugin_driver = plugin_driver
        return cls(DRIVER_NAME, SUPPORTED_INTERFACES,
                   SUPPORTED_SEGMENTATION_TYPES,
                   agent_type=None, can_trunk_bound_port=True)

    @registry.receives(resources.TRUNK_PLUGIN, [events.AFTER_INIT])
    def register(self, resource, event, trigger, payload=None):
        super(NsxpTrunkDriver, self).register(
            resource, event, trigger, payload=payload)
        self._handler = NsxpTrunkHandler(self.plugin_driver)
        for event in (events.AFTER_CREATE, events.AFTER_DELETE):
            registry.subscribe(self._handler.trunk_event,
                               resources.TRUNK,
                               event)
            registry.subscribe(self._handler.subport_event,
                               resources.SUBPORTS,
                               event)
        LOG.debug("VMware NSXP trunk driver initialized.")
