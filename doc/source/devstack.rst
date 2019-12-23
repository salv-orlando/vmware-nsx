NSX DevStack Configurations
===========================

Below are the options for configuring the NSX plugin with DevStack. Prior
to doing this DevStack needs to be downloaded. After updating the relevant
configuration file(s) run ./stack.sh

NSX-V
-----

Mandatory basic configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Add those parameters in ``local.conf``::

    [[local|localrc]]
    enable_plugin vmware-nsx https://opendev.org/x/vmware-nsx
    Q_PLUGIN=vmware_nsx_v
    NSXV_MANAGER_URI=<URI>
    NSXV_USER=<username>
    NSXV_PASSWORD=<password>
    NSXV_VDN_SCOPE_ID=<Transport Zone UUID>
    NSXV_DVS_ID=<Distributed Switch UUID>
    NSXV_DATACENTER_MOID=<Data Center UUID>
    NSXV_DATASTORE_ID=<Data Store UUID>
    NSXV_RESOURCE_POOL_ID=<Resource Pool UUID>
    NSXV_EXTERNAL_NETWORK=<External Network UUID>
    NSXV_CLUSTER_MOID=<Edge Cluster UUID>

QoS Driver
~~~~~~~~~~

Enable the qos in ``local.conf``::

     [[local|localrc]]
     ENABLED_SERVICES+=,q-qos
     Q_SERVICE_PLUGIN_CLASSES+=,vmware_nsxv_qos
     NSXV_USE_DVS_FEATURES = True

Optional: Update the nsx qos_peak_bw_multiplier in nsx.ini (default value is 2.0)::

    [NSX]
    qos_peak_bw_multiplier = <i.e 10.0>

FWaaS (V2) Driver
~~~~~~~~~~~~~~~~~

Add neutron-fwaas repo as an external repository and configure following flags in ``local.conf``::

    [[local|localrc]]
    enable_plugin neutron-fwaas https://opendev.org/openstack/neutron-fwaas
    enable_service q-fwaas-v2
    Q_SERVICE_PLUGIN_CLASSES+=,firewall_v2

    [[post-config|$NEUTRON_FWAAS_CONF]]
    [fwaas]
    enabled = True
    driver = vmware_nsxv_edge_v2

    [service_providers]
    service_provider = FIREWALL_V2:fwaas_db:neutron_fwaas.services.firewall.service_drivers.agents.agents.FirewallAgentDriver:default

L2GW Driver
~~~~~~~~~~~

Add networking-l2gw repo as an external repository and configure following flags in ``local.conf``::

     [[local|localrc]]
     enable_plugin networking-l2gw https://github.com/openstack/networking-l2gw
     ENABLED_SERVICES+=l2gw-plugin
     NETWORKING_L2GW_SERVICE_DRIVER=L2GW:vmware-nsx-l2gw:vmware_nsx.services.l2gateway.nsx_v.driver.NsxvL2GatewayDriver:default

IPAM Driver
~~~~~~~~~~~

Update the ``local.conf`` file::

    [[post-config|$NEUTRON_CONF]]
    [DEFAULT]
    ipam_driver = vmware_nsxv_ipam

Flow Classifier
~~~~~~~~~~~~~~~

Update the ``local.conf`` file::

    [[local|localrc]]
    enable_plugin networking-sfc https://opendev.org/openstack/networking-sfc master
    Q_SERVICE_PLUGIN_CLASSES+=,networking_sfc.services.flowclassifier.plugin.FlowClassifierPlugin

    [[post-config|$NEUTRON_CONF]]
    [flowclassifier]
    drivers = vmware-nsxv-sfc

    [nsxv]
    service_insertion_profile_id = <service profile id. i.e. serviceprofile-1>

In order to prevent tenants from changing the flow classifier, please add the following
lines to the policy.json file::

    "create_flow_classifier": "rule:admin_only",
    "update_flow_classifier": "rule:admin_only",
    "delete_flow_classifier": "rule:admin_only",
    "get_flow_classifier": "rule:admin_only"

Neutron dynamic routing plugin (bgp)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Add neutron-dynamic-routing repo as an external repository and configure following flags in ``local.conf``::

    [[local|localrc]]
    enable_plugin neutron-dynamic-routing https://opendev.org/openstack/neutron-dynamic-routing
    DR_MODE=dr_plugin
    BGP_PLUGIN=vmware_nsx.services.dynamic_routing.bgp_plugin.NSXvBgpPlugin

    [[post-config|$NEUTRON_CONF]]
    [DEFAULT]
    api_extensions_path = $DEST/neutron-dynamic-routing/neutron_dynamic_routing/extensions

Neutron VPNaaS
~~~~~~~~~~~~~~

Add neutron-vpnaas repo as an external repository and configure following flags in ``local.conf``::

    [[local|localrc]]
    enable_plugin neutron-vpnaas https://opendev.org/openstack/neutron-vpnaas
    NEUTRON_VPNAAS_SERVICE_PROVIDER=VPN:vmware:vmware_nsx.services.vpnaas.nsxv.ipsec_driver.NSXvIPsecVpnDriver:default

Octavia
~~~~~~~

Add octavia and python-octaviaclient repos as external repositories and configure following flags in ``local.conf``::

    [[local|localrc]]
    OCTAVIA_NODE=api
    DISABLE_AMP_IMAGE_BUILD=True
    LIBS_FROM_GIT=python-openstackclient,python-octaviaclient
    enable_plugin octavia https://opendev.org/openstack/octavia.git
    enable_plugin octavia-dashboard https://opendev.org/openstack/octavia-dashboard
    enable_service octavia
    enable_service o-api,o-da

    [[post-config|$OCTAVIA_CONF]]
    [DEFAULT]
    verbose = True
    debug = True

    [api_settings]
    default_provider_driver=vmwareedge
    enabled_provider_drivers=vmwareedge:NSX

    [oslo_messaging]
    topic=vmwarensxv_edge_lb

    [controller_worker]
    network_driver = allowed_address_pairs_driver

    [driver_agent]
    enabled_provider_agents=vmwareagent

NSX-T
-----

Mandatory basic configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Add those parameters in ``local.conf``::

    [[local|localrc]]
    enable_plugin vmware-nsx https://opendev.org/x/vmware-nsx
    Q_PLUGIN=vmware_nsx_v3
    NSX_MANAGER=<ip>
    NSX_USER=<username>
    NSX_PASSWORD=<password>
    DHCP_PROFILE_UUID=<MP name or UUID of the DHCP profile>
    METADATA_PROXY_UUID=<MP name or UUID of the metadata proxy>
    DEFAULT_TIER0_ROUTER_UUID=<MP name or UUID of a Tier0 router>
    DEFAULT_OVERLAY_TZ_UUID=<MP name or UUID of of the overlay transport zone>

QoS Driver
~~~~~~~~~~

Enable the qos in ``local.conf``::

    [[local|localrc]]
    ENABLED_SERVICES+=,q-qos
    Q_SERVICE_PLUGIN_CLASSES+=,neutron.services.qos.qos_plugin.QoSPlugin

Optional: Update the nsx qos_peak_bw_multiplier in nsx.ini (default value is 2.0)::

    [NSX]
    qos_peak_bw_multiplier = <i.e 10.0>

L2GW Driver
~~~~~~~~~~~

Add networking-l2gw repo as an external repository and configure following flags in ``local.conf``::

     [[local|localrc]]
     enable_plugin networking-l2gw https://github.com/openstack/networking-l2gw
     ENABLED_SERVICES+=l2gw-plugin
     NETWORKING_L2GW_SERVICE_DRIVER=L2GW:vmware-nsx-l2gw:vmware_nsx.services.l2gateway.nsx_v3.driver.NsxV3Driver:default
     DEFAULT_BRIDGE_CLUSTER_UUID=

IPAM Driver
~~~~~~~~~~~

Update the ``local.conf`` file::

    [[post-config|$NEUTRON_CONF]]
    [DEFAULT]
    ipam_driver = vmware_nsxv3_ipam

Trunk Driver
~~~~~~~~~~~~

Enable trunk service and configure following flags in ``local.conf``::

    [[local]|[localrc]]
    # Trunk plugin NSX-T driver config
    ENABLED_SERVICES+=,q-trunk
    Q_SERVICE_PLUGIN_CLASSES+=,trunk

FWaaS (V2) Driver
~~~~~~~~~~~~~~~~~

Add neutron-fwaas repo as an external repository and configure following flags in ``local.conf``::

    [[local|localrc]]
    enable_plugin neutron-fwaas https://opendev.org/openstack/neutron-fwaas
    enable_service q-fwaas-v2
    Q_SERVICE_PLUGIN_CLASSES+=,firewall_v2

    [[post-config|$NEUTRON_FWAAS_CONF]]
    [fwaas]
    enabled = True
    driver = vmware_nsxv3_edge_v2

    [service_providers]
    service_provider = FIREWALL_V2:fwaas_db:neutron_fwaas.services.firewall.service_drivers.agents.agents.FirewallAgentDriver:default

Neutron VPNaaS
~~~~~~~~~~~~~~

Add neutron-vpnaas repo as an external repository and configure following flags in ``local.conf``::

    [[local|localrc]]
    enable_plugin neutron-vpnaas https://opendev.org/openstack/neutron-vpnaas
    NEUTRON_VPNAAS_SERVICE_PROVIDER=VPN:vmware:vmware_nsx.services.vpnaas.nsxv3.ipsec_driver.NSXv3IPsecVpnDriver:default
    Q_SERVICE_PLUGIN_CLASSES+=,vmware_nsx_vpnaas

    [[post-config|$NEUTRON_CONF]]
    [DEFAULT]
    api_extensions_path = $DEST/neutron-vpnaas/neutron_vpnaas/extensions

Octavia
~~~~~~~

Add octavia and python-octaviaclient repos as external repositories and configure following flags in ``local.conf``::

    [[local|localrc]]
    OCTAVIA_NODE=api
    DISABLE_AMP_IMAGE_BUILD=True
    LIBS_FROM_GIT=python-openstackclient,python-octaviaclient
    enable_plugin octavia https://opendev.org/openstack/octavia.git
    enable_plugin octavia-dashboard https://opendev.org/openstack/octavia-dashboard
    enable_service octavia
    enable_service o-api,o-da

    [[post-config|$OCTAVIA_CONF]]
    [DEFAULT]
    verbose = True
    debug = True

    [api_settings]
    default_provider_driver=vmwareedge
    enabled_provider_drivers=vmwareedge:NSX

    [oslo_messaging]
    topic=vmwarensxv_edge_lb

    [controller_worker]
    network_driver = allowed_address_pairs_driver

    [driver_agent]
    enabled_provider_agents=vmwareagent

NSX-P
-----

Mandatory basic configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Add those parameters in ``local.conf``::

    [[local|localrc]]
    enable_plugin vmware-nsx https://opendev.org/x/vmware-nsx
    Q_PLUGIN=vmware_nsx_p
    NSX_POLICY=<ip>
    NSX_USER=<username>
    NSX_PASSWORD=<password>
    DHCP_PROFILE_UUID=<MP or Policy name or UUID of the DHCP profile>
    METADATA_PROXY_UUID=<MP or Policy name or UUID of the metadata proxy>
    DEFAULT_TIER0_ROUTER_UUID=<Policy name or ID of Tier0>
    DEFAULT_OVERLAY_TZ_UUID=<Policy name or ID of of the overlay transport zone>

QoS Driver
~~~~~~~~~~

Enable the qos in ``local.conf``::

    [[local|localrc]]
    ENABLED_SERVICES+=,q-qos
    Q_SERVICE_PLUGIN_CLASSES+=,neutron.services.qos.qos_plugin.QoSPlugin

Optional: Update the nsx qos_peak_bw_multiplier in nsx.ini (default value is 2.0)::

    [NSX]
    qos_peak_bw_multiplier = <i.e 10.0>

FWaaS (V2) Driver
~~~~~~~~~~~~~~~~~

Add neutron-fwaas repo as an external repository and configure following flags in ``local.conf``::

    [[local|localrc]]
    enable_plugin neutron-fwaas https://opendev.org/openstack/neutron-fwaas
    enable_service q-fwaas-v2
    Q_SERVICE_PLUGIN_CLASSES+=,firewall_v2

    [[post-config|$NEUTRON_FWAAS_CONF]]
    [fwaas]
    enabled = True
    driver = vmware_nsxp_edge_v2

    [service_providers]
    service_provider = FIREWALL_V2:fwaas_db:neutron_fwaas.services.firewall.service_drivers.agents.agents.FirewallAgentDriver:default

Octavia
~~~~~~~

Add octavia and python-octaviaclient repos as external repositories and configure following flags in ``local.conf``::

    [[local|localrc]]
    OCTAVIA_NODE=api
    DISABLE_AMP_IMAGE_BUILD=True
    LIBS_FROM_GIT=python-openstackclient,python-octaviaclient
    enable_plugin octavia https://opendev.org/openstack/octavia.git
    enable_plugin octavia-dashboard https://opendev.org/openstack/octavia-dashboard
    enable_service octavia
    enable_service o-api,o-da

    [[post-config|$OCTAVIA_CONF]]
    [DEFAULT]
    verbose = True
    debug = True

    [api_settings]
    default_provider_driver=vmwareedge
    enabled_provider_drivers=vmwareedge:NSX

    [oslo_messaging]
    topic=vmwarensxv_edge_lb

    [controller_worker]
    network_driver = allowed_address_pairs_driver

    [driver_agent]
    enabled_provider_agents=vmwareagent

Trunk Driver
~~~~~~~~~~~~

Enable trunk service and configure following flags in ``local.conf``::

    [[local]|[localrc]]
    # Trunk plugin NSX-P driver config
    ENABLED_SERVICES+=,q-trunk
    Q_SERVICE_PLUGIN_CLASSES+=,trunk

Neutron VPNaaS
~~~~~~~~~~~~~~

Add neutron-vpnaas repo as an external repository and configure following flags in ``local.conf``::

    [[local|localrc]]
    enable_plugin neutron-vpnaas https://opendev.org/openstack/neutron-vpnaas
    NEUTRON_VPNAAS_SERVICE_PROVIDER=VPN:vmware:vmware_nsx.services.vpnaas.nsxp.ipsec_driver.NSXpIPsecVpnDriver:default
    Q_SERVICE_PLUGIN_CLASSES+=,vmware_nsx_vpnaas

    [[post-config|$NEUTRON_CONF]]
    [DEFAULT]
    api_extensions_path = $DEST/neutron-vpnaas/neutron_vpnaas/extensions


NSX-TVD
-------

Mandatory basic configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Add those parameters in ``local.conf``::

    [[local|localrc]]
    enable_plugin vmware-nsx https://opendev.org/x/vmware-nsx
    Q_PLUGIN=vmware_nsx_tvd
    <NSX-V and / or NSX-T parameters>

FWaaS (V2) Driver
~~~~~~~~~~~~~~~~~

Add neutron-fwaas repo as an external repository and configure following flags in ``local.conf``::

    [[local|localrc]]
    enable_plugin neutron-fwaas https://opendev.org/openstack/neutron-fwaas
    enable_service q-fwaas-v2
    Q_SERVICE_PLUGIN_CLASSES+=,vmware_nsxtvd_fwaasv2

    [DEFAULT]
    api_extensions_path = $DEST/neutron-fwaas/neutron_fwaas/extensions

    [[post-config|$NEUTRON_FWAAS_CONF]]
    [fwaas]
    enabled = True
    driver = vmware_nsxtvd_edge_v2

    [service_providers]
    service_provider = FIREWALL_V2:fwaas_db:neutron_fwaas.services.firewall.service_drivers.agents.agents.FirewallAgentDriver:default


L2GW Driver
~~~~~~~~~~~

Add networking-l2gw repo as an external repository and configure following flags in ``local.conf``::

     [[local|localrc]]
     enable_plugin networking-l2gw https://github.com/openstack/networking-l2gw
     ENABLED_SERVICES+=l2gw-plugin
     NETWORKING_L2GW_SERVICE_DRIVER=L2GW:vmware-nsx-l2gw:vmware_nsx.services.l2gateway.nsx_tvd.driver.NsxTvdL2GatewayDriver:default
     DEFAULT_BRIDGE_CLUSTER_UUID=
     Q_SERVICE_PLUGIN_CLASSES+=,vmware_nsxtvd_l2gw

    [[post-config|$NEUTRON_CONF]]
    [DEFAULT]
    api_extensions_path = $DEST/networking-l2gateway/networking_l2gw/extensions

QoS Driver
~~~~~~~~~~

Enable the qos in ``local.conf``::

    [[local|localrc]]
    ENABLED_SERVICES+=,q-qos
    Q_SERVICE_PLUGIN_CLASSES+=,vmware_nsxtvd_qos

Neutron dynamic routing plugin (bgp)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Add neutron-dynamic-routing repo as an external repository and configure following flags in ``local.conf``::

    [[local|localrc]]
    enable_plugin neutron-dynamic-routing https://opendev.org/openstack/neutron-dynamic-routing
    DR_MODE=dr_plugin
    BGP_PLUGIN=vmware_nsx.services.dynamic_routing.bgp_plugin.NSXBgpPlugin

    [[post-config|$NEUTRON_CONF]]
    [DEFAULT]
    api_extensions_path = $DEST/neutron-dynamic-routing/neutron_dynamic_routing/extensions

Neutron VPNaaS
~~~~~~~~~~~~~~

Add neutron-vpnaas repo as an external repository and configure following flags in ``local.conf``::

    [[local|localrc]]
    enable_plugin neutron-vpnaas https://opendev.org/openstack/neutron-vpnaas
    NEUTRON_VPNAAS_SERVICE_PROVIDER=VPN:vmware:vmware_nsx.services.vpnaas.nsx_tvd.ipsec_driver.NSXIPsecVpnDriver:default
    Q_SERVICE_PLUGIN_CLASSES+=,vmware_nsxtvd_vpnaas

    [[post-config|$NEUTRON_CONF]]
    [DEFAULT]
    api_extensions_path = $DEST/neutron-vpnaas/neutron_vpnaas/extensions

IPAM Driver
~~~~~~~~~~~

Update the ``local.conf`` file::

    [[post-config|$NEUTRON_CONF]]
    [DEFAULT]
    ipam_driver = vmware_nsxtvd_ipam

