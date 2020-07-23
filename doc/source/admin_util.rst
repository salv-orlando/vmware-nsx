Admin Utility
=============

The VMWare NSX plugins support the nsxadmin utility. This enables and administrator to determine and rectify inconsistencies between the Neutron DB and NSX, in addition to performing different configuration changes and migrations.
usage: nsxadmin -r <resources> -o <operation>

In order to specify config files:
usage: nsxadmin --config-file <neutron config path> --config-file <nsx config path > -r <resources> -o <operation>

NSX-V Plugin
------------

The following resources are supported: 'security-groups', 'edges', 'networks', 'firewall-sections', 'orphaned-edges', 'spoofguard-policy', 'missing-edges', 'backup-edges', 'nsx-security-groups', 'dhcp-binding' and  'metadata'

Edges
~~~~~

- List backend NSX edges with their id, name and some more information::

    nsxadmin -r edges -o nsx-list

- List backend NSX edges with more details::

    nsxadmin -r edges -o nsx-list --verbose

- Neutron list::

    nsxadmin -r edges -o neutron-list

- Update Resource pool / Datastore on all edges in the backend. This utility can update resource pool and datastore ID of all edges to the nsx.ini configuration::

    nsxadmin -r edges -o nsx-update-all --property appliances=True

- Update Resource pool / Datastore / edge HA of an edge: This utility can be used on upgrade after the customer added ha_datastore_id to the nsx.ini configuration or after changing the resource pool / data store globally or per availability zone. This Utility can update the deployment of existing edges::

    nsxadmin -r edges -o nsx-update --property edge-id=<edge-id> --property appliances=True

- Update the size of an edge::

    nsxadmin -r edges -o nsx-update --property edge-id=edge-55 --property size=compact

- Update the high availability of an edge: enable/disable high availability of an edge::

    nsxadmin -r edges -o nsx-update --property edge-id=edge-55 --property highavailability=<True/False>

- Update syslog config on edge (syslog-proto and syslog-server2 are optional)::

    nsxadmin -o nsx-update -r edges -p edge-id=edge-55 --property syslog-server=<server ip> --property syslog-server2=<server ip> --property syslog-proto=<tcp|udp>

- Delete syslog config on edge::

    nsxadmin -o nsx-update -r edges -p edge-id=edge-55 --property syslog-server=none

- Enable logging with specified log level for specific module (routing, dns, dhcp, highavailability, loadbalancer) on edge::

    nsxadmin -o nsx-update -r edges -p edge-id=edge-55 --property routing-log-level=debug

- Enable logging with specified log level for all supported modules on edge::

    nsxadmin -o nsx-update -r edges -p edge-id=edge-55 --property log-level=debug

- Disable logging on edge::

    nsxadmin -o nsx-update -r edges -p edge-id=edge-55 --property log-level=none

- Update reservations of an edge::

    nsxadmin -o nsx-update -r edges -p edge-id=edge-55 --property resource=<cpu|memory> --property limit=<limit> --property reservation=<reservation> --property shares=<shares>

- Update DRS hostgroups for an edge::

    nsxadmin -o nsx-update -r edges -p edge-id=edge-55 --property hostgroup=update|all

- Update DRS hostgroups for all edges::

    nsxadmin -o nsx-update -r edges --property hostgroup=all

- Clean all DRS hostgroups for all edges::

    nsxadmin -o nsx-update -r edges --property hostgroup=clean

Orphaned Edges
~~~~~~~~~~~~~~

- List orphaned edges (exist on NSXv backend but don't have a corresponding binding in Neutron DB)::

    nsxadmin -r orphaned-edges -o list

- Clean orphaned edges (delete edges from NSXv backend)::

    nsxadmin -r orphaned-edges -o clean

Orphaned Router bindings
~~~~~~~~~~~~~~~~~~~~~~~~

- List orphaned router bindings entries (exist on the router bindings DB table, but the neutron object behind them (router, network, or loadbalancer) is missing)::

    nsxadmin -r orphaned-bindings -o list

- Clean orphaned router bindings entries (delete DB entry)::

    nsxadmin -r orphaned-bindings -o clean

Orphaned Router VNICs
~~~~~~~~~~~~~~~~~~~~~

- List orphaned router vnic entries (exist on the edge vnics bindings DB table, but the neutron interface port behind them is missing)::

    nsxadmin -r orphaned-vnics -o list

- Clean orphaned router vnics (delete DB entry, and NSX router interface)::

    nsxadmin -r orphaned-vnics -o clean

Missing Edges
~~~~~~~~~~~~~

-  List missing edges on NSX. This includes missing networks on those edges::

    nsxadmin -r missing-edges -o list

Backup Edges
~~~~~~~~~~~~

- List backend backup edges with their id, name and some more information::

    nsxadmin -r backup-edges -o list

- Delete backup edge::

    nsxadmin -r backup-edges -o clean --property edge-id=edge-9 [--force]

- Delete all backup edges existing in both neutron and backend when scope is neutron, else backend only::

    nsxadmin -r backup-edges -o clean-all --property scope=[neutron/all] [--force]

- List Edge name mismatches between DB and backend, and backup edges that are missing from the backend::

    nsxadmin -r backup-edges -o list-mismatches

- Fix Edge name mismatch between DB and backend by updating the name on the backend::

    nsxadmin -r backup-edges -o fix-mismatch --property edge-id=edge-9 [--force]

- Delete a backup edge from the DB and NSX by it's router ID::

    nsxadmin -r backup-edges -o neutron-clean --property router-id=backup-26ab1a3a-d73d

DHCP Bindings
~~~~~~~~~~~~~
- List missing DHCP bindings: list dhcp edges that are missing from the NSXv backend::

    nsxadmin -r dhcp-binding -o list

- Update DHCP bindings on an edge::

    nsxadmin -r dhcp-binding -o nsx-update --property edge-id=edge-15

- Recreate DHCP edge by moving all the networks to other edges::

    nsxadmin -r dhcp-binding -o nsx-recreate --property edge-id=edge-222

- Recreate DHCP edge for a specific network (when the edge does not exist)::

    nsxadmin -r dhcp-binding -o nsx-recreate --property net-id=5253ae45-75b4-4489-8aa1-6a9e1cfa80a6

- Redistribute networks on dhcp edges (for example when configuration of share_edges_between_tenants changes)::

    nsxadmin -r dhcp-binding -o nsx-redistribute

Routers
~~~~~~~
- Recreate a router edge by moving the router/s to other edge/s::

    nsxadmin -r routers -o nsx-recreate --property edge-id=edge-308

- Recreate a router on the NSX backend by removing it from the current edge (if any), and attaching to a new one::

    nsxadmin -r routers -o nsx-recreate --property router-id=8cdd6d06-b457-4cbb-a0b1-41e08ccce287

- Redistribute shared routers on edges (for example when configuration of share_edges_between_tenants changes)::

    nsxadmin -r routers -o nsx-redistribute

- Migrate NSXv metadata infrastructure for VDRs - use regular DHCP edges for VDR::

    nsxadmin -r routers -o migrate-vdr-dhcp

- Recreate the rules in the edge firewall of all routers

    nsxadmin -r routers -o nsx-update-fw

Networks
~~~~~~~~

- Ability to update or get the teaming policy for a DVS::

    nsxadmin -r networks -o nsx-update --property dvs-id=<id> --property teamingpolicy=<policy>

- List backend networks and their network morefs::

    nsxadmin -r networks -o list

Missing Networks
~~~~~~~~~~~~~~~~

- List networks which are missing from the backend::

    nsxadmin -r missing-networks -o list

Orphaned Networks
~~~~~~~~~~~~~~~~~

- List networks which are missing from the neutron DB::

    nsxadmin -r orphaned-networks -o list

- Delete a backend network by it's moref::

    nsxadmin -r orphaned-networks -o nsx-clean --property moref=<moref>

Portgroups
~~~~~~~~~~
- List all NSX portgroups on the configured dvs::

    nsxadmin -r nsx-portgroups -o list

- Delete all NSX portgroups on the configured dvs::

    nsxadmin -r nsx-portgroups -o nsx-cleanup <--force>

Security Groups, Firewall and Spoofguard
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- List NSX firewall sections::

    nsxadmin -r firewall-section -o list

- List neutron security groups that does not have a matching NSX firewall section::

    nsxadmin -r firewall-section -o list-mismatches

- List NSX firewall sections that does not have a matching neutron security group::

    nsxadmin -r firewall-section -o list-unused

- Delete NSX firewall sections that does not have a matching neutron security group::

    nsxadmin -r firewall-section -o nsx-clean

- Reorder the NSX L3 firewall sections to correctly support the policy security groups::

    nsxadmin -r firewall-sections -o nsx-reorder

- List NSX service composer policies, that can be used in security groups::

    nsxadmin -r firewall-sections -o list-policies

- Update the default cluster section::

    nsxadmin -r firewall-sections -o nsx-update

- List NSX security groups::

    nsxadmin -r nsx-security-groups -o list

- List neutron security groups that does not have a matching NSX security group::

    nsxadmin -r nsx-security-groups -o list-mismatches

- List all the neutron security groups together with their NSX security groups and firewall sections::

    nsxadmin -r security-groups -o list

- Recreate missing NSX security groups ans firewall sections::

    nsxadmin -r security-groups -o fix-mismatch

- Migrate a security group from using rules to using a policy::

    nsxadmin -r security-groups -o migrate-to-policy --property policy-id=policy-10 --property security-group-id=733f0741-fa2c-4b32-811c-b78e4dc8ec39

- Update logging flag of the security groups on the NSX DFW::

    nsxadmin -r security-groups -o update-logging --property log-allowed-traffic=true

- Spoofguard support::

    nsxadmin -r spoofguard-policy -o clean --property policy-id=spoofguardpolicy-10
    nsxadmin -r spoofguard-policy -o list --property reverse (entries defined on NSXv and not in Neutron)
    nsxadmin -r spoofguard-policy -o list-mismatches (--property network=<neutron net id>) - List spoofguard policies with mismatching ips or mac, globally or for a specific network
    nsxadmin -r spoofguard-policy -o fix-mismatch --property port=<neutron port id> - Fix the spoofguard ips of a neutron port

- Orphaned rules in NSX section::

    nsxadmin -r orphaned-rules -o list
    nsxadmin -r orphaned-rules -o nsx-clean


Metadata
~~~~~~~~

- Update metadata infrastructure on all router and DHCP edges::

    nsxadmin -r metadata -o nsx-update

- Update metadata infrastructure on availability zone's router and DHCP edges::

    nsxadmin -r metadata -o nsx-update --property az-name=az123

- Update metadata infrastructure on specific router or DHCP edge::

    nsxadmin -r metadata -o nsx-update --property edge-id=edge-15

- Update shared secret on router and DHCP edges::

    nsxadmin -r metadata -o nsx-update-secret

- Retrieve metadata connectivity - optionally for a specific network::

    nsxadmin -r metadata -o status [--property network_id=<net_id>]

V2T migration
~~~~~~~~~~~~~

- Validate the configuration of the NSX-V plugin before migrating to NSX-T::

    nsxadmin -r nsx-migrate-v2t -o validate [--property transit-network=<cidr>]

Config
~~~~~~

- Validate the configuration in the nsx.ini and backend connectivity::

    nsxadmin -r config -o validate

NSX-T Plugin
------------

The following resources are supported: 'security-groups', 'routers', 'networks', 'nsx-security-groups', 'dhcp-binding', 'metadata-proxy', 'orphaned-dhcp-servers', 'firewall-sections', 'certificate', 'orphaned-networks', 'orphaned-routers',
and 'ports'.

Networks
~~~~~~~~

- List missing networks::

    nsxadmin -r networks -o list-mismatches

Orphaned Networks
~~~~~~~~~~~~~~~~~

- List networks (logical switches) which are missing from the neutron DB::

    nsxadmin -r orphaned-networks -o list

- Delete a backend network (logical switch) by it's nsx-id::

    nsxadmin -r orphaned-networks -o nsx-clean --property nsx-id=<id>

Routers
~~~~~~~

- List missing routers::

    nsxadmin -r routers -o list-mismatches

- Update NAT rules on all routers to stop bypassing the FW rules.
  This is useful for NSX version 2.0 & up, before starting to use FWaaS::

    nsxadmin -r routers -o nsx-update-rules

- Update DHCP relay service on NSX router ports according to the current configuration::

    nsxadmin -r routers -o nsx-update-dhcp-relay

- Enable standby relocation on NSX routers that were created without it::

    nsxadmin -r routers -o nsx-enable-standby-relocation

- Replace an old tier0 (that might have been deleted) with a new one::

    nsxadmin -r routers -o  update-tier0  --property old-tier0=<id> --property new-tier0=<id> 

Orphaned Routers
~~~~~~~~~~~~~~~~~

- List logical routers which are missing from the neutron DB::

    nsxadmin -r orphaned-routers -o list

- Delete a backend logical router by it's nsx-id::

    nsxadmin -r orphaned-routers -o nsx-clean --property nsx-id=<id>

Ports
~~~~~

- List missing ports, and ports that exist on backend but without the expected switch profiles or address bindings::

    nsxadmin -r ports -o list-mismatches

- Update the VMs ports (all or of a specific project) on the backend after migrating NSX-V -> NSX-T::

    nsxadmin -r ports -o nsx-migrate-v-v3 (--property project-id=<> --property host-moref=<> --property respool-moref=<> --property net-name=<> --property datastore-moref=<>)) --plugin nsxv3

- Migrate exclude ports to use tags::

    nsxadmin -r ports -o migrate-exclude-ports

- Tag ports to be part of the default OS security group::

    nsxadmin -r ports -o nsx-tag-default

Security Groups & NSX Security Groups
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- List NSX backend security groups::

    nsxadmin -r nsx-security-groups -o list

- List neutron security groups::

    nsxadmin -r security-groups -o list

- List security groups with sections missing on the NSX backend::

    nsxadmin -r nsx-security-groups -o list-mismatches

- Fix mismatch security groups by recreating missing sections & NS groups on the NSX backend::

    nsxadmin -r security-groups -o fix-mismatch

- Update logging flag of the security groups on the NSX DFW::

    nsxadmin -r security-groups -o update-logging --property log-allowed-traffic=true

Firewall Sections
~~~~~~~~~~~~~~~~~

- List NSX backend firewall sections::

    nsxadmin -r firewall-sections -o list

- List security groups with missing sections on the NSX backend::

    nsxadmin -r firewall-sections -o list-mismatches

- Reuse default NSX section ans NS group from a previous installation::

    nsxadmin -r firewall-sections -o reuse

Orphaned Firewall Sections
~~~~~~~~~~~~~~~~~~~~~~~~~~

- List orphaned firewall sections & rules (exist on NSXv3 backend but don't have a corresponding binding in Neutron DB)::

    nsxadmin -r orphaned-firewall-sections -o nsx-list

- Delete orphaned firewall sections & rules (exist on NSXv3 backend but don't have a corresponding binding in Neutron DB)::

    nsxadmin -r orphaned-firewall-sections -o nsx-clean

Metadata Proxy
~~~~~~~~~~~~~~

- List version 1.0.0 metadata networks in Neutron::

    nsxadmin -r metadata-proxy -o list

- update the ip of the Nova server in the metadata proxy server on the NSX::

    nsxadmin -r metadata-proxy -o nsx-update-ip --property server-ip=<server-ip> --property availability-zone=<optional zone name>

DHCP Bindings
~~~~~~~~~~~~~

- List DHCP bindings in Neutron::

    nsxadmin -r dhcp-binding -o list

- Recreate dhcp server for a neutron network::

    nsxadmin -r dhcp-binding -o nsx-recreate --property net-id=<neutron-net-id>

Orphaned DHCP Servers
~~~~~~~~~~~~~~~~~~~~~

- List orphaned DHCP servers (exist on NSX-T backend but don't have a corresponding binding in Neutron DB)::

    nsxadmin -r orphaned-dhcp-servers -o nsx-list

- Clean orphaned DHCP servers (delete logical DHCP servers from NSX-T backend)::

    nsxadmin -r orphaned-dhcp-servers -o nsx-clean

Client Certificate
~~~~~~~~~~~~~~~~~~

- Generate new client certificate (this command will delete previous certificate if exists)::

    nsxadmin -r certificate -o generate [--property username=<username> --property password=<password> --property key-size=<size> --property sig-alg=<alg> --property valid-days=<days> --property country=<country> --property state=<state> --property org=<organization> --property unit=<unit> --property host=<hostname>]

- Delete client certificate::

    nsxadmin -r certificate -o clean

- Show client certificate details::

    nsxadmin -r certificate -o show

- Import external certificate to NSX::

    nsxadmin -r certificate -o import [--property username=<username> --property password=<password> --property filename=<cert filename>]

- List certificates associated with openstack principal identity in NSX::

    nsxadmin -r certificate -o nsx-list


BGP GW edges
~~~~~~~~~~~~
- Create new BGP GW edge::

    nsxadmin -r bgp-gw-edge -o create --property name=<NAME> --property local-as=<ASN> --property external-iface=<PORTGROUP_MOREF>:<IP_ADDRESS/PREFIX_LEN> --property internal-iface=<PORTGROUP_MOREF>:<IP_ADDRESS/PREFIX_LEN>

- Delete BGP GW edge::

    nsxadmin -r bgp-gw-edge -o delete --property gw-edge-id=<edge-id>

- List BGP GW edges::

    nsxadmin -r bgp-gw-edge -o list

- Add a redistribution rule to a BGP GW edges::

    nsxadmin -r routing-redistribution-rule -o create --property edge-ids=<edge_id>[,...] [--property prefix=<NAME:CIDR>] --property learner-protocol=<ospf/bgp> --property learn-from=ospf,bgp,connected,static --property action=<permit/deny>

- Remove a redistribution rule from BGP GW edges::

    nsxadmin -r routing-redistribution-rule -o delete --property gw-edge-ids=<edge_id>[,...] [--property prefix-name=<NAME>]

- Add a new BGP neighbour to BGP GW edges::

    nsxadmin -r bgp-neighbour -o create --property gw-edge-ids=<edge_id>[,...] --property ip-address=<IP_ADDRESS>  --property remote-as=<ASN> --property --password=<PASSWORD>

- Remove BGP neighbour from BGP GW edges::

    nsxadmin -r bgp-neighbour -o delete --property gw-edge-ids=<edge_id>[,...] --property ip-address=<IP_ADDRESS>


LBaaS
~~~~~
- List NSX LB services::

    nsxadmin -r lb-services -o list

- List NSX LB virtual servers::

    nsxadmin -r lb-virtual-servers -o list

- List NSX LB pools::

    nsxadmin -r lb-pools -o list

- List NSX LB monitors::

    nsxadmin -r lb-monitors -o list

- Update advertisement of LB vips on routers::

    nsxadmin -r lb-advertisement -o nsx-update


Rate Limit
~~~~~~~~~~
- Show the current NSX rate limit::

    nsxadmin -r rate-limit -o show

- Update the NSX rate limit::

nsxadmin -r rate-limit -o nsx-update --property value=<>

Cluster
~~~~~~~

- Show the NSX cluster managers ips::

    nsxadmin -r cluster -o show

Config
~~~~~~

- Validate the configuration in the nsx.ini and backend connectivity::

    nsxadmin -r config -o validate

T2P migration
~~~~~~~~~~~~~

- Verify the current configuration can be migrated to Policy::

    nsxadmin -r nsx-migrate-t2p -o validate

- Migrate NSX resources and neutron DB from NSX-T (MP) to Policy::

    nsxadmin -r nsx-migrate-t2p -o import --property logfile=<> (--verbose)

- Delete DB tables related to the MP plugin after migration::

    nsxadmin -r nsx-migrate-t2p -o clean-all

NSXtvd Plugin
-------------

- All the NSX-V/T utilities can be used by calling::

    nsxadmin --plugin nsxv/v3 -r <> -o <>

- Add mapping between existing projects and old (v) plugin before starting to use the tvd plugin::

    nsxadmin -r projects -o import --property plugin=nsx-v --property project=<>

- Migrate a specific project from V to T::

     nsxadmin -r projects -o nsx-migrate-v-v3 --property project-id=<V project ID> --property external-net=<T external network ID> (--property from-file=True)

NSX Policy Plugin
-----------------
- List all the neutron security groups together with their NSX Policy objects and realization state::

    nsxadmin -r security-groups -o list

- List all the neutron networks together with their NSX Policy objects and realization state::

    nsxadmin -r networks -o list

- Sync admin state of networks and ports (Once upgraded to NSX 3.0 which supports policy admin state)::

    nsxadmin -r networks -o nsx-update-state

- List all the neutron routers together with their NSX Policy objects and realization state::

    nsxadmin -r routers -o list

- Set intent realization and purge cycle interval (in minutes) on policy manager::

    nsxadmin -r system -o set -p realization_interval=1

- Replace an old tier0 (that might have been deleted) with a new one::

    nsxadmin -r routers -o  update-tier0  --property old-tier0=<id> --property new-tier0=<id>

- Update the firewall_match value in neutron nat rules with a new value. Should be used when firewall_match_internal_addr config changes::

    nsxadmin -r routers -o  update-nat-firewall-match --property firewall-match=external/internal

- Migrate networks DHCP from MP to Policy (for NSX 3.0 upgrades)::
    nsxadmin -r dhcp-binding -o migrate-to-policy --property dhcp-config=<id>

- Update tags on a loadbalancer service
    nsxadmin -r lb-services -o nsx-update-tags

- Delete DB tables related to the MP plugin after migration from MP plugin to policy::

    nsxadmin -r nsx-migrate-t2p -o clean-all


Client Certificate
~~~~~~~~~~~~~~~~~~

- Generate new client certificate (this command will delete previous certificate if exists)::

    nsxadmin -r certificate -o generate [--property username=<username> --property password=<password> --property key-size=<size> --property sig-alg=<alg> --property valid-days=<days> --property country=<country> --property state=<state> --property org=<organization> --property unit=<unit> --property host=<hostname>]

- Delete client certificate::

    nsxadmin -r certificate -o clean

- Show client certificate details::

    nsxadmin -r certificate -o show

- Import external certificate to NSX::

    nsxadmin -r certificate -o import [--property username=<username> --property password=<password> --property filename=<cert filename>]

- List certificates associated with openstack principal identity in NSX::

    nsxadmin -r certificate -o nsx-list

Steps to create a TVD admin user
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Do the following steps::
    source devstack/openrc admin admin
    openstack project create admin_v --domain=default --or-show -f value -c id
    openstack user create admin_v --password password --domain=default --email=alt_demo@example.com --or-show -f value -c id
    openstack role add admin --user <user-id> --project <admin-id>

Or run:
    devstack/tools/create_userrc.sh

Then:
    openstack project plugin create --plugin nsx-v <project-id>
