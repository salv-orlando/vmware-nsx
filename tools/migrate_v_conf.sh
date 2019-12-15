#!/bin/bash

set -eu

# This script will generate a set of neutron config files for the NSX policy
# plugin given the NSX-V config files

usage () {
    >&2  echo "
Usage: $0 [OPTION]...

Generate neutron NSX-P config files

  --v-neutron-conf-path <path>  Path for the original NSX-V neutron.conf (mandatory)
  --v-nsx-ini-path <path>       Path for the original NSX-V nsx.ini (mandatory)
  --p-neutron-conf-path <path>  Path for the generated NSX-P neutron.conf (optional)
  --p-nsx-ini-path <path>       Path for the generated NSX-P nsx.ini (optional)
  --nsx-api-manager <ip>        IP of the NSX manager (mandatory)
  --nsx-api-user <user>         User for the NSX manager authentication (defaults to admin)
  --nsx-api-password <password> Password for the NSX manager authentication (defaults to Admin!23)
  --metadata-proxy <uuid>       NSX metadata proxy name or UUID (mandatory)
  --dhcp-profile <uuid>         NSX DHCP profile name or UUID (mandatory)
  --default-overlay-tz <uuid>   NSX overlay transport zone name or UUID (mandatory)
  --default-vlan-tz <uuid>      NSX VLAN transport zone name or UUID (optional)
  --default-tier0-router <uuid> NSX tier0 router name or UUID (mandatory)
  -h, --help                    Print this usage message"
    exit 0
}

function process_options {
    i=1
    while [ $i -le $# ]; do
        case "${!i}" in
            -h|--help) usage;;
            --v-neutron-conf-path)
                (( i++ ))
                v_neutron_conf=${!i}
                ;;
            --p-neutron-conf-path)
                (( i++ ))
                p_neutron_conf=${!i}
                ;;
            --v-nsx-ini-path)
                (( i++ ))
                v_nsx_ini=${!i}
                ;;
            --nsx-api-manager)
                (( i++ ))
                nsx_api_manager=${!i}
                ;;
            --nsx-api-password)
                (( i++ ))
                nsx_api_password=${!i}
                ;;
            --nsx-api-user)
                (( i++ ))
                nsx_api_user=${!i}
                ;;
            --metadata-proxy)
                (( i++ ))
                metadata_proxy=${!i}
                ;;
            --dhcp-profile)
                (( i++ ))
                dhcp_profile=${!i}
                ;;
            --default-overlay-tz)
                (( i++ ))
                default_overlay_tz=${!i}
                ;;
            --default-vlan-tz)
                (( i++ ))
                default_vlan_tz=${!i}
                ;;
            --default-tier0-router)
                (( i++ ))
                default_tier0_router=${!i}
                ;;
            -*) testopts="$testopts ${!i}";;
            *) testargs="$testargs ${!i}"
        esac
        (( i++ ))
    done

    # verify existence of mandatory args
    if [ -z $v_neutron_conf ] || [ -z $v_nsx_ini ] || [ -z $nsx_api_manager ]; then
        >&2 echo "Missing mandatory arguments"
        usage
    fi

    if [ -z $metadata_proxy ] || [ -z $dhcp_profile ] || [ -z $default_overlay_tz ] || [ -z $default_tier0_router ]; then
        >&2 echo "Missing mandatory arguments"
        usage
    fi

    # Verify config files exists
    if [[ ! -f "$v_neutron_conf" ]]; then
        >&2 echo "$v_neutron_conf File not found"
        usage
    fi

    if [[ ! -f "$v_nsx_ini" ]]; then
        >&2 echo "$v_nsx_ini File not found"
        usage
    fi
}

function create_neutron_conf {
    # Copy the nsx-v conf file
    cp $v_neutron_conf $p_neutron_conf

    # Change the core plugin
    sed -i 's/^core_plugin = vmware_nsxv/core_plugin = vmware_nsxp/' $p_neutron_conf

    # Remove unsupported services
    sed -i 's/neutron_dynamic_routing.services.bgp.bgp_plugin.BgpPlugin//' $p_neutron_conf
    sed -i 's/networking_l2gw.services.l2gateway.plugin.L2GatewayPlugin//' $p_neutron_conf

    # Replace service plugins
    sed -i 's/vmware_nsxv_qos/neutron.services.qos.qos_plugin.QoSPlugin/' $p_neutron_conf

    # Replace nsx-v FWaaS driver
    sed -i 's/vmware_nsxv_edge_v2/vmware_nsxp_edge_v2/' $p_neutron_conf
    sed -i 's/vmware_nsxv_edge/vmware_nsxp_edge_v2/' $p_neutron_conf

    # Replace the FWaaS service provider temporarily to allow the migration
    sed -i 's/neutron_fwaas.services.firewall.service_drivers.agents.agents.FirewallAgentDriver/vmware_nsx.services.fwaas.common.api_replay_driver.ApiReplayFirewallAgentDriver/' $p_neutron_conf

    echo "Created $p_neutron_conf for policy plugin neutron.conf"
}

function create_nsx_ini {
    cp $v_nsx_ini $p_nsx_ini

    # Replace nsx-v drivers
    sed -i 's/vmware_nsxv_dns/vmware_nsxp_dns/' $p_nsx_ini

    # Add the nsxp section
    echo "" >> $p_nsx_ini
    echo "[nsx_p]" >> $p_nsx_ini
    echo "nsx_api_managers = $nsx_api_manager" >> $p_nsx_ini
    echo "nsx_api_password = $nsx_api_password" >> $p_nsx_ini
    echo "nsx_api_user = $nsx_api_user" >> $p_nsx_ini
    echo "metadata_proxy = $metadata_proxy" >> $p_nsx_ini
    echo "dhcp_profile = $dhcp_profile" >> $p_nsx_ini
    echo "default_overlay_tz = $default_overlay_tz" >> $p_nsx_ini
    if [ -n "$default_vlan_tz" ]; then
        echo "default_vlan_tz = $default_vlan_tz" >> $p_nsx_ini
    fi
    echo "default_tier0_router = $default_tier0_router" >> $p_nsx_ini
    # Add the nat-firewall flag to match the existing nsx-v status
    echo "firewall_match_internal_addr = false" >> $p_nsx_ini

    grep "availability_zones" $v_nsx_ini >> $p_nsx_ini
    echo "" >> $p_nsx_ini

    # Add the api_replay flag under the DEFAULT section so that the migration can start
    sed -i '/\[DEFAULT\]/a api_replay_mode = true' $p_nsx_ini

    # Add comment to manually update the AZs later
    sed -i '/^\[az\:.*\]/a # Please add mandatory availability zone config here' $p_nsx_ini

    echo "Created $p_nsx_ini for policy plugin nsx.ini"

    if grep -q "Please add mandatory" "$p_nsx_ini"; then
        echo "Please add mandatory configuration fields to availability zones in nsx.ini"
    fi
}

testargs=
testopts=

v_neutron_conf=""
p_neutron_conf=${p_neutron_conf:-$(pwd)/neutron.conf.p}
v_nsx_ini=""
p_nsx_ini=${p_nsx_ini:-$(pwd)/nsx.ini.p}

nsx_api_manager=""
nsx_api_password=${nsx_api_password:-"Admin!23Admin"}
nsx_api_user=${nsx_api_user:-"admin"}

metadata_proxy=""
dhcp_profile=""
default_overlay_tz=""
default_vlan_tz=""
default_tier0_router=""

process_options $@

create_neutron_conf
create_nsx_ini
