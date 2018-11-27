#
# Copyright (c) 2018 CertusNet Networks, Inc. All rights reserved.
#

"""
This file contains generic plugin implementation for certus devices
"""

from ncclient import manager
from ncclient.xml_ import new_ele
from ncclient.operations.errors import TimeoutExpiredError
import time
import datetime
from cStringIO import StringIO
from dm_utils import DMUtils
from device_conf import DeviceConf
from dm_utils import PushConfigState
from db import PhysicalInterfaceDM
from db import LogicalInterfaceDM
from db import BgpRouterDM
from db import GlobalSystemConfigDM
from db import VirtualMachineInterfaceDM
from device_api.certus_common_xsd import *


class CertusConf(DeviceConf):
    _vendor = "certus"
    # mapping from contrail family names to flexbng
    _FAMILY_MAP = {
        'route-target': '',
        'inet': 'bgp-types:ipv4-unicast',
        'inet-vpn': 'bgp-types:l3vpn-ipv4-unicast',
        'inet6-vpn': 'bgp-types:l3vpn-ipv6-unicast',
        'e-vpn': 'bgp-types:l2vpn-evpn'
    }

    @classmethod
    def register(cls, plugin_info):
        common_params = {"vendor": cls._vendor}
        plugin_info.update(common_params)
        return super(CertusConf, cls).register(plugin_info)
    # end register

    def __init__(self):
        self._nc_manager = None
        self.user_creds = self.physical_router.user_credentials
        self.management_ip = self.physical_router.management_ip
        self.timeout = 120
        self.nc_port = 2022
        self.push_config_state = PushConfigState.PUSH_STATE_INIT
        super(CertusConf, self).__init__()

        self.db_l2_dci = None
        self.db_l3_dci = None
        self.uplink_interface = ''
        self.db_floating_ips = None
    # end __init__

    def update(self):
        if not self.are_creds_modified():
            return
        self.user_creds = self.physical_router.user_credentials
        self.management_ip = self.physical_router.management_ip
        if self.is_connected():
            self.device_disconnect()
            self.device_connect()
    # ene update

    def get_commit_stats(self):
        return self.commit_stats
    # end get_commit_stats

    def retry(self):
        if self.push_config_state == PushConfigState.PUSH_STATE_RETRY:
            return True
        return False
    # end retry

    def are_creds_modified(self):
        user_creds = self.physical_router.user_credentials
        management_ip = self.physical_router.management_ip
        if (self.user_creds != user_creds or self.management_ip != management_ip):
            return True
        return False
    # end are_creds_modified

    def device_connect(self):
        if not self._nc_manager:
            try:
                self._nc_manager = manager.connect(host=self.management_ip, port=self.nc_port,
                                                   username=self.user_creds['username'],
                                                   password=self.user_creds['password'],
                                                   hostkey_verify=False,
                                                   allow_agent=False,
                                                   look_for_keys=False,
                                                   unknown_host_cb=lambda x, y: True)
            except Exception as e:
                if self._logger:
                    self._logger.error("could not establish netconf session with router %s: %s"
                                       % (self.management_ip, e.message))
    # end device_connect

    def device_disconnect(self):
        if self._nc_manager and self._nc_manager.connected:
            try:
                self._nc_manager.close_session()
            except Exception as e:
                if self._logger:
                    self._logger.error("could not close the netconf session: router %s: %s"
                                       % (self.management_ip, e.message))
            self._nc_manager = None
    # end device_disconnect

    def is_connected(self):
        return self._nc_manager and self._nc_manager.connected
    # end is_connected

    def initialize(self):
        self.interfaces = Interfaces()
        self.router = Router()
        self.bgp = Bgp()
        self.compare_config = config()
        self.l2smvfi = L2smVfi()
        self.l3vpn = L3vpn()
        self.config = config()
        self.service_instances = ServiceInstance()
        # when flexbng as L3DCI, need a vrf to publish 0.0.0.0/0 to flexvisor. just need one
        self.dci_vrf = None

        self.gateways = None
        self.tunnel_num = 0


        self.ri_config = None
        self.routing_instances = {}
        self.interfaces_config = None
        self.services_config = None
        self.policy_config = None
        self.firewall_config = None
        self.inet4_forwarding_filter = None
        self.inet6_forwarding_filter = None
        self.forwarding_options_config = None
        self.global_routing_options_config = None
        self.global_switch_options_config = None
        self.vlans_config = None
        self.proto_config = None
        self.route_targets = set()
        self.bgp_peers = {}
        self.chassis_config = None
        self.external_peers = {}
    # ene initialize

    def find_interface_conf(self, interface_name):
        if self.interfaces and self.interfaces.hasContent_():
            for interface in self.interfaces.interface:
                if interface.name == interface_name:
                    return interface
        return None
    # find interface conf

    def find_vfi_conf(self, vfi_name):
        if self.l2smvfi and self.l2smvfi.hasContent_():
            for vfi in self.l2smvfi.vfi:
                if vfi.vfi_name == vfi_name:
                    return vfi
        return None
    # end find vfi conf

    def find_vrf_conf(self, vrf_name):
        if self.l3vpn and self.l3vpn.hasContent_():
            for vrf in self.l3vpn.vrf:
                if vrf.vrfname == vrf_name:
                    return vrf
        return None
    # end find vrf conf

    def device_send(self, conf, default_operation="merge", operation="replace"):
        config_str = self.serialize(conf)
        self.push_config_state = PushConfigState.PUSH_STATE_INIT
        start_time = None
        config_size = 0
        try:
            self.device_connect()
            self._logger.info("\nsend netconf message: %s\n" % config_str)
            config_size = len(config_str)

            self._nc_manager.edit_config(
                    target='candidate', config=config_str,
                    # flexbng dont need test_option.
                    # test_option='test-then-set',
                    default_operation=default_operation)
            self.commit_stats['total_commits_sent_since_up'] += 1
            start_time = time.time()
            self._nc_manager.commit()
            self._logger.info("finish commit")
            end_time = time.time()
            self.commit_stats['commit_status_message'] = 'success'
            self.commit_stats['last_commit_time'] = \
                    datetime.datetime.fromtimestamp(
                    end_time).strftime('%Y-%m-%d %H:%M:%S')
            self.commit_stats['last_commit_duration'] = str(
                    end_time - start_time)
            self.push_config_state = PushConfigState.PUSH_STATE_SUCCESS
        except TimeoutExpiredError:
            self._logger.error("Could not commit(timeout error): (%s, %ss)"
                               % (self.management_ip, self.timeout))
            self.device_disconnect()
            self.timeout = 300
            self.push_config_state = PushConfigState.PUSH_STATE_RETRY
        except Exception as e:
            self._logger.error("Router %s: %s" % (self.management_ip,
                                                      e.message))
            self.commit_stats[
                    'commit_status_message'] = 'failed to apply config,\
                                                router response: ' + e.message
            if start_time is not None:
                self.commit_stats['last_commit_time'] = \
                        datetime.datetime.fromtimestamp(
                            start_time).strftime('%Y-%m-%d %H:%M:%S')
                self.commit_stats['last_commit_duration'] = str(
                        time.time() - start_time)
            self.push_config_state = PushConfigState.PUSH_STATE_RETRY
        return config_size
    # end device_send

    def get_xpath_data(self, res, path_name, is_node=False):
        data = ''
        try:
            if not is_node:
                data = res.xpath(path_name)[0].text
            else:
                data = res.xpath(path_name)[0]
        except IndexError:
            if self._logger:
                self._logger.warning("could not fetch element data: %s, ip: %s" % (
                                             path_name, self.management_ip))
        return data
    # end get_xpath_data

    # get device info from device.but flexbng has no info about device.
    def device_get(self, filters = {}):
        dev_conf = {
                       'product-name': 'flexbng',
                       'product-model': 'flexbng',
                       'software-version': 'v2.11'
                   }
        return dev_conf


    def device_get_bkp(self, filters = {}):
        dev_conf = {
                     'product-name': '',
                     'product-model': '',
                     'software-version': ''
                   }
        try:
            self.device_connect()
            sw_info = new_ele('get-software-information')
            res = self._nc_manager.rpc(sw_info)
            dev_conf['product-name'] = self.get_xpath_data(res,
                                             '//software-information/product-name')
            dev_conf['product-model'] = self.get_xpath_data(res,
                                             '//software-information/product-model')
            dev_conf['software-version'] = self.get_xpath_data(res,
                                             '//software-information/junos-version')
            if not dev_conf.get('software-version'):
                ele = self.get_xpath_data(res,
                     "//software-information/package-information[name='junos-version']", True)
                if ele:
                    dev_conf['software-version'] = ele.find('comment').text
        except Exception as e:
            if self._logger:
                self._logger.error("could not fetch config from router %s: %s" % (
                                          self.management_ip, e.message))
        return dev_conf
    # end device_get

    def device_get_config(self, filter_ele, filter_type="subtree", filter_format="data_ele"):
        try:
            self.device_connect()
            # TODO: check filter_format
            filter_config = self._nc_manager.get_config(source="running", filter=(filter_type, filter_ele)).data_ele
            return filter_config
        except Exception as e:
            if self._logger:
                self._logger.error("could not fetch config from router %s: %s" % (self.management_ip, e.message))
            return None
    # end device_get_config

    def get_vn_li_map(self):
        pr = self.physical_router
        vn_dict = {}
        for vn_id in pr.virtual_networks:
            vn_dict[vn_id] = []

        li_set = pr.logical_interfaces
        for pi_uuid in pr.physical_interfaces:
            pi = PhysicalInterfaceDM.get(pi_uuid)
            if pi is None:
                continue
            li_set |= pi.logical_interfaces
        for li_uuid in li_set:
            li = LogicalInterfaceDM.get(li_uuid)
            if li is None:
                continue
            vmi_id = li.virtual_machine_interface
            vmi = VirtualMachineInterfaceDM.get(vmi_id)
            if vmi is None:
                continue
            vn_id = vmi.virtual_network
            vn_dict.setdefault(vn_id, []).append(
                JunosInterface(li.name, li.li_type, li.vlan_tag))
        return vn_dict
    # end

    def add_product_specific_config(self, groups):
        # override this method to add any product specific configurations
        pass
    # end add_product_specific_config

    # build netconf config
    def build_netconf_config(self):
        if self.interfaces.hasContent_():
            self.config.set_interfaces(self.interfaces)
        if self.router.hasContent_():
            self.config.set_router(self.router)
        if self.l2smvfi.hasContent_():
            self.config.set_l2sm_vfi(self.l2smvfi)
        if self.l3vpn.hasContent_():
            self.config.set_l3vpn(self.l3vpn)
        if self.service_instances.hasContent_():
            self.config.set_service_instance(self.service_instances)
    # end build netconf config

    def serialize(self, obj, obj_name=None, type='string'):
        if isinstance(obj, str):
            return obj
        xml_data = StringIO()
        if obj_name is None:
            obj.export_xml(xml_data, 1)
        elif isinstance(obj_name, str):
            obj.export_xml(xml_data, 1, name_=obj_name)
        xml_str = xml_data.getvalue()
        if type == 'element':
            return etree.fromstring(xml_str)
        else:
            return xml_str
    # end serialize

    def prepare_conf(self, default_operation="merge", operation="replace"):
        self.compare_netconf_config()
        if self.compare_config.hasContent_():
            self.device_send(self.serialize(self.compare_config, obj_name='config'))
            self._logger.info("send compare netconf..")

    def prepare_conf_bkp(self, default_operation="merge", operation="replace"):
        groups = self.prepare_groups(is_delete = True if operation is 'delete' else False)
        return self.build_conf(groups, operation)
    # end prepare_conf

    def has_conf(self):
        if not self.router.hasContent_() or not self.router.bgp.hasContent_():
            return False
        return True
    # end has_conf

    def has_conf_bkp(self):
        if not self.proto_config or not self.proto_config.get_bgp():
            return False
        return True
    # end has_conf_bkp

    def send_conf(self, is_delete=False):
        if not self.has_conf() and not is_delete:
            return 0
        default_operation = "none" if is_delete else "merge"
        operation = "delete" if is_delete else "replace"
        self.prepare_conf(default_operation, operation)
        self.build_netconf_config()
        if self.config.hasContent_():
            return self.device_send(self.config, default_operation, operation)
        else:
            # send nothing to physical router, return success.
            self._logger.info("No netconf to send ,so success commit.")
            return 0
        return self.device_send(conf, default_operation, operation)
    # end send_conf

    def add_lo0_interface(self, loopback_ip=''):
        if not loopback_ip:
            return
        if not self.interfaces:
            self.interfaces = Interfaces()
        lo0_intf = Interface(name='loopback0', description='_contrail_config')
        ipv4 = Ipv4(Address(ip_address=loopback_ip, ip_mask=32))
        lo0_intf.set_ipv4(ipv4)
        self.interfaces.add_interface(lo0_intf)
    # end add lo0 interface

    # flexbng not support dynamic tunnels,so build static tunnels
    # TODO: not support gre tunnel ,now just vxlan tunnel
    def add_static_tunnels(self, tunnel_source_ip, ip_fabric_nets, bgp_router_ips, tunnel_ips=[]):
        if ip_fabric_nets is not None:
            # TODO: create tunnel by fabric net
            pass
        for tunnel_dest_ip in tunnel_ips:
            self.tunnel_num += 1
            tunnel_interface = Interface(name="vxlan-tunnel" + str(self.tunnel_num), description='_contrail_config')
            tunnel = Tunnel(source=tunnel_source_ip, destination=tunnel_dest_ip)
            tunnel_interface.set_tunnel(tunnel)
            interfaces = self.interfaces or Interfaces()
            interfaces.add_interface(tunnel_interface)

    def add_dynamic_tunnels(self, tunnel_source_ip,
                             ip_fabric_nets, bgp_router_ips, vrouter_ips=[]):
        if not vrouter_ips:
            vrouter_ips = self.physical_router.get_vrouter_ip()
        self.add_static_tunnels(tunnel_source_ip, ip_fabric_nets, bgp_router_ips, tunnel_ips=vrouter_ips)
    # end add_dynamic_tunnels

    def set_global_routing_options(self, bgp_params):
        router_id = bgp_params.get('identifier') or bgp_params.get('address')
        if router_id:
            if not self.global_routing_options_config:
                self.global_routing_options_config = RoutingOptions(comment=DMUtils.routing_options_comment())
            self.global_routing_options_config.set_router_id(router_id)
    # end set_global_routing_options

    def is_family_configured(self, params, family_name):
        if params is None or params.get('address_families') is None:
            return False
        families = params['address_families'].get('family', [])
        if family_name in families:
            return True
        return False
    # end is_family_configured

    def add_families(self, parent, params):
        if params.get('address_families') is None:
            return
        families = params['address_families'].get('family', [])
        if not families:
            return
        family_etree = Family()
        parent.set_family(family_etree)
        for family in families:
            fam = family.replace('-', '_')
            if family in ['e-vpn', 'e_vpn']:
                fam = 'evpn'
            if family in self._FAMILY_MAP:
                getattr(family_etree, "set_" + fam)(self._FAMILY_MAP[family])
            else:
                self._logger.info("DM does not support address family: %s" % fam)
    # end add_families

    def add_ibgp_export_policy(self, params, bgp_group):
        if params.get('address_families') is None:
            return
        families = params['address_families'].get('family', [])
        if not families:
            return
        if self.policy_config is None:
            self.policy_config = PolicyOptions(comment=DMUtils.policy_options_comment())
        ps = PolicyStatement(name=DMUtils.make_ibgp_export_policy_name())
        self.policy_config.add_policy_statement(ps)
        ps.set_comment(DMUtils.ibgp_export_policy_comment())
        vpn_types = []
        for family in ['inet-vpn', 'inet6-vpn']:
            if family in families:
                vpn_types.append(family)
        for vpn_type in vpn_types:
            is_v6 = True if vpn_type == 'inet6-vpn' else False
            term = Term(name=DMUtils.make_ibgp_export_policy_term_name(is_v6))
            ps.add_term(term)
            then = Then()
            from_ = From()
            term.set_from(from_)
            term.set_then(then)
            from_.set_family(DMUtils.get_inet_family_name(is_v6))
            then.set_next_hop(NextHop(selfxx=''))
        bgp_group.set_export(DMUtils.make_ibgp_export_policy_name())
    # end add_ibgp_export_policy

    # TODO: need modity, not now
    def add_bgp_auth_config(self, bgp_config, bgp_params):
        if bgp_params.get('auth_data') is None:
            return
        keys = bgp_params['auth_data'].get('key_items', [])
        if len(keys) > 0:
            bgp_config.set_authentication_key(keys[0].get('key'))
    # end add_bgp_auth_config

    # TODO: need modity, not now
    def add_bgp_hold_time_config(self, bgp_config, bgp_params):
        if bgp_params.get('hold_time') is None:
            return
        bgp_config.set_hold_time(bgp_params.get('hold_time'))
    # end add_bgp_hold_time_config

    def set_bgp_config(self, params, bgp_obj):
        self.bgp_params = params
        self.bgp_obj = bgp_obj
    # end set_bgp_config

    def _add_family_etree(self, parent, params):
        if params.get('address_families') is None:
            return
        families = params['address_families'].get('family', [])
        if not families:
            return

        bgp_afi_safis = BgpAfiSafis()
        bgp_address_family = BgpAddressFamily()
        bgp_address_family.set_afi_safi_name('bgp-types:ipv4-unicast')
        bgp_afi_safis.add_address_family(bgp_address_family)

        parent.set_afi_safis(bgp_afi_safis)
    # end _add_family_etree

    def _get_bgp_config(self, external=False):
        if self.bgp_params is None or not self.bgp_params.get('address'):
            return None
        # no difference config between ibgp or ebgp
        bgp_config = self.bgp or Bgp()
        bgp_config.set_local_as(self.bgp_params.get('autonomous_system'))
        bgp_config.set_router_id(self.bgp_params['address'])
        if self.is_family_configured(self.bgp_params, 'e-vpn'):
            bgp_config.set_evpn_traffic_relay('')
        self._add_family_etree(bgp_config, self.bgp_params)
        # self.add_bgp_auth_config(bgp_config, self.bgp_params)
        # self.add_bgp_hold_time_config(bgp_config, self.bgp_params)
        self.bgp = bgp_config
        return bgp_config

    def _get_bgp_config_xml(self, external=False):
        if self.bgp_params is None or not self.bgp_params.get('address'):
            return None
        bgp_group = BgpGroup()
        bgp_group.set_comment(DMUtils.bgp_group_comment(self.bgp_obj))
        if external:
            bgp_group.set_name(DMUtils.make_bgp_group_name(self.get_asn(), True))
            bgp_group.set_type('external')
            bgp_group.set_multihop('')
        else:
            bgp_group.set_name(DMUtils.make_bgp_group_name(self.get_asn(), False))
            bgp_group.set_type('internal')
            self.add_ibgp_export_policy(self.bgp_params, bgp_group)
        bgp_group.set_local_address(self.bgp_params['address'])
        self.add_families(bgp_group, self.bgp_params)
        self.add_bgp_auth_config(bgp_group, self.bgp_params)
        self.add_bgp_hold_time_config(bgp_group, self.bgp_params)
        return bgp_group
    # end _get_bgp_config_xml

    def add_bgp_peer(self, router, params, attr, external, peer):
        peer_data = {}
        peer_data['params'] = params
        peer_data['attr'] = attr
        peer_data['obj'] = peer
        if external:
            self.external_peers[router] = peer_data
        else:
            self.bgp_peers[router] = peer_data
    # end add_peer

    def _get_remote_neighbor_config(self, bgp_config, bgp_obj):
        if not bgp_obj.bgp_remote_neighbours:
            return

        nbrs = bgp_config.get_neighbors()
        for remote_nb in bgp_obj.bgp_remote_neighbours['neighbours']:
            neighbor = Neighbor()
            neighbor.set_neighbor_address(remote_nb["peer_address"])
            neighbor.set_remote_as(remote_nb["remote_asn"])
            neighbor.set_update_source(UpdateSource(ifname='loopback0'))

            if remote_nb.get('address_families', {}):
                afi_safis = NeighborAfiSafis()
                for family in remote_nb.get['address_families'].get('family', []):
                    if family == "l2vpn-evpn":
                        address_family_l2vpn_evpn = NeighborAddressFamily()
                        address_family_l2vpn_evpn.set_afi_safi_name('bgp-types:l2vpn-evpn')
                        address_family_l2vpn_evpn.set_send_community('BOTH')
                        address_family_l2vpn_evpn.set_irb_mode(remote_nb['irb_mode'])
                        afi_safis.add_address_family(address_family_l2vpn_evpn)
                    # TODO: now just support l2vpn-evpn.
                    else:
                        continue
            neighbor.set_afi_safis(afi_safis)
            nbrs.add_neighbor(neighbor)
    # _get_remote_neighbor_config

    def _get_neighbor_config(self, bgp_config, peers):
        neighbors = Neighbors()
        for peer, peer_data in peers.items():
            params = peer_data.get('params', {})
            neighbor = Neighbor()
            if params.get('autonomous_system') is not None:
                neighbor.set_neighbor_address(peer)
                neighbor.set_remote_as(params.get('autonomous_system'))
                neighbor.set_update_source(UpdateSource(ifname='loopback0'))

                if params.get('address_families', {}) and params['address_families'].get('family', []):
                    afi_safis = NeighborAfiSafis()
                    families = params['address_families']['family']
                    for family in families:
                        if family == 'inet-vpn':
                            address_family_l3vpn_ipv4 = NeighborAddressFamily()
                            address_family_l3vpn_ipv4.set_afi_safi_name(self._FAMILY_MAP[family])
                            address_family_l3vpn_ipv4.set_send_community('BOTH')
                            afi_safis.add_address_family(address_family_l3vpn_ipv4)
                        elif family == 'e-vpn':
                            address_family_l2vpn_evpn = NeighborAddressFamily()
                            address_family_l2vpn_evpn.set_afi_safi_name(self._FAMILY_MAP[family])
                            address_family_l2vpn_evpn.set_send_community('BOTH')
                            address_family_l2vpn_evpn.set_irb_mode('asymmetric')
                            afi_safis.add_address_family(address_family_l2vpn_evpn)
                        # TODO:device manger not support inet6-vpn
                        elif family == 'inet6-vpn':
                            continue
                        # device manager not support route-target
                        elif family == 'route-target':
                            continue

                neighbor.set_afi_safis(afi_safis)
            neighbors.add_neighbor(neighbor)
        bgp_config.set_neighbors(neighbors)
    # end get neighbor_config

    def get_asn(self):
        return self.bgp_params.get('local_autonomous_system') or self.bgp_params.get('autonomous_system')
    # end get_asn

    def set_as_config(self):
        if not self.bgp_params.get("identifier"):
            return
        if self.global_routing_options_config is None:
            self.global_routing_options_config = RoutingOptions(comment=DMUtils.routing_options_comment())
        self.global_routing_options_config.set_route_distinguisher_id(self.bgp_params['identifier'])
        self.global_routing_options_config.set_autonomous_system(str(self.get_asn()))
    # end set_as_config

    def set_bgp_router_config(self):
        bgp_config = self._get_bgp_config()
        if not bgp_config:
            return

        self._get_neighbor_config(bgp_config, self.bgp_peers)
        self._get_remote_neighbor_config(bgp_config, self.bgp_obj)
        # TODO:not test this external peers.
        if self.external_peers:
            ext_grp_config = self._get_bgp_config(True)
            self._get_neighbor_config(ext_grp_config, self.external_peers)
            self.router.set_bgp(ext_grp_config)
        self.router.set_bgp(bgp_config)
        return

    # TODO: need modify
    def build_bgp_config(self):
        bgp_router = BgpRouterDM.get(self.physical_router.bgp_router)
        if not bgp_router:
            return
        if bgp_router:
            for peer_uuid, attr in bgp_router.bgp_routers.items():
                peer = BgpRouterDM.get(peer_uuid)
                if not peer or not peer.params or not peer.params.get('address'):
                    continue
                local_as = (bgp_router.params.get('local_autonomous_system') or
                            bgp_router.params.get('autonomous_system'))
                peer_as = (peer.params.get('local_autonomous_system') or
                           peer.params.get('autonomous_system'))
                external = (local_as != peer_as)
                self.add_bgp_peer(peer.params['address'],
                                  peer.params, attr, external, peer)
            self.set_bgp_config(bgp_router.params, bgp_router)
            # self.set_global_routing_options(bgp_router.params)
            bgp_router_ips = bgp_router.get_all_bgp_router_ips()
            tunnel_ip = self.physical_router.dataplane_ip
            if not tunnel_ip and bgp_router.params:
                tunnel_ip = bgp_router.params.get('address')
            if (tunnel_ip and self.physical_router.is_valid_ip(tunnel_ip)):
                self.add_dynamic_tunnels(
                    tunnel_ip,
                    GlobalSystemConfigDM.ip_fabric_subnets,
                    bgp_router_ips)

        if self.physical_router.loopback_ip:
            self.add_lo0_interface(self.physical_router.loopback_ip)
        # self.set_as_config()
        # self.set_bgp_group_config()
        self.set_bgp_router_config()

    def ensure_bgp_config(self):
        if not self.physical_router.bgp_router:
            self._logger.info("bgp router not configured for pr: " + \
                                                 self.physical_router.name)
            return False
        bgp_router = BgpRouterDM.get(self.physical_router.bgp_router)
        if not bgp_router.params or not bgp_router.params.get("address"):
            self._logger.info("bgp router parameters not configured for pr: " + \
                                                 bgp_router.name)
            return False
        return True
    # end ensure_bgp_config

# end JuniperConf


class CertusInterface(object):

    def __init__(self, if_name, if_type, if_vlan_tag=0, if_ip=None):
        self.name = if_name
        self.if_type = if_type
        self.vlan_tag = if_vlan_tag
        ifparts = if_name.split('.')
        self.ifd_name = ifparts[0]
        self.unit = ifparts[1]
        self.ip = if_ip
    # end __init__

    def is_untagged(self):
        if not self.vlan_tag:
            return True
        return False
    # end is_untagged

# end CertusInterface
