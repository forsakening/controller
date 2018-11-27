#
# Copyright (c) 2018 Certus Networks, Inc. All rights reserved.
#

"""
This file contains implementation of netconf interface for physical router
configuration manager
"""

from db import *
from dm_utils import DMUtils
from certus_conf import CertusConf
from certus_conf import CertusInterface
from device_api.certus_common_xsd import *

class FlexbngConf(CertusConf):
    _products = ['flexbng', 'flexedge']

    def __init__(self, logger, params={}):
        self._logger = logger
        self.physical_router = params.get("physical_router")
        super(FlexbngConf, self).__init__()
    # end __init__

    @classmethod
    def register(cls):
        mconf = {
              "vendor": cls._vendor,
              "products": cls._products,
              "class": cls
            }
        return super(FlexbngConf, cls).register(mconf)
    # end register

    @classmethod
    def is_product_supported(cls, name, role):
        if role and role.lower().startswith('e2-'):
            return False
        for product in cls._products or []:
            if name.lower().startswith(product.lower()):
                return True
        return False
    # end is_product_supported

    # add by guwei from certus
    def _check_mac_vaild(self, mac):
        if re.match(r"^\s*([0-9a-fA-F]{2,2}:){5,5}[0-9a-fA-F]{2,2}\s*$", mac): return True
        return False

    def _get_mac_address_by_ip(self, ipaddr=None):
        prefix = '00:50'
        if ipaddr is None:
            return '00:50:ee:3e:ee:e2'
        mac_address = prefix+':'+':'.join([hex(int(x))[2:].zfill(2) for x in ipaddr.split('.')])
        return mac_address

    def _get_random_mac_address(self, prefix=None):
        prefix_len = 0
        if prefix is not None:
            prefix_len = len(prefix.split(":"))

        mac_list = []
        if prefix_len > 7:
            return None

        for i in range(1,(7-prefix_len)):
            rand_str = "".join(random.sample("0123456789abcdef",2))
            mac_list.append(rand_str)
        rand_mac = ":".join(mac_list)
        if prefix is not None:
            mac_address = prefix+":"+rand_mac
            if self._check_mac_vaild(mac_address):
                return mac_address
        else:
            if self._check_mac_vaild(rand_mac):
                return rand_mac
        return None
    # end get mac address

    def add_pnf_logical_interface(self, junos_interface):
        if not self.interfaces_config:
            self.interfaces_config = Interfaces(comment=DMUtils.interfaces_comment())
        family = Family(inet=FamilyInet(address=[Address(name=junos_interface.ip)]))
        unit = Unit(name=junos_interface.unit, vlan_id=junos_interface.vlan_tag, family=family)
        interface = Interface(name=junos_interface.ifd_name)
        interface.add_unit(unit)
        self.interfaces_config.add_interface(interface)
    # end add_pnf_logical_interface

    def config_pnf_logical_interface(self):
        pnf_dict = {}
        pnf_ris = set()
        # make it fake for now
        # sholud save to the database, the allocation
        self.vlan_alloc = {"max": 1}
        self.ip_alloc = {"max": -1}
        self.li_alloc = {}

        for pi_uuid in self.physical_router.physical_interfaces:
            pi = PhysicalInterfaceDM.get(pi_uuid)
            if pi is None:
                continue
            for pi_pi_uuid in pi.physical_interfaces:
                pi_pi = PhysicalInterfaceDM.get(pi_pi_uuid)
                for pi_vmi_uuid in pi_pi.virtual_machine_interfaces:
                    allocate_li = False
                    pi_vmi = VirtualMachineInterfaceDM.get(pi_vmi_uuid)
                    if (pi_vmi is None or
                            pi_vmi.service_instance is None or
                            pi_vmi.service_interface_type is None):
                        continue
                    if pi_vmi.routing_instances:
                        for ri_id in pi_vmi.routing_instances:
                            ri_obj = RoutingInstanceDM.get(ri_id)
                            if ri_obj and ri_obj.routing_instances and ri_obj.service_chain_address:
                                pnf_ris.add(ri_obj)
                                # If this service is on a service chain, we need allocate
                                # a logic interface for its VMI
                                allocate_li = True

                    if allocate_li:
                        resources = self.physical_router.allocate_pnf_resources(pi_vmi)
                        if (not resources or
                                not resources["ip_address"] or
                                not resources["vlan_id"] or
                                not resources["unit_id"]):
                            self._logger.error(
                                "Cannot allocate PNF resources for "
                                "Virtual Machine Interface" + pi_vmi_uuid)
                            return
                        logical_interface = JunosInterface(
                            pi.name + '.' + resources["unit_id"],
                            "l3", resources["vlan_id"], resources["ip_address"])
                        self.add_pnf_logical_interface(
                            logical_interface)
                        lis = pnf_dict.setdefault(
                            pi_vmi.service_instance,
                            {"left": [], "right": [],
                             "mgmt": [], "other": []}
                        )[pi_vmi.service_interface_type]
                        lis.append(logical_interface)

        return (pnf_dict, pnf_ris)

    # end

    def add_pnf_vrfs(self, first_vrf, pnf_dict, pnf_ris):
        is_first_vrf = False
        is_left_first_vrf = False
        for ri_obj in pnf_ris:
            if ri_obj in first_vrf:
                is_first_vrf = True
            else:
                is_first_vrf = False
            export_set = copy.copy(ri_obj.export_targets)
            import_set = copy.copy(ri_obj.import_targets)
            for ri2_id in ri_obj.routing_instances:
                ri2 = RoutingInstanceDM.get(ri2_id)
                if ri2 is None:
                    continue
                import_set |= ri2.export_targets

            pnf_inters = set()
            static_routes = self.physical_router.compute_pnf_static_route(ri_obj, pnf_dict)
            if_type = ""
            for vmi_uuid in ri_obj.virtual_machine_interfaces:
                vmi_obj = VirtualMachineInterfaceDM.get(vmi_uuid)
                if vmi_obj.service_instance is not None:
                    si_obj = ServiceInstanceDM.get(vmi_obj.service_instance)
                    if_type = vmi_obj.service_interface_type
                    pnf_li_inters = pnf_dict[
                        vmi_obj.service_instance][if_type]
                    if if_type == 'left' and is_first_vrf:
                        is_left_first_vrf = True
                    else:
                        is_left_first_vrf = False

                    for pnf_li in pnf_li_inters:
                        pnf_inters.add(pnf_li)

            if pnf_inters:
                vrf_name = self.physical_router.get_pnf_vrf_name(
                    si_obj, if_type, is_left_first_vrf)
                vrf_interfaces = pnf_inters
                ri_conf = {'ri_name': vrf_name}
                ri_conf['si'] = si_obj
                ri_conf['import_targets'] = import_set
                ri_conf['export_targets'] = export_set
                ri_conf['interfaces'] = vrf_interfaces
                ri_conf['static_routes'] = static_routes
                ri_conf['no_vrf_table_label'] = True
                self.add_routing_instance(ri_conf)

    # end add_pnf_vrfs

    # TODO:need modify
    def add_static_routes(self, parent, static_routes):
        static_config = parent.get_static()
        if not static_config:
            static_config = Static()
            parent.set_static(static_config)
        for dest, next_hops in static_routes.items():
            route_config = Route(name=dest)
            for next_hop in next_hops:
                next_hop_str = next_hop.get("next-hop")
                preference = next_hop.get("preference")
                if not next_hop_str:
                    continue
                if preference:
                    route_config.set_qualified_next_hop(QualifiedNextHop(
                        name=next_hop_str, preference=str(preference)))
                else:
                    route_config.set_next_hop(next_hop_str)
            static_config.add_route(route_config)

    # end add_static_routes

    def add_inet_public_vrf_filter(self, forwarding_options_config,
                                   firewall_config, inet_type):
        fo = Family()
        inet_filter = InetFilter(input=DMUtils.make_public_vrf_filter_name(inet_type))
        if inet_type == 'inet6':
            fo.set_inet6(FamilyInet6(filter=inet_filter))
        else:
            fo.set_inet(FamilyInet(filter=inet_filter))
        forwarding_options_config.add_family(fo)

        f = FirewallFilter(name=DMUtils.make_public_vrf_filter_name(inet_type))
        f.set_comment(DMUtils.public_vrf_filter_comment())
        ff = firewall_config.get_family()
        if not ff:
            ff = FirewallFamily()
            firewall_config.set_family(ff)
        if inet_type == 'inet6':
            inet6 = ff.get_inet6()
            if not inet6:
                inet6 = FirewallInet()
                ff.set_inet6(inet6)
            inet6.add_filter(f)
        else:
            inet = ff.get_inet()
            if not inet:
                inet = FirewallInet()
                ff.set_inet(inet)
            inet.add_filter(f)

        term = Term(name="default-term", then=Then(accept=''))
        f.add_term(term)
        return f

    # end add_inet_public_vrf_filter

    def add_inet_filter_term(self, ri_name, prefixes, inet_type):
        if inet_type == 'inet6':
            prefixes = DMUtils.get_ipv6_prefixes(prefixes)
        else:
            prefixes = DMUtils.get_ipv4_prefixes(prefixes)

        from_ = From()
        for prefix in prefixes:
            from_.add_destination_address(prefix)
        then_ = Then()
        then_.add_routing_instance(ri_name)
        return Term(name=DMUtils.make_vrf_term_name(ri_name),
                    fromxx=from_, then=then_)
    # end add_inet_filter_term

    def _check_dci(self, bgp_remote_neghbours):
        return (self._check_l2_dci(bgp_remote_neghbours) or self._check_l3_dci(bgp_remote_neghbours))

    def _check_l2_dci(self, bgp_remote_neighbours):
        if bgp_remote_neighbours is not None and \
                bgp_remote_neighbours['neighbours'] != [] and self.db_l2_dci is not None:
            return True
        return False

    def _check_l3_dci(self, bgp_remote_neighbours):
        if bgp_remote_neighbours is not None and \
                bgp_remote_neighbours['neighbours'] != [] and self.db_l3_dci is not None:
            return True
        return False

    def config_bgp_l3_dci(self, bgp_remote_neighbours, bgp_config, routing_instances, bgp_params):
        if not self._check_l3_dci(bgp_remote_neighbours) or bgp_config is None:
            return

        bgp_config.set_evpn_traffic_relay("")
        system_mac = self._get_mac_address_by_ip(self.management_ip)
        self.config.set_system_mac(SystemMac(system_mac=system_mac))
        # config vrf two  vrf _2bng2 use to flexvior ,vrf _2flexvisor use to type-5
        interfaces = self.interfaces or Interfaces()
        dci_vrf = Vrf(vrfname=self.db_l3_dci.vrf_l3_dci_name)
        dci_vrf.set_rd(str(bgp_params['autonomous_system']) + ":" + str(self.db_l3_dci.l3_vnid))
        route_target = RouteTarget()
        for rt_i in routing_instances['import_targets']:
            route_target.add_import(rt_i[7:])
        for rt_e in routing_instances['export_targets']:
            route_target.add_export(rt_e[7:])
        dci_vrf.set_route_target(route_target)
        self.l3vpn.add_vrf(dci_vrf)

        loopback_interface = Interface(name='loopback100', description='_contrail_config')
        vrf_bind = InterfaceBind(vrf=BindVrf(vrf_name=self.db_l3_dci.vrf_l3_dci_name))
        loopback_interface.set_bind(vrf_bind)
        self.interfaces.add_interface(loopback_interface)

        neis = bgp_config.get_neighbors()
        for nei in neis.get_neighbor():
            afi_safis = nei.get_afi_safis()
            for family in afi_safis.get_address_family():
                if 'l3vpn-ipv4-unicast' in family.afi_safi_name:
                    family.set_defaultoriginatevrf(
                        DefaultOriginateVrf(default_originate_vrf=self.db_l3_dci.vrf_l3_dci_name))

        for neighbour in bgp_remote_neighbours['neighbours']:
            # add tunnel
            self.tunnel_num += 1
            tunnel_interface = Interface(name="vxlan-tunnel" + str(self.tunnel_num), description='_contrail_config')
            tunnel_interface.set_tunnel(Tunnel(source=bgp_params['address'], destination=neighbour['peer_address']))
            interfaces.add_interface(tunnel_interface)

        bgp_vrf = BgpVrf(vrfname=self.db_l3_dci.vrf_l3_dci_name)
        afi_safis = VrfAfiSafis()
        address_family = VrfAddressFamily()
        address_family.set_afi_safi_name('bgp-types:ipv4-unicast')
        address_family.set_redistribute(Redistribute(routing_protocol='static'))
        afi_safis.add_address_family(address_family)
        bgp_vrf.set_afi_safis(afi_safis)
        bgp_config.add_vrf(bgp_vrf)
    # config bgp l3 dci

    # config bgp when flexbng as l2 dci
    def config_bgp_l2_dci(self, bgp_remote_neighbours, bgp_config, bgp_params):
        if not self._check_l2_dci(bgp_remote_neighbours) or bgp_config is None:
            return

        bgp_config.set_evpn_traffic_relay("")
        for neighbour in bgp_remote_neighbours['neighbours']:
            # add tunnel
            self.tunnel_num = self.tunnel_num + 1
            interfaces = self.interfaces or Interfaces()
            tunnel_interface = Interface(name="vxlan-tunnel" + str(self.tunnel_num), description='_contrail_config')
            tunnel = Tunnel(source=bgp_params['address'], destination=neighbour['peer_address'])
            tunnel_interface.set_tunnel(tunnel)
            interfaces.add_interface(tunnel_interface)
    # end config bgp l2 dci

    # add remote vxlan tunnel in dci mode.
    def add_remote_tunnels(self, bgp_remote_neighbours, bgp_params):
        interfaces = self.interfaces or Interfaces()
        for neighbour in bgp_remote_neighbours['neighbours']:
            # add tunnel
            self.tunnel_num += 1
            tunnel_interface = Interface(name="vxlan-tunnel" + str(self.tunnel_num), description='_contrail_config')
            tunnel_interface.set_tunnel(Tunnel(source=bgp_params['address'], destination=neighbour['peer_address']))
            interfaces.add_interface(tunnel_interface)

    def config_bgp_config(self, bgp_config, is_l2, is_l2_l3, external, ri_name, bgp_remote_neighbours):
        if bgp_config is None or self._check_dci(bgp_remote_neighbours):
            if self._check_l3_dci(bgp_remote_neighbours) and not is_l2 and 'l3' == ri_name.split("_")[2]:
                network = self.db_l3_dci.get_network_subnet(ri_name)
                if network is not None:
                    bgp_vrf_type5 = BgpVrf(vrfname=ri_name)
                    afi_safis_type5 = VrfAfiSafis()
                    address_family_type5 = VrfAddressFamily()
                    address_family_type5.set_afi_safi_name('bgp-types:ipv4-unicast')
                    address_family_type5.set_network(NetWork(network_prefix=network))
                    afi_safis_type5.add_address_family(address_family_type5)
                    bgp_vrf_type5.set_afi_safis(afi_safis_type5)
                    bgp_config.add_vrf(bgp_vrf_type5)
            return

        if not is_l2 and external and is_l2_l3 and 'l3' == ri_name.split("_")[2]:
            bgp_vrf = BgpVrf(vrfname=ri_name)
            vrf_afi_safis = VrfAfiSafis()
            vrf_address_family = VrfAddressFamily(afi_safi_name='bgp-types:ipv4-unicast')
            vrf_address_family.set_redistribute(Redistribute(routing_protocol='static'))
            vrf_afi_safis.add_address_family(vrf_address_family)
            bgp_vrf.set_afi_safis(vrf_afi_safis)

            bgp = self.router.get_bgp()
            bgp.add_vrf(bgp_vrf)

            neis = bgp.get_neighbors()
            for nei in neis.get_neighbor():
                afi_safis = nei.get_afi_safis()
                for family in afi_safis.get_address_family():
                    if 'l3vpn-ipv4-unicast' in family.afi_safi_name:
                        family.set_defaultoriginatevrf(DefaultOriginateVrf(default_originate_vrf=ri_name))
    # end config bgp config

    # 1. flexbng as L2_GW 2. flexbng as L3_GW
    # TODO: flexbng as L2DCI_GW and L3DCI_GW
    def add_routing_instance(self, ri_conf):
        ri_l2_name = ri_conf.get("ri_l2_name")
        ri_l3_name = ri_conf.get("ri_l3_name")
        mode = ri_conf.get('mode')
        vn = ri_conf.get("vn")
        si = ri_conf.get("si")
        is_l2 = ri_conf.get("is_l2", False)
        is_l2_l3 = ri_conf.get("is_l2_l3", False)
        import_targets = ri_conf.get("import_targets", set())
        export_targets = ri_conf.get("export_targets", set())
        prefixes = ri_conf.get("prefixes", [])
        gateways = ri_conf.get("gateways", [])
        router_external = ri_conf.get("router_external", False)
        interfaces = ri_conf.get("interfaces", [])
        vni = ri_conf.get("vni", None)
        fip_map = ri_conf.get("fip_map", None)
        network_id = ri_conf.get("network_id", None)
        static_routes = ri_conf.get("static_routes", {})
        no_vrf_table_label = ri_conf.get("no_vrf_table_label", False)
        restrict_proxy_arp = ri_conf.get("restrict_proxy_arp", False)
        highest_enapsulation_priority = \
            ri_conf.get("highest_enapsulation_priority") or "MPLSoGRE"

        # flexbng as l2gw
        # if (mode == 'l2gw' and is_l2 and vni is not None and self.is_family_configured(prc.bgp_params,'e-vpn')):
        # all virtual  network has one vfi
        if (vni is not None and self.is_family_configured(self.bgp_params,'e-vpn')):
            l2smvfi = self.l2smvfi or L2smVfi()
            if not self.find_vfi_conf(ri_l2_name):
                vfi = Vfi()
                l2smvfi.add_vfi(vfi)
            else:
                vfi = self.find_vfi_conf(ri_l2_name)
            vfi.set_vfi_name(ri_l2_name)
            vfi.set_flooding('enable')

            vxlantunnelconf = VxlanTunnelConf(mac_learning='disable', arp_learning='enable')
            vfi.set_remote(Remote(vxlan_tunnel=vxlantunnelconf))
            vfi.set_arp_suppression(ArpSuppression(enable=''))

            vfiservice = VfiService(type_='evpn')

            servicetypeevpn = ServiceTypeEvpn(vni=vni, rd=self.bgp_params['identifier']+":"+str(vni))
            servicetypeevpn.set_vtep_source(self.bgp_params['address'])
            vfiservice.set_evpn(servicetypeevpn)
            routetarget = RouteTarget()
            for rt_i in import_targets:
                routetarget.add_import(rt_i[7:])
            for rt_e in export_targets:
                routetarget.add_export(rt_e[7:])
            servicetypeevpn.set_route_target(routetarget)
            vfi.set_service(vfiservice)

            # l2smvfi.add_vfi(vfi)

        # flexbng as l2 gateway
        # if not router_external and is_l2 and not self._check_dci(prc.bgp_remote_neighbours):
        if 'l2gw' in self.physical_router.get_vn_lr_modes(vn.uuid):
            # service instance
            for option in self.physical_router.attach_vn_lr[vn.uuid]['options']:
                if 'mode' in option and 'l2gw' == option['mode']:
                    try:
                        l2gw_interface = option['interface_name']
                    except:
                        l2gw_interface = '10gei-1/1/2'
                
                    vlan = vn.attach_vlan

                    instance = Instance(instance_id=network_id)
                    instance_bind = InstanceBind()
                    # need l2gw_interface and vlan.
                    instance_bind.set_port(InstanceBindPort(name=l2gw_interface, vlan=InstanceBindPortVlan(vlan_id=vlan)))
                    instance.set_bind(instance_bind)
                    self.service_instances.add_instance(instance)
                    intfs = self.interfaces or Interfaces()
                    interface = Interface(name=l2gw_interface, description='_contrail_config')
                    intfs.add_interface(interface)

                    vfi_service_instance = VfiServiceInstance(instance_id=network_id, access_mode='vlan')
                    vfi.set_service_instance(vfi_service_instance)

        # flexbng as l3 gateway
        # elif router_external and not is_l2 and not self._check_dci(prc.bgp_remote_neighbours):
        if 'l3gw' in self.physical_router.get_vn_lr_modes(vn.uuid) and not is_l2:
            l3vpn = self.l3vpn or L3vpn()
            if not self.find_vrf_conf(ri_l3_name):
                vrf = Vrf()
                l3vpn.add_vrf(vrf)
            else:
                vrf = self.find_vrf_conf(ri_l3_name)

            vrf.set_vrfname(ri_l3_name)
            # rd is local as : network_id
            vrf.set_rd(self.bgp_params['identifier']+":"+str(network_id))

            vrf_routetarget = RouteTarget()
            address_routetarget = RouteTarget()
            for rt_i in import_targets:
                address_routetarget.add_import(rt_i[7:])
            for rt_e in export_targets:
                address_routetarget.add_export(rt_e[7:])
                vrf_routetarget.add_export(rt_e[7:])

            vrf.set_route_target(vrf_routetarget)

            l3vpn_af = L3vpnVrfAddressFamily()
            l3vpn_af.set_route_target(address_routetarget)
            vrf.set_address_family(l3vpn_af)

            for option in self.physical_router.attach_vn_lr[vn.uuid]['options']:
                if 'mode' in option and 'l3gw' == option['mode']:
                    try:
                        l3gw_interface = option['interface_name']
                        l3gw_ip = option['ipaddr']
                    except:
                        l3gw_interface = '10gei-1/1/1'
            # if has irb, then create irb and modify vfi
            if vn.irb:
                irb_ipaddr = vn.irb.split('/')[0]
                irb_len = vn.irb.split('/')[-1]
                mac_address = self._get_mac_address_by_ip(ipaddr=irb_ipaddr)
                irb_intf = Interface(name='irb'+str(network_id), description='_contrail_config')
                irb_intf.set_gateway_mac(mac_address)
                irb_ipv4 = Ipv4(address=Address(ip_address=irb_ipaddr, ip_mask=int(irb_len)))
                irb_intf.set_ipv4(irb_ipv4)
                bind_vrf = InterfaceBind(vrf=BindVrf(vrf_name=ri_l3_name))
                irb_intf.set_bind(bind_vrf)
                self.interfaces.add_interface(irb_intf)

                vfis = self.l2smvfi.get_vfi()
                for vfi in vfis:
                    if vfi.get_vfi_name().split('-')[:-2] == ri_l3_name.split('-')[:-2]:
                        vfi.set_gateway('irb'+str(network_id))
                        vfi.get_service().set_type('evpn')
                        evpn = vfi.get_service().get_evpn()
                        evpn.set_xconnect_vrf(ri_l3_name)

                # need l3gw_interface, l3gw_ip / vlan
                up_interface = Interface(name=l3gw_interface, description='_contrail_config')
                l3gw_ipv4 = Ipv4(address=Address(ip_address=l3gw_ip.split('/')[0], ip_mask=int(l3gw_ip.split('/')[1])))
                up_interface.set_ipv4(l3gw_ipv4)
                bind_vrf = InterfaceBind(vrf=BindVrf(vrf_name=ri_l3_name))
                up_interface.set_bind(bind_vrf)

                self.interfaces.add_interface(up_interface)
            # l3vpn.add_vrf(vrf)

    '''
     ri_name: routing instance name to be configured on mx
     is_l2:  a flag used to indicate routing instance type, i.e : l2 or l3
     is_l2_l3:  VN forwarding mode is of type 'l2_l3' or not
     import/export targets: routing instance import, export targets
     prefixes: for l3 vrf static routes and for public vrf filter terms
     gateways: for l2 evpn, bug#1395944
     router_external: this indicates the routing instance configured is for
                      the public network
     interfaces: logical interfaces to be part of vrf
     fip_map: contrail instance ip to floating-ip map, used for snat & floating ip support
     network_id : this is used for configuraing irb interfaces
     static_routes: this is used for add PNF vrf static routes
     no_vrf_table_label: if this is set to True will not generate vrf table label knob
     restrict_proxy_arp: proxy-arp restriction config is generated for irb interfaces
                         only if vn is external and has fip map
     highest_enapsulation_priority: highest encapsulation configured
    '''
    def add_routing_instance_bkp(self, ri_conf):
        ri_name = ri_conf.get("ri_name")
        vn = ri_conf.get("vn")
        si = ri_conf.get("si")
        is_l2 = ri_conf.get("is_l2", False)
        is_l2_l3 = ri_conf.get("is_l2_l3", False)
        import_targets = ri_conf.get("import_targets", set())
        export_targets = ri_conf.get("export_targets", set())
        prefixes = ri_conf.get("prefixes", [])
        gateways = ri_conf.get("gateways", [])
        router_external = ri_conf.get("router_external", False)
        interfaces = ri_conf.get("interfaces", [])
        vni = ri_conf.get("vni", None)
        fip_map = ri_conf.get("fip_map", None)
        network_id = ri_conf.get("network_id", None)
        static_routes = ri_conf.get("static_routes", {})
        no_vrf_table_label = ri_conf.get("no_vrf_table_label", False)
        restrict_proxy_arp = ri_conf.get("restrict_proxy_arp", False)
        highest_enapsulation_priority = \
            ri_conf.get("highest_enapsulation_priority") or "MPLSoGRE"

        self.routing_instances[ri_name] = ri_conf
        ri_config = self.ri_config or RoutingInstances(comment=DMUtils.routing_instances_comment())
        policy_config = self.policy_config or PolicyOptions(comment=DMUtils.policy_options_comment())
        ri = Instance(name=ri_name)
        if vn:
            is_nat = True if fip_map else False
            ri.set_comment(DMUtils.vn_ri_comment(vn, is_l2, is_l2_l3, is_nat, router_external))
        elif si:
            ri.set_comment(DMUtils.si_ri_comment(si))
        ri_config.add_instance(ri)
        ri_opt = None
        if router_external and is_l2 == False:
            ri_opt = RoutingInstanceRoutingOptions(
                static=Static(route=[Route(name="0.0.0.0/0",
                                           next_table="inet.0",
                                           comment=DMUtils.public_vrf_route_comment())]))
            ri.set_routing_options(ri_opt)

        # for both l2 and l3
        ri.set_vrf_import(DMUtils.make_import_name(ri_name))
        ri.set_vrf_export(DMUtils.make_export_name(ri_name))

        has_ipv6_prefixes = DMUtils.has_ipv6_prefixes(prefixes)
        has_ipv4_prefixes = DMUtils.has_ipv4_prefixes(prefixes)

        if not is_l2:
            if ri_opt is None:
                ri_opt = RoutingInstanceRoutingOptions()
                ri.set_routing_options(ri_opt)
            if prefixes and fip_map is None:
                static_config = ri_opt.get_static()
                if not static_config:
                    static_config = Static()
                    ri_opt.set_static(static_config)
                rib_config_v6 = None
                static_config_v6 = None
                for prefix in prefixes:
                    if ':' in prefix and not rib_config_v6:
                        static_config_v6 = Static()
                        rib_config_v6 = RIB(name=ri_name + ".inet6.0")
                        rib_config_v6.set_static(static_config_v6)
                        ri_opt.set_rib(rib_config_v6)
                    if ':' in prefix:
                        static_config_v6.add_route(Route(name=prefix, discard=''))
                    else:
                        static_config.add_route(Route(name=prefix, discard=''))
                    if router_external:
                        self.add_to_global_ri_opts(prefix)

            ri.set_instance_type("vrf")
            if not no_vrf_table_label:
                ri.set_vrf_table_label('')  # only for l3
            if fip_map is None:
                for interface in interfaces:
                    ri.add_interface(Interface(name=interface.name))
            if static_routes:
                self.add_static_routes(ri_opt, static_routes)
            family = Family()
            if has_ipv4_prefixes:
                family.set_inet(FamilyInet(unicast=''))
            if has_ipv6_prefixes:
                family.set_inet6(FamilyInet6(unicast=''))
            if has_ipv4_prefixes or has_ipv6_prefixes:
                auto_export = AutoExport(family=family)
                ri_opt.set_auto_export(auto_export)
        else:
            if highest_enapsulation_priority == "VXLAN":
                ri.set_instance_type("virtual-switch")
            elif highest_enapsulation_priority in ["MPLSoGRE", "MPLSoUDP"]:
                ri.set_instance_type("evpn")

        if fip_map is not None:
            if ri_opt is None:
                ri_opt = RoutingInstanceRoutingOptions()
                ri.set_routing_options(ri_opt)
            static_config = ri_opt.get_static()
            if not static_config:
                static_config = Static()
                ri_opt.set_static(static_config)
            static_config.add_route(Route(name="0.0.0.0/0",
                                          next_hop=interfaces[0].name,
                                          comment=DMUtils.fip_ingress_comment()))
            ri.add_interface(Interface(name=interfaces[0].name))

            public_vrf_ips = {}
            for pip in fip_map.values():
                if pip["vrf_name"] not in public_vrf_ips:
                    public_vrf_ips[pip["vrf_name"]] = set()
                public_vrf_ips[pip["vrf_name"]].add(pip["floating_ip"])

            for public_vrf, fips in public_vrf_ips.items():
                ri_public = Instance(name=public_vrf)
                ri_config.add_instance(ri_public)
                ri_public.add_interface(Interface(name=interfaces[1].name))

                ri_opt = RoutingInstanceRoutingOptions()
                ri_public.set_routing_options(ri_opt)
                static_config = Static()
                ri_opt.set_static(static_config)

                for fip in fips:
                    static_config.add_route(Route(name=fip + "/32",
                                                  next_hop=interfaces[1].name,
                                                  comment=DMUtils.fip_egress_comment()))

        # add policies for export route targets
        ps = PolicyStatement(name=DMUtils.make_export_name(ri_name))
        if vn:
            ps.set_comment(DMUtils.vn_ps_comment(vn, "Export"))
        elif si:
            ps.set_comment(DMUtils.si_ps_comment(si, "Export"))
        then = Then()
        ps.add_term(Term(name="t1", then=then))
        for route_target in export_targets:
            comm = Community(add='',
                             community_name=DMUtils.make_community_name(route_target))
            then.add_community(comm)
        if fip_map is not None:
            # for nat instance
            then.set_reject('')
        else:
            then.set_accept('')
        policy_config.add_policy_statement(ps)

        # add policies for import route targets
        ps = PolicyStatement(name=DMUtils.make_import_name(ri_name))
        if vn:
            ps.set_comment(DMUtils.vn_ps_comment(vn, "Import"))
        elif si:
            ps.set_comment(DMUtils.si_ps_comment(si, "Import"))
        from_ = From()
        term = Term(name="t1", fromxx=from_)
        ps.add_term(term)
        for route_target in import_targets:
            from_.add_community(DMUtils.make_community_name(route_target))
        term.set_then(Then(accept=''))
        ps.set_then(Then(reject=''))
        policy_config.add_policy_statement(ps)

        # add firewall config for public VRF
        forwarding_options_config = self.forwarding_options_config
        firewall_config = self.firewall_config
        if router_external and is_l2 == False:
            forwarding_options_config = (self.forwarding_options_config or
                                         ForwardingOptions(DMUtils.forwarding_options_comment()))
            firewall_config = self.firewall_config or Firewall(DMUtils.firewall_comment())
            if has_ipv4_prefixes and not self.inet4_forwarding_filter:
                # create single instance inet4 filter
                self.inet4_forwarding_filter = self.add_inet_public_vrf_filter(
                    forwarding_options_config,
                    firewall_config, "inet")
            if has_ipv6_prefixes and not self.inet6_forwarding_filter:
                # create single instance inet6 filter
                self.inet6_forwarding_filter = self.add_inet_public_vrf_filter(
                    forwarding_options_config,
                    firewall_config, "inet6")
            if has_ipv4_prefixes:
                # add terms to inet4 filter
                term = self.add_inet_filter_term(ri_name, prefixes, "inet4")
                # insert before the last term
                terms = self.inet4_forwarding_filter.get_term()
                terms = [term] + (terms or [])
                self.inet4_forwarding_filter.set_term(terms)
            if has_ipv6_prefixes:
                # add terms to inet6 filter
                term = self.add_inet_filter_term(ri_name, prefixes, "inet6")
                # insert before the last term
                terms = self.inet6_forwarding_filter.get_term()
                terms = [term] + (terms or [])
                self.inet6_forwarding_filter.set_term(terms)

        if fip_map is not None:
            firewall_config = firewall_config or Firewall(DMUtils.firewall_comment())
            f = FirewallFilter(name=DMUtils.make_private_vrf_filter_name(ri_name))
            f.set_comment(DMUtils.vn_firewall_comment(vn, "private"))
            ff = firewall_config.get_family()
            if not ff:
                ff = FirewallFamily()
                firewall_config.set_family(ff)
            inet = ff.get_inet()
            if not inet:
                inet = FirewallInet()
                ff.set_inet(inet)
            inet.add_filter(f)

            term = Term(name=DMUtils.make_vrf_term_name(ri_name))
            from_ = From()
            for fip_user_ip in fip_map.keys():
                from_.add_source_address(fip_user_ip)
            term.set_from(from_)
            term.set_then(Then(routing_instance=[ri_name]))
            f.add_term(term)

            term = Term(name="default-term", then=Then(accept=''))
            f.add_term(term)

            interfaces_config = self.interfaces_config or Interfaces(comment=DMUtils.interfaces_comment())
            irb_intf = Interface(name="irb")
            interfaces_config.add_interface(irb_intf)

            intf_unit = Unit(name=str(network_id),
                             comment=DMUtils.vn_irb_fip_inet_comment(vn))
            if restrict_proxy_arp:
                intf_unit.set_proxy_arp(ProxyArp(restricted=''))
            inet = FamilyInet()
            inet.set_filter(InetFilter(input=DMUtils.make_private_vrf_filter_name(ri_name)))
            intf_unit.set_family(Family(inet=inet))
            irb_intf.add_unit(intf_unit)

        # add L2 EVPN and BD config
        bd_config = None
        interfaces_config = self.interfaces_config
        proto_config = self.proto_config
        if (is_l2 and vni is not None and
                self.is_family_configured(self.bgp_params, "e-vpn")):
            ri.set_vtep_source_interface("lo0.0")
            if highest_enapsulation_priority == "VXLAN":
                bd_config = BridgeDomains()
                ri.set_bridge_domains(bd_config)
                bd = Domain(name=DMUtils.make_bridge_name(vni), vlan_id='none', vxlan=VXLan(vni=vni))
                bd.set_comment(DMUtils.vn_bd_comment(vn, "VXLAN"))
                bd_config.add_domain(bd)
                for interface in interfaces:
                    bd.add_interface(Interface(name=interface.name))
                if is_l2_l3:
                    # network_id is unique, hence irb
                    bd.set_routing_interface("irb." + str(network_id))
                ri.set_protocols(RoutingInstanceProtocols(
                    evpn=Evpn(encapsulation='vxlan', extended_vni_list='all')))
            elif highest_enapsulation_priority in ["MPLSoGRE", "MPLSoUDP"]:
                ri.set_vlan_id('none')
                if is_l2_l3:
                    # network_id is unique, hence irb
                    ri.set_routing_interface("irb." + str(network_id))
                evpn = Evpn()
                evpn.set_comment(DMUtils.vn_evpn_comment(vn, highest_enapsulation_priority))
                for interface in interfaces:
                    evpn.add_interface(Interface(name=interface.name))
                ri.set_protocols(RoutingInstanceProtocols(evpn=evpn))

            interfaces_config = self.interfaces_config or Interfaces(comment=DMUtils.interfaces_comment())
            if is_l2_l3:
                irb_intf = Interface(name='irb', gratuitous_arp_reply='')
                interfaces_config.add_interface(irb_intf)
                if gateways is not None:
                    intf_unit = Unit(name=str(network_id),
                                     comment=DMUtils.vn_irb_comment(vn, False, is_l2_l3))
                    irb_intf.add_unit(intf_unit)
                    family = Family()
                    intf_unit.set_family(family)
                    inet = None
                    inet6 = None
                    for (irb_ip, gateway) in gateways:
                        if ':' in irb_ip:
                            if not inet6:
                                inet6 = FamilyInet6()
                                family.set_inet6(inet6)
                            addr = Address()
                            inet6.add_address(addr)
                        else:
                            if not inet:
                                inet = FamilyInet()
                                family.set_inet(inet)
                            addr = Address()
                            inet.add_address(addr)
                        addr.set_name(irb_ip)
                        addr.set_comment(DMUtils.irb_ip_comment(irb_ip))
                        if len(gateway) and gateway != '0.0.0.0':
                            addr.set_virtual_gateway_address(gateway)

            self.build_l2_evpn_interface_config(interfaces_config, interfaces, vn)

        if (not is_l2 and not is_l2_l3 and gateways):
            interfaces_config = self.interfaces_config or Interfaces(comment=DMUtils.interfaces_comment())
            ifl_num = str(1000 + int(network_id))
            lo_intf = Interface(name="lo0")
            interfaces_config.add_interface(lo_intf)
            intf_unit = Unit(name=ifl_num, comment=DMUtils.l3_lo_intf_comment(vn))
            lo_intf.add_unit(intf_unit)
            family = Family()
            intf_unit.set_family(family)
            inet = None
            inet6 = None
            for (lo_ip, _) in gateways:
                subnet = lo_ip
                (ip, _) = lo_ip.split('/')
                if ':' in lo_ip:
                    if not inet6:
                        inet6 = FamilyInet6()
                        family.set_inet6(inet6)
                    addr = Address()
                    inet6.add_address(addr)
                    lo_ip = ip + '/' + '128'
                else:
                    if not inet:
                        inet = FamilyInet()
                        family.set_inet(inet)
                    addr = Address()
                    inet.add_address(addr)
                    lo_ip = ip + '/' + '32'
                addr.set_name(lo_ip)
                addr.set_comment(DMUtils.lo0_ip_comment(subnet))
            ri.add_interface(Interface(name="lo0." + ifl_num,
                                       comment=DMUtils.lo0_ri_intf_comment(vn)))

        # fip services config
        services_config = self.services_config
        if fip_map is not None:
            services_config = self.services_config or Services()
            services_config.set_comment(DMUtils.services_comment())
            service_name = DMUtils.make_services_set_name(ri_name)
            service_set = ServiceSet(name=service_name)
            service_set.set_comment(DMUtils.service_set_comment(vn))
            services_config.add_service_set(service_set)
            nat_rule = NATRules(name=service_name + "-sn-rule")
            service_set.add_nat_rules(NATRules(name=DMUtils.make_snat_rule_name(ri_name),
                                               comment=DMUtils.service_set_nat_rule_comment(vn, "SNAT")))
            service_set.add_nat_rules(NATRules(name=DMUtils.make_dnat_rule_name(ri_name),
                                               comment=DMUtils.service_set_nat_rule_comment(vn, "DNAT")))
            next_hop_service = NextHopService(inside_service_interface=interfaces[0].name,
                                              outside_service_interface=interfaces[1].name)
            service_set.set_next_hop_service(next_hop_service)

            nat = NAT(allow_overlapping_nat_pools='')
            nat.set_comment(DMUtils.nat_comment())
            services_config.add_nat(nat)
            snat_rule = Rule(name=DMUtils.make_snat_rule_name(ri_name),
                             match_direction="input")
            snat_rule.set_comment(DMUtils.snat_rule_comment())
            nat.add_rule(snat_rule)
            dnat_rule = Rule(name=DMUtils.make_dnat_rule_name(ri_name),
                             match_direction="output")
            dnat_rule.set_comment(DMUtils.dnat_rule_comment())
            nat.add_rule(dnat_rule)

            for pip, fip_vn in fip_map.items():
                fip = fip_vn["floating_ip"]
                term = Term(name=DMUtils.make_ip_term_name(pip))
                snat_rule.set_term(term)
                # private ip
                from_ = From(source_address=[pip + "/32"])
                term.set_from(from_)
                # public ip
                then_ = Then()
                term.set_then(then_)
                translated = Translated(source_prefix=fip + "/32",
                                        translation_type=TranslationType(basic_nat44=''))
                then_.set_translated(translated)

                term = Term(name=DMUtils.make_ip_term_name(fip))
                dnat_rule.set_term(term)

                # public ip
                from_ = From(destination_address=[fip + "/32"])
                term.set_from(from_)
                # private ip
                then_ = Then()
                term.set_then(then_)
                translated = Translated(destination_prefix=pip + "/32",
                                        translation_type=TranslationType(dnat_44=''))
                then_.set_translated(translated)

            interfaces_config = self.interfaces_config or Interfaces(comment=DMUtils.interfaces_comment())
            si_intf = Interface(name=interfaces[0].ifd_name,
                                comment=DMUtils.service_ifd_comment())
            interfaces_config.add_interface(si_intf)

            intf_unit = Unit(name=interfaces[0].unit,
                             comment=DMUtils.service_intf_comment("Ingress"))
            si_intf.add_unit(intf_unit)
            family = Family(inet=FamilyInet())
            intf_unit.set_family(family)
            intf_unit.set_service_domain("inside")

            intf_unit = Unit(name=interfaces[1].unit,
                             comment=DMUtils.service_intf_comment("Egress"))
            si_intf.add_unit(intf_unit)
            family = Family(inet=FamilyInet())
            intf_unit.set_family(family)
            intf_unit.set_service_domain("outside")

        self.forwarding_options_config = forwarding_options_config
        self.firewall_config = firewall_config
        self.policy_config = policy_config
        self.proto_config = proto_config
        self.interfaces_config = interfaces_config
        self.services_config = services_config
        self.route_targets |= import_targets | export_targets
        self.ri_config = ri_config

    # end add_routing_instance

    # TODO: need modify
    def build_l2_evpn_interface_config(self, interfaces_config, interfaces, vn=None):
        ifd_map = {}
        for interface in interfaces:
            ifd_map.setdefault(interface.ifd_name, []).append(interface)

        for ifd_name, interface_list in ifd_map.items():
            intf = Interface(name=ifd_name)
            interfaces_config.add_interface(intf)
            if interface_list[0].is_untagged():
                if (len(interface_list) > 1):
                    self._logger.error(
                        "invalid logical interfaces config for ifd %s" % (
                            ifd_name))
                    continue
                intf.set_encapsulation("ethernet-bridge")
                intf.add_unit(Unit(name=interface_list[0].unit,
                                   comment=DMUtils.l2_evpn_intf_unit_comment(vn, False),
                                   family=Family(bridge='')))
            else:
                intf.set_flexible_vlan_tagging('')
                intf.set_encapsulation("flexible-ethernet-services")
                for interface in interface_list:
                    intf.add_unit(Unit(name=interface.unit,
                                       comment=DMUtils.l2_evpn_intf_unit_comment(vn,
                                                                                 True, interface.vlan_tag),
                                       encapsulation='vlan-bridge',
                                       vlan_id=str(interface.vlan_tag)))

    # end build_l2_evpn_interface_config

    def add_to_global_ri_opts(self, prefix):
        if not prefix:
            return
        if self.global_routing_options_config is None:
            self.global_routing_options_config = RoutingOptions(comment=DMUtils.routing_options_comment())
        static_config = Static()
        if ':' in prefix:
            rib_config_v6 = RIB(name='inet6.0')
            rib_config_v6.set_static(static_config)
            self.global_routing_options_config.add_rib(rib_config_v6)
        else:
            self.global_routing_options_config.add_static(static_config)
        static_config.add_route(Route(name=prefix, discard=''))

    # end add_to_global_ri_opts

    def set_route_targets_config(self):
        if self.policy_config is None:
            self.policy_config = PolicyOptions(comment=DMUtils.policy_options_comment())
        for route_target in self.route_targets:
            comm = CommunityType(name=DMUtils.make_community_name(route_target))
            comm.add_members(route_target)
            self.policy_config.add_community(comm)
    # end set_route_targets_config

    def floating_ip_qos_config(self, floating_ips_qos, interface=[]):
        policy = Policy(name='_contrail_policy')
        for floating_ip_key in floating_ips_qos.keys():
            floating_ip_qos = floating_ips_qos[floating_ip_key]
            for qos_policy in [floating_ip_qos['qos_policy'].ingress_policy, floating_ip_qos['qos_policy'].egress_policy]:
                cb = Cb()
                if qos_policy is not None:
                    ipaddress = floating_ip_key.replace('_', '.')
                    if qos_policy['direction'] == 'ingress':
                        class_map = ClassMap(name='_contrail_class_'+qos_policy['direction']+'_'+floating_ip_key)
                        class_map.set_match_way('match-any')
                        ipv4_source = ClassMapMatchIpv4(values=[Value(ipv4_addr=ipaddress)])
                        class_map_match = ClassMapMatch()
                        class_map_match.set_ipv4_source_address(ipv4_source)
                        class_map.set_match(class_map_match)
                    else:
                        class_map = ClassMap(name='_contrail_class_'+qos_policy['direction']+'_'+floating_ip_key)
                        class_map.set_match_way('match-any')
                        ipv4_dest = ClassMapMatchIpv4(values=[Value(ipv4_addr=ipaddress)])
                        class_map_match = ClassMapMatch()
                        class_map_match.set_ipv4_dest_address(ipv4_dest)
                        class_map.set_match(class_map_match)
                    self.config.add_class_map(class_map)

                    # cir:<INTEGER, 512..10000000>
                    # pir:<INTEGER, 1024..10000000>
                    # if cir > 102400 ;cbs  = 12500000 else cbs = cir*1000/8
                    max_bkps = 512 if qos_policy['max_kbps'] < 512 else qos_policy['max_kbps']
                    max_burst_kbps = 1024 if qos_policy['max_burst_kbps'] < 1024 else qos_policy['max_burst_kbps']
                    max_cbs = 12500000 if max_bkps > 102400 else max_bkps*1000/8
                    max_pbs = 12500000 if max_burst_kbps > 102400 else max_burst_kbps*1000/8
                    behavior = Behavior(name='_contrail_behavior_'+qos_policy['direction']+'_'+floating_ip_key)
                    behavior.set_car(Car(cir=max_bkps, pir=max_burst_kbps, cbs=max_cbs, pbs=max_pbs))
                    self.config.add_behavior(behavior)

                    cb.set_class_map(class_map.name)
                    cb.set_behavior(behavior.name)
                    policy.add_cb(cb)

        # has cb ,config floating qos
        if policy.get_cb() is not None:
            self.config.add_policy(policy)

            bind_qos = BindQos()
            bind_qos.set_in(QosIn(qos_in_name=policy.get_name()))
            bind_qos.set_out(QosOut(qos_out_name=policy.get_name()))
            for up_interface in interface:
                uplink_interface = self._find_interface(up_interface)
                if uplink_interface is None:
                    uplink_interface = Interface(name=up_interface)
                    uplink_interface.set_bind(InterfaceBind(qos=bind_qos))
                    self.interfaces.add_interface(uplink_interface)
                elif uplink_interface.bind:
                    uplink_interface.bind.set_qos(bind_qos)
    # end floating ip qos bind.

    # add by guwei replace contrail push_conf
    def push_conf(self, is_delete=False):
        if not self.physical_router:
            return 0
        if is_delete:
            return self.send_conf(is_delete=True)
        if not self.ensure_bgp_config():
            return 0
        self.build_bgp_config()
        vn_dict = self.get_vn_li_map()
        self.physical_router.evaluate_vn_irb_ip_map(set(vn_dict.keys()), 'l2_l3', 'irb', False)
        self.physical_router.evaluate_vn_irb_ip_map(set(vn_dict.keys()), 'l3', 'lo0', True)
        vn_irb_ip_map = self.physical_router.get_vn_irb_ip_map()

        # save nve, mode, up link, ip, vlan to physical router.type is {vnid:XXXXX}
        # get all vn id from vn_dict with physical router

        for vn_id, interfaces in vn_dict.items():
            vn_obj = VirtualNetworkDM.get(vn_id)
            if (vn_obj is None or
                    vn_obj.get_vxlan_vni() is None or
                    vn_obj.vn_network_id is None):
                continue
            export_set = None
            import_set = None
            for ri_id in vn_obj.routing_instances:
                # Find the primary RI by matching the name
                ri_obj = RoutingInstanceDM.get(ri_id)
                if ri_obj is None:
                    continue
                if ri_obj.fq_name[-1] == vn_obj.fq_name[-1]:
                    vrf_name_l2 = DMUtils.make_vrf_name(vn_obj.fq_name[-1],
                                                        vn_obj.vn_network_id, 'l2')
                    vrf_name_l3 = DMUtils.make_vrf_name(vn_obj.fq_name[-1],
                                                        vn_obj.vn_network_id, 'l3')
                    export_set = copy.copy(ri_obj.export_targets)
                    import_set = copy.copy(ri_obj.import_targets)

                    for ri2_id in ri_obj.routing_instances:
                        ri2 = RoutingInstanceDM.get(ri2_id)
                        if ri2 in pnf_ris:
                            first_vrf.append(ri2)
                        if ri2 is None:
                            continue
                        import_set |= ri2.export_targets

                    if vn_obj.get_forwarding_mode() in ['l2', 'l2_l3']:
                        irb_ips = None
                        if vn_obj.get_forwarding_mode() == 'l2_l3':
                            irb_ips = vn_irb_ip_map['irb'].get(vn_id, [])

                    if vn_obj.get_forwarding_mode() in ['l3', 'l2_l3']:
                        interfaces = []
                        lo0_ips = None
                        if vn_obj.get_forwarding_mode() == 'l2_l3':
                            interfaces = [
                                CertusInterface(
                                    'irb.' + str(vn_obj.vn_network_id),
                                    'l3', 0)]
                        else:
                            lo0_ips = vn_irb_ip_map['lo0'].get(vn_id, [])

                        mode =  self.physical_router.get_vn_lr_modes(vn_id)
                        ri_conf = {'ri_l2_name': vrf_name_l2, 'ri_l3_name': vrf_name_l3, 'vn': vn_obj}
                        ri_conf['is_l2_l3'] = (vn_obj.get_forwarding_mode() == 'l2_l3')
                        ri_conf['mode'] = mode
                        ri_conf['import_targets'] = import_set
                        ri_conf['export_targets'] = export_set
                        ri_conf['vni'] = vn_obj.get_vxlan_vni()
                        ri_conf['network_id'] = vn_obj.vn_network_id
                        ri_conf['highest_enapsulation_priority'] = \
                            GlobalVRouterConfigDM.global_encapsulation_priority
                        self.add_routing_instance(ri_conf)

            # build qos config. self.physical router up link.
            # self.floating_ip_qos_config(self.floating_ips_qos, up_interfaces)

        # modify bgp
        self.config_bgp()
        return self.send_conf()

    # config bgp
    def config_bgp(self):
        # if has vrf then add bgp vrf
        if self.l3vpn.hasContent_():
            # TODO: not finish l3dci.
            for vrf in self.l3vpn.vrf:
                self.add_bgp_vrf(vrf.vrfname, self.router.bgp, mode='static')
    # end config bgp

    # all vrf add to bgp vrf is static router
    def add_bgp_vrf(self, vrf_name, bgp_config, mode, prefix=None):
        bgp_vrf = BgpVrf(vrfname=vrf_name)

        vrf_afi_safis = VrfAfiSafis()
        vrf_address_family = VrfAddressFamily(afi_safi_name='bgp-types:ipv4-unicast')
        if mode == 'static':
            vrf_address_family.set_redistribute(Redistribute(routing_protocol='static'))
        # advertise rt-5 route by  type-5 vrf
        elif mode == 'network':
            vrf_address_family.set_network(NetWork(network_prefix=prefix))
        vrf_afi_safis.add_address_family(vrf_address_family)
        bgp_vrf.set_afi_safis(vrf_afi_safis)
        bgp_config.add_vrf(bgp_vrf)
    # end add bgp vrf

    # only dci vrf config ,then config this
    def modify_bgp_default_originate_vrf(self, bgp_config):
        if self.dci_vrf is None and not self.dci_vrf.vrfname:
            return

        # add to bgp default originate vrf
        neis = bgp_config.get_neighbors()
        for nei in neis.get_neighbor():
            afi_safis = nei.get_afi_safis()
            for family in afi_safis.get_address_family():
                if 'l3vpn-ipv4-unicast' in family.afi_safi_name:
                    family.set_defaultoriginatevrf(
                        DefaultOriginateVrf(default_originate_vrf=self.dci_vrf.vrfname))

    # TODO: need modify
    def push_conf_bkp(self, is_delete=False):
        if not self.physical_router:
            return 0
        if is_delete:
            return self.send_conf(is_delete=True)
        if not self.ensure_bgp_config():
            return 0
        self.build_bgp_config()
        vn_dict = self.get_vn_li_map()
        self.physical_router.evaluate_vn_irb_ip_map(set(vn_dict.keys()), 'l2_l3', 'irb', False)
        self.physical_router.evaluate_vn_irb_ip_map(set(vn_dict.keys()), 'l3', 'lo0', True)
        vn_irb_ip_map = self.physical_router.get_vn_irb_ip_map()

        first_vrf = []
        # TODO: flexbng not support pnf logical interface.
        pnfs = self.config_pnf_logical_interface()
        pnf_dict = pnfs[0]
        pnf_ris = pnfs[1]

        for vn_id, interfaces in vn_dict.items():
            vn_obj = VirtualNetworkDM.get(vn_id)
            if (vn_obj is None or
                    vn_obj.get_vxlan_vni() is None or
                    vn_obj.vn_network_id is None):
                continue
            export_set = None
            import_set = None
            for ri_id in vn_obj.routing_instances:
                # Find the primary RI by matching the name
                ri_obj = RoutingInstanceDM.get(ri_id)
                if ri_obj is None:
                    continue
                if ri_obj.fq_name[-1] == vn_obj.fq_name[-1]:
                    vrf_name_l2 = DMUtils.make_vrf_name(vn_obj.fq_name[-1],
                                                        vn_obj.vn_network_id, 'l2')
                    vrf_name_l3 = DMUtils.make_vrf_name(vn_obj.fq_name[-1],
                                                        vn_obj.vn_network_id, 'l3')
                    export_set = copy.copy(ri_obj.export_targets)
                    import_set = copy.copy(ri_obj.import_targets)

                    for ri2_id in ri_obj.routing_instances:
                        ri2 = RoutingInstanceDM.get(ri2_id)
                        if ri2 in pnf_ris:
                            first_vrf.append(ri2)
                        if ri2 is None:
                            continue
                        import_set |= ri2.export_targets

                    if vn_obj.get_forwarding_mode() in ['l2', 'l2_l3']:
                        irb_ips = None
                        if vn_obj.get_forwarding_mode() == 'l2_l3':
                            irb_ips = vn_irb_ip_map['irb'].get(vn_id, [])

                        ri_conf = {'ri_name': vrf_name_l2, 'vn': vn_obj}
                        ri_conf['is_l2'] = True
                        ri_conf['is_l2_l3'] = (vn_obj.get_forwarding_mode() == 'l2_l3')
                        ri_conf['import_targets'] = import_set
                        ri_conf['export_targets'] = export_set
                        ri_conf['prefixes'] = vn_obj.get_prefixes()
                        ri_conf['gateways'] = irb_ips
                        ri_conf['router_external'] = vn_obj.router_external
                        ri_conf['interfaces'] = interfaces
                        ri_conf['vni'] = vn_obj.get_vxlan_vni()
                        ri_conf['network_id'] = vn_obj.vn_network_id
                        ri_conf['highest_enapsulation_priority'] = \
                            GlobalVRouterConfigDM.global_encapsulation_priority
                        self.add_routing_instance(ri_conf)

                    if vn_obj.get_forwarding_mode() in ['l3', 'l2_l3']:
                        interfaces = []
                        lo0_ips = None
                        if vn_obj.get_forwarding_mode() == 'l2_l3':
                            interfaces = [
                                JunosInterface(
                                    'irb.' + str(vn_obj.vn_network_id),
                                    'l3', 0)]
                        else:
                            lo0_ips = vn_irb_ip_map['lo0'].get(vn_id, [])
                        ri_conf = {'ri_name': vrf_name_l3, 'vn': vn_obj}
                        ri_conf['is_l2_l3'] = (vn_obj.get_forwarding_mode() == 'l2_l3')
                        ri_conf['import_targets'] = import_set
                        ri_conf['export_targets'] = export_set
                        ri_conf['prefixes'] = vn_obj.get_prefixes()
                        ri_conf['router_external'] = vn_obj.router_external
                        ri_conf['interfaces'] = interfaces
                        ri_conf['gateways'] = lo0_ips
                        ri_conf['network_id'] = vn_obj.vn_network_id
                        self.add_routing_instance(ri_conf)

                    # do something about bgp config, because bgp config is flexible
                    # config bgp and neighbor base external l2 l2_l3
                    self.config_bgp_config(self.bgp, ri_conf['is_l2'], ri_conf['is_l2_l3'], ri_conf['router_external'],
                                           ri_conf['ri_name'], self.bgp_remote_neighbours)
                    if self._check_l2_dci(self.bgp_remote_neighbours) and ri_conf["is_l2"]:
                        import_target |= ri['import_targets']
                        export_target |= ri['export_targets']

                    break

            # config bgp and vrf by dci
            if self._check_l2_dci(self.bgp_remote_neighbours) and \
                    self.db_l2_dci.vn.read_obj(self.db_l2_dci.vn.uuid)['fq_name'][-1] in ri_conf['ri_name']:
                self.config_bgp_l2_dci(self.bgp_remote_neighbours, bgp_config, self.bgp_params)

            if self._check_l3_dci(self.bgp_remote_neighbours):
                for vn_uuid in self.db_l3_dci.virtual_network:
                    for vn in self.db_l3_dci.vn:
                        for ri_key in self.routing_instances.keys():
                            ri = self.routing_instances.get(ri_key)
                            if vn.read_obj(vn_uuid)['fq_name'][-1] in ri_conf['ri_name'] and not ri_conf['is_l2']:
                                self.config_bgp_l3_dci(self.bgp_remote_neighbours, bgp_config, ri_conf, self.bgp_params)

            # flexbng not support junos service ports.
            if (export_set is not None and
                    self.physical_router.is_junos_service_ports_enabled() and
                    len(vn_obj.instance_ip_map) > 0):
                service_port_ids = DMUtils.get_service_ports(vn_obj.vn_network_id)
                if self.physical_router.is_service_port_id_valid(service_port_ids[0]) == False:
                    self._logger.error("DM can't allocate service interfaces for "
                                       "(vn, vn-id)=(%s,%s)" % (
                                           vn_obj.fq_name,
                                           vn_obj.vn_network_id))
                else:
                    vrf_name = DMUtils.make_vrf_name(vn_obj.fq_name[-1],
                                                     vn_obj.vn_network_id, 'l3', True)
                    interfaces = []
                    service_ports = self.physical_router.junos_service_ports.get(
                        'service_port')
                    interfaces.append(
                        JunosInterface(
                            service_ports[0] + "." + str(service_port_ids[0]),
                            'l3', 0))
                    interfaces.append(
                        JunosInterface(
                            service_ports[0] + "." + str(service_port_ids[1]),
                            'l3', 0))
                    ri_conf = {'ri_name': vrf_name, 'vn': vn_obj}
                    ri_conf['import_targets'] = import_set
                    ri_conf['interfaces'] = interfaces
                    ri_conf['fip_map'] = vn_obj.instance_ip_map
                    ri_conf['network_id'] = vn_obj.vn_network_id
                    ri_conf['restrict_proxy_arp'] = vn_obj.router_external
                    self.add_routing_instance(ri_conf)
        # Add PNF ri configuration
        self.add_pnf_vrfs(first_vrf, pnf_dict, pnf_ris)
        # self.set_as_config()
        # self.set_route_targets_config()
        # self.set_bgp_group_config()
        self.set_bgp_router_config()
        return self.send_conf()
    # end push_conf

    # params: policy is list
    def compare_policy(self, bng_policy, new_policy):
        if bng_policy is []:
            return

        for policy in bng_policy:
            do = False
            if '_contrail_' in policy.name:
                for _policy in new_policy:
                        if policy.name == _policy.name:
                            if policy.__eq__(_policy):
                                new_policy.remove(_policy)
                            else:
                                _policy.set_operation('replace')
                            do = True
                            break
                if not do:
                    policy.set_operation('delete')
                    self.compare_config.add_policy(policy)
    # params: bng_behavior is list

    def compare_behavior(self, bng_behavior, new_behavior):
        if bng_behavior is []:
            return

        for behavior in bng_behavior:
            do = False
            if '_contrail_' in behavior.name:
                for _behavior in new_behavior:
                        if behavior.name == _behavior.name:
                            if behavior.__eq__(_behavior):
                                new_behavior.remove(_behavior)
                            else:
                                _behavior.set_operation('replace')
                            do = True
                            break
                if not do:
                    behavior.set_operation('delete')
                    self.compare_config.add_behavior(behavior)
    # params: bng_class_map is list

    def compare_class_map(self, bng_class_map, new_class_map):
        if bng_class_map is []:
            return

        for class_map in bng_class_map:
            do = False
            if '_contrail_' in class_map.name:
                for _class_map in new_class_map:
                        if class_map.name == _class_map.name:
                            if class_map.__eq__(_class_map):
                                new_class_map.remove(_class_map)
                            else:
                                _class_map.set_operation('replace')
                            do = True
                            break
                if not do:
                    class_map.set_operation('delete')
                    self.compare_config.add_class_map(class_map)
    # service_instance

    def compare_service_instances(self, bng_service_instance, new_service_instance):
        if bng_service_instance is None:
            return

        del_service_instance = ServiceInstance()
        for instance in bng_service_instance.get_instance():
            do = False
            if new_service_instance is not None:
                for _instance in new_service_instance.get_instance():
                    if instance.__eq__(_instance):
                        new_service_instance.delete_instance(_instance)
                        do = True
                        break
                    elif instance.instance_id == _instance.instance_id:
                        _instance.set_operation('replace')
                        do = True
                        break
            if not do:
                del_service_instance.add_instance(Instance(instance_id=instance.instance_id, operation='delete'))
        if del_service_instance.hasContent_():
            self.compare_config.set_service_instance(del_service_instance)
    # compare_service_instances

    def compare_l3vpn_config(self, bng_l3vpn, new_l3vpn):
        if bng_l3vpn is None:
            return

        del_l3vpn = L3vpn()
        for vrf in bng_l3vpn.get_vrf():
            do = False
            if '_contrail_' in vrf.get_vrfname():
                if new_l3vpn.get_vrf() is not None:
                    for _vrf in new_l3vpn.get_vrf():
                        if vrf.vrfname == _vrf.vrfname:
                            _vrf.set_vrf_index(vrf.vrf_index)
                            if vrf.__eq__(_vrf):
                                new_l3vpn.delete_vrf(_vrf)
                            else:
                                _vrf.set_operation('replace')
                            do = True
                            break
                if not do:
                    del_vrf = Vrf(vrfname=vrf.vrfname, vrf_index=vrf.vrf_index, operation='delete')
                    del_l3vpn.add_vrf(del_vrf)
        if del_l3vpn.hasContent_():
            self.compare_config.set_l3vpn(del_l3vpn)
    # compare_l3vpn_config

    def compare_l2sm_vfi_config(self, bng_vfi, new_vfi):
        if bng_vfi is None:
            return

        del_l2sm_vfi = L2smVfi()
        for vfi in bng_vfi.get_vfi():
            do = False
            if '_contrail_' in vfi.get_vfi_name():
                if new_vfi.get_vfi() is not None:
                    for _vfi in new_vfi.get_vfi():
                        if vfi.vfi_name == _vfi.vfi_name:
                            _vfi.set_vfi_idx(vfi.vfi_idx)
                            if vfi.__eq__(_vfi):
                                new_vfi.delete_vfi(_vfi)
                            else:
                                _vfi.set_operation('replace')
                                # need clear gateway or can not delete irb interface
                                if vfi.gateway is not None:
                                    vfi.set_gateway(None)
                                    vfi.set_operation('replace')
                                    del_l2sm_vfi.add_vfi(vfi)
                                # need clear xconnect_vrf if new_vfi has no xconnect_vrf
                                if vfi.service.type_ == 'evpn' and \
                                        vfi.service.evpn.xconnect_vrf is not None and \
                                        _vfi.service.evpn.xconnect_vrf is None:
                                    vfi.service.evpn.set_xconnect_vrf(None)
                                    vfi.set_operation('replace')
                                    del_l2sm_vfi.add_vfi(vfi)
                            do = True
                            break
                if not do:
                    del_vfi = Vfi(vfi_name=vfi.vfi_name, vfi_index=vfi.vfi_idx, operation='delete')
                    del_l2sm_vfi.add_vfi(del_vfi)
        if del_l2sm_vfi.hasContent_():
            self.compare_config.set_l2sm_vfi(del_l2sm_vfi)
    # compare_l2sm_vfi_config

    def _get_defaultoriginatevrf(self, address_family, afi_safi_name='bgp-types:l3vpn-ipv4-unicast'):
        for family in address_family:
            if family.afi_safi_name == afi_safi_name:
                return family.defaultoriginatevrf
        return None

    def _set_defaultoriginatevrf(self, address_family, defaultoriginatevrf, afi_safi_name='bgp-types:l3vpn-ipv4-unicast'):
        for family in address_family:
            if family.afi_safi_name == afi_safi_name:
                family.defaultoriginatevrf = defaultoriginatevrf
    # clear bgp vrf and default-originate-vrf

    def _bgp_clear_bgp_vrf(self, old_bgp, new_bgp):
        if new_bgp.vrf is None:
            old_bgp.set_vrf([])
        elif old_bgp.vrf is not None and old_bgp.vrf.__ne__(new_bgp.vrf):
            old_bgp.set_vrf([])

        del_neis = []
        if old_bgp.neighbors and old_bgp.neighbors.__ne__(new_bgp.neighbors):
            for old_nei in old_bgp.neighbors.get_neighbor():
                search = False
                for new_nei in new_bgp.neighbors.get_neighbor():
                    # clear default-originate-vrf, very deep
                    if old_nei.neighbor_address == new_nei.neighbor_address:
                        search = True
                        old_dov = self._get_defaultoriginatevrf(old_nei.afi_safis.address_family)
                        new_dov = self._get_defaultoriginatevrf(new_nei.afi_safis.address_family)
                        if old_dov != new_dov:
                            self._set_defaultoriginatevrf(old_nei.afi_safis.address_family, None)

                if not search:
                    del_neis.append(old_nei)

        for del_nei in del_neis:
            old_bgp.neighbors.delete_neighbor(del_nei)
    # bgp clear vrf

    # compare router bgp ,static.
    def compare_router_config(self, bng_router, new_router):
        if bng_router is None:
            return

        del_router = Router()
        # if local_as has change then delete .
        # if bng_bgp == new_bgp then nothing to do
        # or replace flexbng bgp
        if bng_router.get_bgp() is not None and new_router.get_bgp() is not None:
            if bng_router.get_bgp().local_as != new_router.get_bgp().local_as:
                del_bgp = Bgp(local_as=bng_router.get_bgp().local_as, operation='delete')
                del_router.set_bgp(del_bgp)
            elif bng_router.get_bgp().__ne__(new_router.get_bgp()):
                new_router.get_bgp().set_operation('replace')
                # if bgp has vrf or something ,then first replace
                self._bgp_clear_bgp_vrf(bng_router.get_bgp(), new_router.get_bgp())
                bng_router.get_bgp().set_operation('replace')
                del_router.set_bgp(bng_router.get_bgp())
            else:
                new_router.set_bgp(None)
        elif bng_router.get_bgp() is not None and new_router.get_bgp() is None:
            del_bgp = Bgp(local_as=bng_router.get_bgp().local_as, operation='delete')
            del_router.set_bgp(del_bgp)

        # delete route static by vrf. because can not delete vrf with exited route static.
        try:
            route_static = bng_router.get_static().get_ip().get_route()
        except:
            route_static = None

        if route_static is not None and route_static.get_vrf() is not None:
            vrf_statics = route_static.get_vrf()
            static_ip_route = StaticIpRoute()
            for vrf_static in vrf_statics:
                vrf_name = vrf_static.get_vrfname()
                if '_contrail_' in vrf_name:
                    if self.l3vpn is None:
                        vrf_static.set_operation('remove')
                        static_ip_route.add_vrf(vrf_static)
                    elif vrf_name not in [vrf.vrfname for vrf in self.l3vpn.get_vrf()]:
                        vrf_static.set_operation('remove')
                        static_ip_route.add_vrf(vrf_static)

            if static_ip_route.hasContent_():
                del_route_static = Static(ip=StaticIp(route=static_ip_route))
                del_router.set_static(del_route_static)
        if del_router.hasContent_():
            self.compare_config.set_router(del_router)

    # uplink interfaces is very special.
    # delete bind vrf if necessary
    # keep ipv4 and dot1q.
    def _compare_uplink_interface(self, bng_uplink, new_uplink):
        bind_vrf_name = None
        vrf_name = None

        if bng_uplink.get_bind() and bng_uplink.bind.get_vrf():
            bind_vrf_name = bng_uplink.bind.vrf.vrf_name

        if new_uplink.get_bind() and new_uplink.bind.get_vrf():
            vrf_name = new_uplink.bind.vrf.vrf_name

        if bind_vrf_name is None:
            pass
        elif vrf_name is None:
            bng_uplink.bind.set_vrf(None)
        elif vrf_name != bind_vrf_name:
            bng_uplink.set_operation('replace')
            bng_uplink.bind.set_vrf(None)

        # cp ipv4 and dot1q
        new_uplink.set_ipv4(bng_uplink.get_ipv4())
        new_uplink.set_dot1q(bng_uplink.get_dot1q())

    # compare interface,update or new or delete.
    def compare_interfaces_config(self, bng_interfaces, new_interfaces):
        if new_interfaces is None:
            return
        del_interfaces = self.compare_config.get_interfaces() or Interfaces()
        for del_interface in bng_interfaces.get_interface():
            if del_interface.get_description() == '_contrail_config':
                do = False
                for interface in new_interfaces.get_interface():
                    if del_interface.name == interface.name:
                        if del_interface.__eq__(interface):
                            new_interfaces.delete_interface(interface)
                        elif self.uplink_interface == del_interface.name:
                            self._compare_uplink_interface(del_interface, interface)
                            if del_interface.__eq__(interface):
                                new_interfaces.delete_interface(interface)
                            else:
                                interface.set_operation('replace')
                                del_interfaces.add_interface(del_interface)
                        else:
                            if not interface.ipv4 and del_interface.ipv4:
                                interface.set_ipv4(del_interface.ipv4)
                            interface.set_operation('replace')
                        do = True
                        break

                if not do:
                    # if interface is physical, then just clear all config
                    if '10gei' in del_interface.name:
                        del_interfaces.add_interface(Interface(name=del_interface.name, operation='replace'))
                    else:
                        del_interface.set_operation('delete')
                        del_interfaces.add_interface(del_interface)

        if del_interfaces.hasContent_():
            self.compare_config.set_interfaces(del_interfaces)
    # end compare interfaces

    def compare_system_mac(self, bng_system_mac, new_system_mac):
        if bng_system_mac is None:
            return

        if new_system_mac is None or bng_system_mac.__ne__(new_system_mac):
            bng_system_mac.set_operation('delete')
            self.compare_config.set_system_mac(bng_system_mac)

    # compare config between flexbng and flexvisor,and just send diff netconf to flexbng
    # to avoided flexbng broken.
    def compare_netconf_config(self):
        bng_data = data()

        self.compare_config = data()
        bng_interfaces_xml = self.device_get_config(self.serialize(Interfaces(),obj_name='interfaces'))
        if bng_interfaces_xml is not None:
            bng_data.build(bng_interfaces_xml)
            interfaces = bng_data.get_interfaces()
            self.compare_interfaces_config(interfaces, self.interfaces)

        bng_router_xml = self.device_get_config(self.serialize(Router(), obj_name='router'))
        if bng_router_xml is not None:
            bng_data.build(bng_router_xml)
            router = bng_data.get_router()
            self.compare_router_config(router, self.router)

        bng_l2smvfi_xml = self.device_get_config(self.serialize(L2smVfi(), obj_name='l2sm-vfi'))
        if bng_l2smvfi_xml is not None:
            bng_data.build(bng_l2smvfi_xml)
            l2smvfi = bng_data.get_l2sm_vfi()
            self.compare_l2sm_vfi_config(l2smvfi, self.l2smvfi)

        bng_l3vpn_xml = self.device_get_config(self.serialize(L3vpn(), obj_name='l3vpn'))
        if bng_l3vpn_xml is not None:
            bng_data.build(bng_l3vpn_xml)
            l3vpn = bng_data.get_l3vpn()
            self.compare_l3vpn_config(l3vpn, self.l3vpn)

        bng_service_instances_xml = self.device_get_config(self.serialize(ServiceInstance(),obj_name='service-instance'))
        if bng_service_instances_xml is not None:
            bng_data.build(bng_service_instances_xml)
            service_instances = bng_data.get_service_instance()
            self.compare_service_instances(service_instances, self.service_instances)

        bng_class_maps_xml = self.device_get_config(self.serialize(ClassMap(),obj_name='class_map'))
        if bng_class_maps_xml is not None:
            bng_data.build(bng_class_maps_xml)
            class_maps = bng_data.get_class_map()
            self.compare_class_map(class_maps, self.config.get_class_map())

        bng_behaviors_xml = self.device_get_config(self.serialize(Behavior(), obj_name='behavior'))
        if bng_behaviors_xml is not None:
            bng_data.build(bng_behaviors_xml)
            behaviors = bng_data.get_behavior()
            self.compare_behavior(behaviors, self.config.get_behavior())

        bng_policy_xml = self.device_get_config(self.serialize(Policy(), obj_name='policy'))
        if bng_policy_xml is not None:
            bng_data.build(bng_policy_xml)
            policys = bng_data.get_policy()
            self.compare_policy(policys, self.config.get_policy())

        bng_system_mac_xml = self.device_get_config(self.serialize(SystemMac(), obj_name='system-mac'))
        if bng_system_mac_xml is not None:
            bng_data.build(bng_system_mac_xml)
            system_mac = bng_data.get_system_mac()
            self.compare_system_mac(system_mac, self.config.get_system_mac())
    # end compare netconf config

# end PhycalRouterConfig
