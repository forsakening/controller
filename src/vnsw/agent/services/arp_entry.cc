/*
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */

#include "base/os.h"
#include "services/arp_proto.h"
#include "services/services_sandesh.h"
#include "services/services_init.h"
#include "oper/route_common.h"

ArpEntry::ArpEntry(boost::asio::io_service &io, ArpHandler *handler,
                   ArpKey &key, const VrfEntry *vrf, State state,
                   const Interface *itf)
    : io_(io), key_(key), nh_vrf_(vrf), state_(state), retry_count_(0),
      handler_(handler), arp_timer_(NULL), interface_(itf) {
    if (!IsDerived()) {
        arp_timer_ = TimerManager::CreateTimer(io, "Arp Entry timer",
                TaskScheduler::GetInstance()->GetTaskId("Agent::Services"),
                PktHandler::ARP);
    }

    //zx-ipv6
    icmpv6_reuse = false;
}

ArpEntry::ArpEntry(boost::asio::io_service &io, ArpHandler *handler, Icmpv6Handler *icmpv6_handler,
             ArpKey &key, const VrfEntry *vrf, State state,
              const Interface *itf)
    : io_(io), key_(key), nh_vrf_(vrf), state_(state), retry_count_(0),
      handler_(handler), icmpv6_handler_(icmpv6_handler), arp_timer_(NULL), interface_(itf) {
    if (!IsDerived()) {
        arp_timer_ = TimerManager::CreateTimer(io, "Arp Entry timer",
                TaskScheduler::GetInstance()->GetTaskId("Agent::Services"),
                PktHandler::ARP);
    }

    //zx-ipv6
    icmpv6_reuse = true;
}

ArpEntry::~ArpEntry() {
    if (!IsDerived()) {
        arp_timer_->Cancel();
        TimerManager::DeleteTimer(arp_timer_);
    }
    handler_.reset(NULL);
}

void ArpEntry::HandleDerivedArpRequest() {
    ArpProto *arp_proto = handler_->agent()->GetArpProto();
    //Add ArpRoute for Derived entry
    AddArpRoute(IsResolved());

    ArpKey key(key_.ip, nh_vrf_);
    ArpEntry *entry = arp_proto->FindArpEntry(key);
    if (entry) {
        entry->HandleArpRequest();
    } else {
        entry = new ArpEntry(io_, handler_.get(), key, nh_vrf_, ArpEntry::INITING,
                             interface_.get());
        if (arp_proto->AddArpEntry(entry) == false) {
            delete entry;
            return;
        }
        entry->HandleArpRequest();
    }
}

bool ArpEntry::HandleArpRequest() {
    if (IsDerived()) {
        HandleDerivedArpRequest();
        return true;
    }
    if (IsResolved())
        AddArpRoute(true);
    else {
        AddArpRoute(false);
        if (state_ & ArpEntry::INITING) {
            state_ = ArpEntry::RESOLVING;
            SendArpRequest();
        }
    }
    return true;
}

void ArpEntry::HandleArpReply(const MacAddress &mac) {

    if (IsDerived()) {
        /* We don't expect ARP replies in derived Vrf */
        return;
    }
    if ((state_ == ArpEntry::RESOLVING) || (state_ == ArpEntry::ACTIVE) ||
        (state_ == ArpEntry::INITING) || (state_ == ArpEntry::RERESOLVING)) {
        ArpProto *arp_proto = handler_->agent()->GetArpProto();
        arp_timer_->Cancel();
        retry_count_ = 0;
        mac_address_ = mac;
        if (state_ == ArpEntry::RESOLVING) {
            arp_proto->IncrementStatsResolved();
            arp_proto->IncrementStatsResolved(interface_->id());
        }
        state_ = ArpEntry::ACTIVE;
        StartTimer(arp_proto->aging_timeout(), ArpProto::AGING_TIMER_EXPIRED);
        AddArpRoute(true);
    }
}

bool ArpEntry::RetryExpiry() {
    if (state_ & ArpEntry::ACTIVE)
        return true;
    ArpProto *arp_proto = handler_->agent()->GetArpProto();
    if (retry_count_ < arp_proto->max_retries()) {
        retry_count_++;
        SendArpRequest();
    } else {
        IpAddress ip(key_.ip);
        ARP_TRACE(Trace, "Retry exceeded", ip.to_string(), 
                  key_.vrf->GetName(), "");
        arp_proto->IncrementStatsMaxRetries();

        // if Arp NH is not present, let the entry be deleted
        if (DeleteArpRoute())
            return false;

        // keep retrying till Arp NH is deleted
        retry_count_ = 0;
        SendArpRequest();
    }
    return true;
}

bool ArpEntry::AgingExpiry() {
    IpAddress ip(key_.ip);
    const string& vrf_name = key_.vrf->GetName();
    ArpNHKey nh_key(vrf_name, ip, false);
    ArpNH *arp_nh = static_cast<ArpNH *>(handler_->agent()->nexthop_table()->
                                         FindActiveEntry(&nh_key));
    if (!arp_nh) {
        // do not re-resolve if Arp NH doesnt exist
        return false;
    }
    state_ = ArpEntry::RERESOLVING;
    SendArpRequest();
    return true;
}

void ArpEntry::SendGratuitousArp() {
    Agent *agent = handler_->agent();
    ArpProto *arp_proto = agent->GetArpProto();
    if (agent->router_id_configured()) {
        if (interface_->type() == Interface::VM_INTERFACE) {
            const VmInterface *vmi =
                static_cast<const VmInterface *>(interface_.get());
            MacAddress smac = vmi->GetVifMac(agent);
            if (key_.vrf && key_.vrf->vn()) {
                IpAddress gw_ip = key_.vrf->vn()->GetGatewayFromIpam
                    (IpAddress(key_.ip));
                IpAddress dns_ip = key_.vrf->vn()->GetDnsFromIpam
                    (IpAddress(key_.ip));
                if (!gw_ip.is_unspecified() && gw_ip.is_v4())  {
                    handler_->SendArp(ARPOP_REQUEST, smac,
                                      gw_ip.to_v4().to_ulong(),
                                      smac, vmi->vm_mac(), gw_ip.to_v4().to_ulong(),
                                      vmi->id(), key_.vrf->vrf_id());
                }
                if (!dns_ip.is_unspecified() && dns_ip.is_v4() &&
                    dns_ip != gw_ip)  {
                    handler_->SendArp(ARPOP_REQUEST, smac,
                                      dns_ip.to_v4().to_ulong(),
                                      smac, vmi->vm_mac(), dns_ip.to_v4().to_ulong(),
                                      vmi->id(), key_.vrf->vrf_id());
                }
            }
        } else {
            handler_->SendArp(ARPOP_REQUEST, arp_proto->ip_fabric_interface_mac(),
                              agent->router_id().to_ulong(), MacAddress(),
                              MacAddress::BroadcastMac(), agent->router_id().to_ulong(),
                              arp_proto->ip_fabric_interface_index(),
                              key_.vrf->vrf_id());
        }

    }

    retry_count_++;
    StartTimer(ArpProto::kGratRetryTimeout, ArpProto::GRATUITOUS_TIMER_EXPIRED);
}

bool ArpEntry::IsResolved() {
    return (state_ & (ArpEntry::ACTIVE | ArpEntry::RERESOLVING));
}

bool ArpEntry::IsDerived() {
    if (key_.vrf != nh_vrf_) {
        return true;
    }
    return false;
}

void ArpEntry::StartTimer(uint32_t timeout, uint32_t mtype) {
    arp_timer_->Cancel();
    arp_timer_->Start(timeout, boost::bind(&ArpProto::TimerExpiry,
                                           handler_->agent()->GetArpProto(),
                                           key_, mtype, interface_.get()));
}

void ArpEntry::SendArpRequest() {
    assert(!IsDerived());

    //zx-ipv6 
    //Icmpv6 ND neighbor solicitation reuse this method
    Agent *agent = handler_->agent();
    ArpProto *arp_proto = agent->GetArpProto();
    uint32_t vrf_id = VrfEntry::kInvalidIndex;
    uint32_t intf_id = arp_proto->ip_fabric_interface_index();//send it from fabirc port
    IpAddress ip;
    MacAddress smac;
    if (interface_->type() == Interface::VM_INTERFACE) {
        const VmInterface *vmi =
            static_cast<const VmInterface *>(interface_.get());
        ip = vmi->GetServiceIp(IpAddress(key_.ip));
        if (vmi->vmi_type() == VmInterface::VHOST) {
            if (icmpv6_reuse)
                ip = agent->v6router_id();
            else
                ip = agent->router_id();
        }
        vrf_id = nh_vrf_->vrf_id();
        if (vmi->parent()) {
            intf_id = vmi->parent()->id();
        }
        smac = vmi->GetVifMac(agent);
    } else {
        if (icmpv6_reuse)
            ip = agent->v6router_id();
        else
            ip = agent->router_id();
        
        VrfEntry *vrf =
            agent->vrf_table()->FindVrfFromName(agent->fabric_vrf_name());
        if (vrf) {
            vrf_id = vrf->vrf_id();
        }
        smac = interface_->mac();
    }

    if (vrf_id != VrfEntry::kInvalidIndex) {
        if (icmpv6_reuse)
            icmpv6_handler_->SendNeighborSolicit(ip.to_v6(), key_.ip.to_v6(), intf_id, vrf_id);
        else
            handler_->SendArp(ARPOP_REQUEST, smac, ip.to_v4().to_ulong(),
                          MacAddress(), MacAddress::BroadcastMac(), key_.ip.to_v4().to_ulong(), intf_id, vrf_id);
    }

    StartTimer(arp_proto->retry_timeout(), ArpProto::RETRY_TIMER_EXPIRED);
}

void ArpEntry::AddArpRoute(bool resolved) {
    if (key_.vrf->GetName() == handler_->agent()->linklocal_vrf_name()) {
        // Do not squash existing route entry.
        // should be smarter and not replace an existing route.
        return;
    }

    IpAddress ip(key_.ip);
    const string& vrf_name = key_.vrf->GetName();
    ArpNHKey nh_key(nh_vrf_->GetName(), ip, false);
    ArpNH *arp_nh = static_cast<ArpNH *>(handler_->agent()->nexthop_table()->
                                         FindActiveEntry(&nh_key));

    MacAddress mac = mac_address();
    if (arp_nh && arp_nh->GetResolveState() &&
        mac.CompareTo(arp_nh->GetMac()) == 0) {
        // MAC address unchanged, ignore
        if (!IsDerived()) {
            return;
        } else {
            /* Return if the route is already existing */
            InetUnicastRouteKey *rt_key = new InetUnicastRouteKey(
                    handler_->agent()->local_peer(), vrf_name, ip, 32); 
            AgentRoute *entry = key_.vrf->GetInet4UnicastRouteTable()->
                FindActiveEntry(rt_key);
            delete rt_key;
            if (entry) {
                return;
            }
            resolved = true;
        }
    }

    ARP_TRACE(Trace, "Add", ip.to_string(), vrf_name, mac.ToString());
    AgentRoute *entry;
    if (ip.is_v4())
        entry = key_.vrf->GetInet4UnicastRouteTable()->FindLPM(ip);
    else
        entry = key_.vrf->GetInet6UnicastRouteTable()->FindLPM(ip);
    
    bool policy = false;
    SecurityGroupList sg;
    TagList tag;
    VnListType vn_list;
    if (entry) {
        policy = entry->GetActiveNextHop()->PolicyEnabled();
        sg = entry->GetActivePath()->sg_list();
        tag = entry->GetActivePath()->tag_list();
        vn_list = entry->GetActivePath()->dest_vn_list();
    }

    const Interface *itf = handler_->agent()->GetArpProto()->ip_fabric_interface();
    if (interface_->type() == Interface::VM_INTERFACE) {
        const VmInterface *vintf =
            static_cast<const VmInterface *>(interface_.get());
        if (vintf->vmi_type() == VmInterface::VHOST) {
            itf = vintf->parent();
        }
    }

    uint8_t plen = 32; 
    if (ip.is_v6())
        plen = 128;

    //zx-ipv6 TODO ipv4 and v6 now use one fabric_inet4_unicast_table
    handler_->agent()->fabric_inet4_unicast_table()->ArpRoute(
                       DBRequest::DB_ENTRY_ADD_CHANGE, vrf_name, ip, mac,
                       nh_vrf_->GetName(), *itf, resolved, plen, policy,
                       vn_list, sg, tag);
}

bool ArpEntry::DeleteArpRoute() {
    if (key_.vrf->GetName() == handler_->agent()->linklocal_vrf_name()) {
        return true;
    }

    IpAddress ip(key_.ip);
    const string& vrf_name = key_.vrf->GetName();
    ArpNHKey nh_key(nh_vrf_->GetName(), ip, false);
    ArpNH *arp_nh = static_cast<ArpNH *>(handler_->agent()->nexthop_table()->
                                         FindActiveEntry(&nh_key));
    if (!arp_nh)
        return true;

    MacAddress mac = mac_address();
    ARP_TRACE(Trace, "Delete", ip.to_string(), vrf_name, mac.ToString());
    if (IsDerived()) {
        //Just enqueue a delete, no need to mark nexthop invalid
        InetUnicastAgentRouteTable::Delete(handler_->agent()->local_peer(),
                                           vrf_name, ip, 32);
        return true;
    }

    uint8_t plen = 32; 
    if (ip.is_v6())
        plen = 128;

    //zx-ipv6 TODO ipv4 and v6 now use one fabric_inet4_unicast_table
    handler_->agent()->fabric_inet4_unicast_table()->ArpRoute(
                       DBRequest::DB_ENTRY_DELETE, vrf_name, ip, mac, nh_vrf_->GetName(),
                       *interface_, false, plen, false, Agent::NullStringList(),
                       SecurityGroupList(), TagList());
    return false;
}

void ArpEntry::Resync(bool policy, const VnListType &vnlist,
                      const SecurityGroupList &sg,
                      const TagList &tag) {
    IpAddress ip(key_.ip);

    uint8_t plen = 32; 
    if (ip.is_v6())
        plen = 128;

    //zx-ipv6 TODO ipv4 and v6 now use one fabric_inet4_unicast_table
    handler_->agent()->fabric_inet4_unicast_table()->ArpRoute(
                       DBRequest::DB_ENTRY_ADD_CHANGE, key_.vrf->GetName(), ip,
                       mac_address_, nh_vrf_->GetName(), *interface_, IsResolved(),
                       plen, policy, vnlist, sg, tag);
}
