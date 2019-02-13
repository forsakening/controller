/*
 * Copyright (c) 2014 Juniper Networks, Inc. All rights reserved.
 */

#ifndef vnsw_agent_oper_dhcp_options_h_
#define vnsw_agent_oper_dhcp_options_h_

#include <vnc_cfg_types.h>

namespace autogen {
    struct DhcpOptionType;
    struct RouteType;
}

// DHCP options coming from config
class OperDhcpOptions {
public:
    typedef std::vector<autogen::DhcpOptionType> DhcpOptionsList;
    typedef std::vector<autogen::RouteType> HostOptionsList;

    struct HostRoute {
        IpAddress prefix_;
        uint32_t plen_;
        IpAddress gw_;

        HostRoute() : prefix_(), plen_(0), gw_() {}
        bool operator<(const HostRoute &rhs) const {
            if (prefix_ != rhs.prefix_)
                return prefix_ < rhs.prefix_;
            if (plen_ != rhs.plen_)
                return plen_ < rhs.plen_;
            return gw_ < rhs.gw_;
        }
        bool operator==(const HostRoute &rhs) const {
            return prefix_ == rhs.prefix_ && plen_ == rhs.plen_ &&
                   gw_ == rhs.gw_;
        }
        std::string ToString() const { 
            char len[128];
            snprintf(len, sizeof(len), "%u", plen_);
            return prefix_.to_string() + "/" + std::string(len) +
                   " -> " + gw_.to_string();
        }
    };

    OperDhcpOptions() {}
    OperDhcpOptions(const OperDhcpOptions &options) {
        dhcp_options_ = options.dhcp_options_;
        host_routes_ = options.host_routes_;
    }
    virtual ~OperDhcpOptions() {}

    const DhcpOptionsList &dhcp_options() const { return dhcp_options_; }
    const std::vector<HostRoute> &host_routes() const { return host_routes_; }
    void set_options(const DhcpOptionsList &options) { dhcp_options_ = options; }
    void set_host_routes(const HostOptionsList &host_routes) {
        host_routes_.clear();
        update_host_routes(host_routes);
    }
    void update_host_routes(const HostOptionsList &host_routes) {
        host_routes_.clear();
        for (unsigned int i = 0; i < host_routes.size(); ++i) {
            HostRoute host_route;
            if (string::npos != host_routes[i].prefix.find("."))
            {
                int        _len;
                Ip4Address v4addr;
            boost::system::error_code ec = Ip4PrefixParse(host_routes[i].prefix,
                                                              &v4addr,
                                                              &_len);
                if (ec || _len > 32) {
                continue;
            }

                host_route.prefix_ = v4addr;
                host_route.plen_   = _len;
            host_route.gw_ = Ip4Address::from_string(host_routes[i].next_hop, ec);
            if (ec) {
                host_route.gw_ = Ip4Address();
            }
            }
            else if (string::npos != host_routes[i].prefix.find(":"))
            {
                int        _len;
                Ip6Address v6addr;
                boost::system::error_code ec = Inet6PrefixParse(host_routes[i].prefix,
                                                                &v6addr,
                                                                &_len);
                if (ec || _len > 128) {
                    continue;
                }

                host_route.prefix_ = v6addr;
                host_route.plen_   = _len;
                host_route.gw_ = Ip6Address::from_string(host_routes[i].next_hop, ec);
                if (ec) {
                    host_route.gw_ = Ip6Address();
                }
            }
            else
                continue;
            
            host_routes_.push_back(host_route);
        }
    }

    bool are_dhcp_options_set() const {
        return dhcp_options_.size() > 0;
    }
    bool are_host_routes_set() const {
        return host_routes_.size() > 0;
    }

private:
    DhcpOptionsList dhcp_options_;
    std::vector<HostRoute> host_routes_;
};

#endif // vnsw_agent_oper_dhcp_options_h_
