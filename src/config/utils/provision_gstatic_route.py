#!/usr/bin/python
#
# Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
#

import sys
import argparse
import ConfigParser

from vnc_api.vnc_api import *
from vnc_api.gen.resource_xsd import RouteType
from vnc_api.gen.resource_xsd import RouteTableType
from netaddr import *


class GlobalStaticRouteProvision(object):

    def __init__(self, args_str = None):
        self._args = None
        if not args_str:
            args_str = ' '.join(sys.argv[1:])
        self._parse_args(args_str)

        self._vnc_lib = VncApi(
            self._args.admin_user, self._args.admin_password,
            self._args.admin_tenant_name,
            self._args.api_server_ip,
            self._args.api_server_port, '/')

        prefix = self._args.prefix
        nh = self._args.nh
        try:
            ip_nw = IPNetwork(prefix)
        except AddrFormatError:
            print 'Invalid ip address format'
            sys.exit(1)

        try:
            global_config = self._vnc_lib.global_vrouter_config_read(
                                fq_name = ['default-global-system-config', 'default-global-vrouter-config'])
        except Exception as e:
            print "Global vrouter config does not exist"
            sys.exit(1)

        if not global_config.get_global_static_routes():
            route_table = RouteTableType()
            route_table.set_route([])
            global_config.set_global_static_routes(route_table)

        if self._args.oper == 'add':
            global_config = self.add_route(global_config, prefix, nh)
        elif self._args.oper == 'del':
            global_config = self.del_route(global_config, prefix, nh)
        result = self._vnc_lib.global_vrouter_config_update(global_config)
        print 'Updated.%s'%(result)
    # end __init__

    def add_route(self, global_config, prefix, nh):
        rt_routes = global_config.get_global_static_routes()
        routes = rt_routes.get_route()
        found = False
        for route in routes:
            if route.prefix == prefix:
                print "Prefix already present in default Route Table, not adding"
                found = True
                sys.exit(0)
        if not found:
            rt1 = RouteType(prefix = prefix, next_hop = nh, next_hop_type = 'ip-address')
        routes.append(rt1)
        global_config.set_global_static_routes(rt_routes)
        return global_config
    #end add_route

    def del_route(self, global_config, prefix, nh):
        print "del_route!"
        rt_routes = global_config.get_global_static_routes()
        routes = rt_routes.get_route()
        found = False
        for route in routes:
            if route.prefix == prefix:
                found = True
                routes.remove(route)
        if not found :
            print "Prefix not found in Route table!"
            sys.exit(1)
        global_config.set_global_static_routes(rt_routes)
        return global_config
    #end del_route

    def _parse_args(self, args_str):
        '''
        Eg. python provision_gstatic_route.py
                                        --api_server_ip 127.0.0.1
                                        --api_server_port 8082
                                        --prefix 2.2.2.2/32
                                        --nh 192.168.36.254
                                        --oper <add | del>
        '''

        # Source any specified config/ini file
        # Turn off help, so we print all options in response to -h
        conf_parser = argparse.ArgumentParser(add_help = False)

        conf_parser.add_argument("-c", "--conf_file",
                                 help = "Specify config file", metavar = "FILE")
        args, remaining_argv = conf_parser.parse_known_args(args_str.split())

        defaults = {
            'api_server_ip': '127.0.0.1',
            'api_server_port': '8082',
            'oper': 'add',
        }
        ksopts = {
            'admin_user': 'user1',
            'admin_password': 'password1',
            'admin_tenant_name': 'admin'
        }

        if args.conf_file:
            config = ConfigParser.SafeConfigParser()
            config.read([args.conf_file])
            defaults.update(dict(config.items("DEFAULTS")))
            if 'KEYSTONE' in config.sections():
                ksopts.update(dict(config.items("KEYSTONE")))

        # Override with CLI options
        # Don't surpress add_help here so it will handle -h
        parser = argparse.ArgumentParser(
            # Inherit options from config_parser
            parents = [conf_parser],
            # print script description with -h/--help
            description = __doc__,
            # Don't mess with format of description
            formatter_class = argparse.RawDescriptionHelpFormatter,
        )
        defaults.update(ksopts)
        parser.set_defaults(**defaults)

        parser.add_argument(
            "--prefix", help = "IP Destination prefix to be updated in the Route", required = True)
        parser.add_argument(
            "--nh", help = "Nexthop of the Route", required = True)
        parser.add_argument(
            "--api_server_ip", help = "IP address of api server")
        parser.add_argument("--api_server_port", help = "Port of api server")
        parser.add_argument(
            "--oper", default = 'add',help = "Provision operation to be done(add or del)")
        parser.add_argument(
            "--admin_user", help = "Name of keystone admin user", required = True)
        parser.add_argument(
            "--admin_password", help = "Password of keystone admin user", required = True)
        parser.add_argument(
            "--admin_tenant_name", help = "Tenant name for keystone admin user")

        self._args = parser.parse_args(remaining_argv)

    # end _parse_args

# end class GlobalStaticRouteProvision


def main(args_str = None):
    GlobalStaticRouteProvision(args_str)
# end main

if __name__ == "__main__":
    main()
