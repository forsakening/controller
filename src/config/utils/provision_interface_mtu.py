#!/usr/bin/python
#
# Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
#

import sys
import argparse
import ConfigParser

from vnc_api.vnc_api import *
from vnc_admin_api import VncApiAdmin


class InterfaceMtuProvisioner(object):

    def __init__(self, args_str=None):
        self._args = None
        if not args_str:
            args_str = ' '.join(sys.argv[1:])
        self._parse_args(args_str)

        self._vnc_lib = VncApiAdmin(
            self._args.use_admin_api,
            self._args.user, self._args.password,
            self._args.tenant_name,
            self._args.api_server_ip,
            self._args.api_server_port, '/',
            api_server_use_ssl=self._args.api_server_use_ssl)

        mtu = int(self._args.mtu)
        vmi_id_got = self._args.virtual_machine_interface_id

        if mtu < 256 or mtu > 9160:
            print 'Mtu value should be between 256 and 9160'
            sys.exit(1)

	if vmi_id_got is None:
            print 'virtual_machine_interface_id is invalid'
            sys.exit(1)
	vmi = None
	try:
            vmi = self._vnc_lib.virtual_machine_interface_read(id=vmi_id_got)
	except NoIdError:
	    pass
        if vmi is not None:
            vmi.set_virtual_machine_interface_mtu(mtu)
            self._vnc_lib.virtual_machine_interface_update(vmi)
            print "Virtual machine interface mtu updated"
        else:
            print "No virtual machine interface found"

    # end __init__


    def _parse_args(self, args_str):
        '''
        Eg. python provision_mtu.py
                                        --api_server_ip 127.0.0.1
                                        --api_server_port 8082
                                        --api_server_use_ssl False
                                        --virtual_machine_interface_id 242717c9-8e78-4c67-94a8-5fbef1f2f096
                                        --mtu 1500
                                        --tenant_name "admin"
        '''

        # Source any specified config/ini file
        # Turn off help, so we print all options in response to -h
        conf_parser = argparse.ArgumentParser(add_help=False)

        conf_parser.add_argument("-c", "--conf_file",
                                 help="Specify config file", metavar="FILE")
        args, remaining_argv = conf_parser.parse_known_args(args_str.split())

        defaults = {
            'api_server_ip': '127.0.0.1',
            'api_server_port': '8082',
            'api_server_use_ssl': False,
            'control_names': [],
            'mtu': '1500',
        }
        ksopts = {
            'user': 'user1',
            'password': 'password1',
            'tenant_name': 'default-domain'
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
            parents=[conf_parser],
            # print script description with -h/--help
            description=__doc__,
            # Don't mess with format of description
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        defaults.update(ksopts)
        parser.set_defaults(**defaults)

        parser.add_argument("--api_server_port", help="Port of api server")
        parser.add_argument("--api_server_use_ssl",help="Use SSL to connect with API server")
        parser.add_argument("--virtual_machine_interface_id", help="UUID of the virtual machine interface")
        parser.add_argument("--tenant_name", help="Tenant name for keystone admin user")
        parser.add_argument("--user", help="Name of keystone admin user")
        parser.add_argument("--password", help="Password of keystone admin user")
        parser.add_argument("--mtu", help="VM interface mtu value.Valid range from 256 to 9160,default : 1500")
        group = parser.add_mutually_exclusive_group()
        group.add_argument("--api_server_ip", help="IP address of api server")
        group.add_argument("--use_admin_api",
                           default=False,
                           help="Connect to local api-server on admin port",
                           action="store_true")

        self._args = parser.parse_args(remaining_argv)

    # end _parse_args


# end class InterfaceMtuProvisioner


def main(args_str=None):
    InterfaceMtuProvisioner(args_str)
# end main


if __name__ == "__main__":
    main()
