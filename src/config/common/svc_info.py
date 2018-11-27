#
# Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
#

_MGMT_STR = "management"
_LEFT_STR = "left"
_RIGHT_STR = "right"
_OTHER_STR = "other0"

_SVC_VN_MGMT = "svcVnMgmt"
_SVC_VN_LEFT = "svcVnLeft"
_SVC_VN_RIGHT = "svcVnRight"
_SVC_VN_OTHER = "svcVnOther"
_VN_MGMT_SUBNET_CIDR = '10.250.1.0/24'
_VN_LEFT_SUBNET_CIDR = '10.250.2.0/24'
_VN_RIGHT_SUBNET_CIDR = '10.250.3.0/24'
_VN_OTHER_SUBNET_CIDR = '10.250.5.0/24'
_VN_MGMT_SUBNET_CIDR6 = 'fd12:3456:789a:1::/64'
_VN_LEFT_SUBNET_CIDR6 = 'fd12:3456:789a:2::/64'
_VN_RIGHT_SUBNET_CIDR6 = 'fd12:3456:789a:3::/64'
_VN_OTHER_SUBNET_CIDR6 = 'fd12:3456:789a:4::/64'

_VN_SNAT_PREFIX_NAME = 'snat-si-left'
_VN_SNAT_SUBNET_CIDR = '100.64.0.0/29'

_CHECK_SVC_VM_HEALTH_INTERVAL = 60

_VM_INSTANCE_TYPE = 'virtual-machine'
_NETNS_INSTANCE_TYPE = 'network-namespace'

_SNAT_SVC_TYPE = 'source-nat'
_LB_SVC_TYPE = 'loadbalancer'

_ACTIVE_LOCAL_PREFERENCE = 200
_STANDBY_LOCAL_PREFERENCE = 100

_SVC_SG = "svc-default-sg"
_VM_NFV_FLAG_KEY = "instance_type"
_VM_NFV_FLAG_DEFAULT_VALUE = "nfv"

# Version from the vrouter agent can manage service instances
_VROUTER_NETNS_SUPPORTED_VERSION = '1.10'

def get_nfv_vm_flag_default_value():
    return _VM_NFV_FLAG_DEFAULT_VALUE

def get_nfv_vm_flag_key():
    return _VM_NFV_FLAG_KEY

def get_management_if_str():
    return _MGMT_STR

def get_left_if_str():
    return _LEFT_STR

def get_right_if_str():
    return _RIGHT_STR

def get_other0_if_str():
    return _OTHER_STR

def get_if_str_list():
    if_str_list = []
    if_str_list.append(get_management_if_str())
    if_str_list.append(get_left_if_str())
    if_str_list.append(get_right_if_str())
    return if_str_list

def get_default_sg():
    return _SVC_SG

def get_management_vn_name():
    return _SVC_VN_MGMT

def get_left_vn_name():
    return _SVC_VN_LEFT

def get_right_vn_name():
    return _SVC_VN_RIGHT

def get_other0_vn_name():
    return _SVC_VN_OTHER

def get_shared_vn_list():
    shared_vn_list = []
    shared_vn_list.append(get_management_vn_name())
    shared_vn_list.append(get_left_vn_name())
    shared_vn_list.append(get_right_vn_name())
    shared_vn_list.append(get_other0_vn_name())
    return shared_vn_list

def get_management_vn_subnet():
    return _VN_MGMT_SUBNET_CIDR

def get_left_vn_subnet():
    return _VN_LEFT_SUBNET_CIDR

def get_right_vn_subnet():
    return _VN_RIGHT_SUBNET_CIDR

def get_other0_vn_subnet():
    return _VN_OTHER_SUBNET_CIDR

def get_management_vn_subnet6():
    return _VN_MGMT_SUBNET_CIDR6

def get_left_vn_subnet6():
    return _VN_LEFT_SUBNET_CIDR6

def get_right_vn_subnet6():
    return _VN_RIGHT_SUBNET_CIDR6

def get_other0_vn_subnet6():
    return _VN_OTHER_SUBNET_CIDR6

def get_snat_left_vn_prefix():
    return _VN_SNAT_PREFIX_NAME

def get_snat_left_subnet():
    return _VN_SNAT_SUBNET_CIDR

def get_vm_instance_type():
    return _VM_INSTANCE_TYPE

def get_netns_instance_type():
    return _NETNS_INSTANCE_TYPE

def get_snat_service_type():
    return _SNAT_SVC_TYPE

def get_lb_service_type():
    return _LB_SVC_TYPE

def get_vm_health_interval():
    return _CHECK_SVC_VM_HEALTH_INTERVAL

def get_active_preference():
    return _ACTIVE_LOCAL_PREFERENCE

def get_standby_preference():
    return _STANDBY_LOCAL_PREFERENCE
