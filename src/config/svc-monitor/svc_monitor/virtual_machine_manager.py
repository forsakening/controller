# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (c) 2014 Cloudwatt
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
# @author: Rudra Rugge

from cfgm_common import svc_info
from vnc_api.vnc_api import *
from instance_manager import InstanceManager
from config_db import VirtualMachineSM, VirtualNetworkSM, ServiceInstanceSM
from vnc_api.vnc_api import InstanceIp,RouteType,RouteTableType,NoIdError,RefsExistError

try:
    from novaclient import exceptions as nc_exc
except ImportError:
    pass
from novaclient import exceptions as nc_exc
from oslo_concurrency import lockutils
from pyVmomi import vim
from pyVim.connect import SmartConnect, Disconnect
import vmutils
import netaddr
import gevent
import json
import atexit


synchronized = lockutils.synchronized_with_prefix('vnc-monitor-')

nfv_type_obj_map = {
    "loadbalancer": "loadbalancer_pool",
    "firewall": "firewallservice",
    "vpn": "vpnservice",
}

class VirtualMachineManager(InstanceManager):

    def _create_service_vm(self, instance_index, si, st):
        proj_name = si.fq_name[-2]
        try:
            if si.flavor:
                flavor = self._nc.oper('flavors', 'find', proj_name,
                                       name=si.flavor)
            else:
                flavor = self._nc.oper('flavors', 'find', proj_name, ram=4096)
        except nc_exc.NotFound:
            flavor = None
        if not flavor:
            self.logger.error("Flavor not found %s" %
                ((':').join(st.fq_name)))
            return None

        auth_url = getattr(self._args, 'auth_url', None)
        try:
            if auth_url and 'v3' in auth_url:
                image = self._nc.oper('glance', 'find_image', proj_name, name=si.image)
            else:
                image = self._nc.oper('images', 'find', proj_name, name=si.image)
        except nc_exc.NotFound:
            image = None
        if not image:
            self.logger.error("Image not found %s" % si.image)
            return None

        instance_name = self._get_instance_name(si, instance_index)

        # create port
        nics_with_port = []
        for nic in si.vn_info:
            nic_with_port = {}
            vmi_obj = self._create_svc_vm_port(nic, instance_name, si, st)
            nic_with_port['port-id'] = vmi_obj.get_uuid()
            nics_with_port.append(nic_with_port)

        # launch vm
        idx_str = "%(#)03d" % {'#': (instance_index + 1)}
        nova_vm_name = "_".join(si.fq_name) + idx_str
        self.logger.info('Launching VM : ' + nova_vm_name)

        instance_meta={}
        image_meta = getattr(image,"metadata",None)
        if isinstance(image_meta,dict):
            instance_type_key = svc_info.get_nfv_vm_flag_key()
            instance_type_default_value = svc_info.get_nfv_vm_flag_default_value()
            nfvflag = image_meta.get(instance_type_key,instance_type_default_value)
            instance_meta.update({instance_type_key:nfvflag})

        nfv_type = si.params.get("nfv_type",None)
        if nfv_type:
            # indicate nfv tenant_id since we put all nfv vms into one tenant
            si_obj = self._vnc_lib.service_instance_read(id=si.uuid)
            get_ref_fun = getattr(si_obj, "get_"+nfv_type_obj_map[nfv_type]+"_back_refs")
            read_fun = getattr(self._vnc_lib, nfv_type_obj_map[nfv_type]+"_read")
            nfv_refs = get_ref_fun()
            if nfv_refs:
                nfv_obj = read_fun(id=nfv_refs[0]["uuid"])
                instance_meta.update({"nfv_tenant_id": nfv_obj.parent_uuid, "nfv_type":nfv_type})

        nova_vm = self._nc.oper('servers', 'create', proj_name,
            name=nova_vm_name, image=image,
            flavor=flavor, nics=nics_with_port,
            availability_zone=si.availability_zone,
            meta=instance_meta)
        if not nova_vm:
            self.logger.error("Nova vm create failed %s" % nova_vm_name)
            return None

        nova_vm.get()
        self.logger.info('Created VM : ' + str(nova_vm))

        # link si and vm
        self.link_si_to_vm(si, st, instance_index, nova_vm.id)
        return nova_vm.id

    def _validate_nova_objects(self, st, si):
        # check image and flavor
        si.flavor = st.params.get('flavor', None)
        si.image = st.params.get('image_name', None)
        if not si.image:
            self.logger.error("Image not present in %s" %
                ((':').join(st.fq_name)))
            return False

        # get availability zone
        if st.params.get('availability_zone_enable', None):
            si.availability_zone = si.params.get('availability_zone')
        elif self._args.availability_zone:
            si.availability_zone = self._args.availability_zone

        return True

    def create_vip(self, si):
        update = False
        si_obj = self._vnc_lib.service_instance_read(id=si.uuid)
        si_prop = si_obj.get_service_instance_properties()
        if si.max_instances > 1:
            for vn in si.vn_info:
                if vn["type"] in ("left", "right"):
                    if not getattr(si_prop, "get_%s_vip"%vn["type"])():
                        net = self._vnc_lib.virtual_network_read(id=vn["net-id"])

                        iip_name = "%s__vip__%s"%(vn["type"], si.uuid)
                        iip_obj = InstanceIp(name=iip_name)
                        iip_obj.set_virtual_network(net)
                        iip_uuid = self._vnc_lib.instance_ip_create(iip_obj)

                        getattr(si_prop, "set_%s_vip"%vn["type"])(iip_uuid)
                        self.logger.info(
                            "vip %s of net %s for service instance %s created"%(iip_uuid,vn["type"],si.uuid))
                        update = True
        if update:
            si_obj.set_service_instance_properties(si_prop)
            self._vnc_lib.service_instance_update(si_obj)

    def update_si_prop(self, si):
        si_obj = self._vnc_lib.service_instance_read(id=si.uuid)
        si_prop = si_obj.get_service_instance_properties()
        update = False

        if si.max_instances > 1:
            si_obj.get_service_instance_properties()
            for direct in ("left", "right"):
                _si_vip = getattr(si_prop, "get_%s_ip_address"%direct)()
                vip_uuid = getattr(si_prop, "get_%s_vip"%direct)()
                vip_instance = self._vnc_lib.instance_ip_read(id=vip_uuid)
                instance_ip_address = vip_instance.get_instance_ip_address()
                if _si_vip!=instance_ip_address:
                    getattr(si_prop, "set_%s_ip_address"%direct)(instance_ip_address)
                    update = True
        else:
            gevent.sleep(5)
            vm_refs = si_obj.get_virtual_machine_back_refs()
            vm_obj = self._vnc_lib.virtual_machine_read(id=vm_refs[0]["uuid"])
            for vmi_ref in vm_obj.get_virtual_machine_interface_back_refs() or []:
                vmi_obj = self._vnc_lib.virtual_machine_interface_read(id=vmi_ref["uuid"])
                service_interface_type = vmi_obj.get_virtual_machine_interface_properties().get_service_interface_type()
                if service_interface_type in ("left", "right"):
                    _si_vip = getattr(si_prop, "get_%s_ip_address"%service_interface_type)()
                    instance_ip_uuid = vmi_obj.get_instance_ip_back_refs()[0]["uuid"]
                    instance_ip_obj = self._vnc_lib.instance_ip_read(id=instance_ip_uuid)
                    instance_ip_address = instance_ip_obj.get_instance_ip_address()
                    if _si_vip!=instance_ip_address:
                        getattr(si_prop, "set_%s_ip_address"%service_interface_type)(instance_ip_address)
                        update = True

        interface_list = si_prop.get_interface_list()
        for i in range(len(si.vn_info)):
            vn = si.vn_info[i]
            if vn["type"] in ("left", "right","other0"):
                net_obj = self._vnc_lib.virtual_network_read(id=vn["net-id"])
                if not interface_list[i].get_virtual_network():
                    interface_list[i].set_virtual_network(":".join(net_obj.get_fq_name()))
                    update = True

        if update:
            si_obj.set_service_instance_properties(si_prop)
            self._vnc_lib.service_instance_update(si_obj)

    def create_service(self, st, si):
        if not self._validate_nova_objects(st, si):
            return
        if not self.validate_network_config(st, si):
            return

        # get current vm list
        vm_list = [None] * si.max_instances
        vm_id_list = list(si.virtual_machines)
        for vm_id in vm_id_list:
            vm = VirtualMachineSM.get(vm_id)
            if not vm:
                continue
            if (vm.index + 1) > si.max_instances:
                self.delete_service(vm)
                continue
            vm_list[vm.index] = vm

        # create and launch vm
        si.state = 'launching'
        instances = []
        for index in range(0, si.max_instances):
            if vm_list[index]:
                vm_uuid = vm_list[index].uuid
            else:
                vm_uuid = self._create_service_vm(index, si, st)
                if not vm_uuid:
                    self.logger.error("virtual machine create failed "+
                        "for service instance %s,index %s"%(si.uuid,index))
                    continue

            instances.append({'uuid': vm_uuid})

        # update static routes
        self.update_static_routes(si)

        # uve trace
        si.state = 'active'
        self.logger.uve_svc_instance(":".join(si.fq_name), status='CREATE',
            vms=instances, st_name=st.name)

        self.create_vip(si)
        if instances:
            self.update_si_prop(si)

    def delete_service(self, vm):
        # instance ip delete
        vmi_list = []
        for vmi_id in vm.virtual_machine_interfaces:
            vmi_list.append(vmi_id)
        self.cleanup_svc_vm_ports(vmi_list)

        # nova vm delete
        nova_vm_deleted = False
        proj_name = vm.proj_fq_name[-1]
        try:
            nova_vm = self._nc.oper('servers', 'get', proj_name, id=vm.uuid)
        except nc_exc.NotFound:
            nova_vm_deleted = True
            nova_vm = None

        if nova_vm:
            try:
                nova_vm.delete()
                nova_vm_deleted = True
            except Exception as e:
                self.logger.error("%s nova delete failed with error %s" %
                    (vm.uuid, str(e)))

        if nova_vm_deleted:
            try:
                self._vnc_lib.virtual_machine_delete(id=vm.uuid)
            except NoIdError:
                pass
            except RefsExistError:
                self.logger.error("%s vm delete RefsExist" % (vm.uuid))

    def check_service(self, si):
        vm_id_list = list(si.virtual_machines)
        for vm_id in vm_id_list:
            try:
                vm = self._nc.oper('servers', 'get', si.proj_name, id=vm_id)
            except nc_exc.NotFound:
                vm = None
            if vm and vm.status == 'ERROR':
                try:
                    vm.delete()
                    self.logger.info(
                        "virtual machine %s deleted for service instance %s because of status ERROR" % (vm_id, si.uuid))
                    try:
                        self._vnc_lib.virtual_machine_delete(id=vm_id)
                    except NoIdError:
                        pass
                    except RefsExistError:
                        self.logger.error("%s vm delete RefsExist" % (vm_id))
                except Exception:
                    pass

        return True

class VmwareVirtualMachineManager(VirtualMachineManager):
    def __init__(self, vnc_lib, db, logger, vrouter_scheduler,
                 nova_client, agent_manager, args=None):
        super(VmwareVirtualMachineManager, self).__init__(vnc_lib, db, logger,
                                                          vrouter_scheduler,
                                                          nova_client,agent_manager, args)
        self._args = args
        self.sc = None
        try:
            self._connect()
            atexit.register(Disconnect,self.sc)
        except Exception, e:
            self.logger.error("Connect issue: %s." % str(e))

    def _connect(self):
        self.sc = SmartConnect(protocol=self._args.vcenter_protocol,
                               host=self._args.vcenter_host,
                               user=self._args.vcenter_user,
                               pwd=self._args.vcenter_pwd,
                               port=self._args.vcenter_port)

    def check_connect(func):
        def wrapper(self, *args, **kwargs):
            try:
                dc = vmutils.get_datacenter_by_name(self.sc, self._args.vcenter_datacenter)
            except Exception as e:
                self.logger.error("Connect issue: %s. Try reconnect." % str(e))
                self._connect()
                atexit.register(Disconnect, self.sc)
            return func(self, *args, **kwargs)
        return wrapper

    def _create_service_vm(self, instance_index, si, st):
        proj_name = si.fq_name[-2]
        # Check if template exists
        template_name = st.params['image_name']
        template_vm = vmutils.get_vm_by_name(self.sc, template_name)
        if not template_vm:
            self.logger.error("Template %s not found." % template_vm)
            return None

        cluster = vmutils.get_cluster_by_name(self.sc, self._args.vcenter_cluster)
        resource_pool = cluster.resourcePool

        relocateSpec = vim.vm.RelocateSpec(pool=resource_pool)

        # Set adapters info
        instance_name = self._get_instance_name(si, instance_index)

        # create port
        nics_info = []
        extra_cfg = []
        for nic in si.vn_info:
            vmi_obj = self._create_svc_vm_port(nic, instance_name, si, st)

            if not vmi_obj.virtual_machine_interface_mac_addresses:
                vmi_obj = self._vnc_lib.virtual_machine_interface_read(fq_name=vmi_obj.fq_name)
            mac_address = vmi_obj.virtual_machine_interface_mac_addresses.mac_address[0]
            net_obj = VirtualNetworkSM.get(nic["net-id"])
            network_name = net_obj.display_name or net_obj.name
            network_ref = vmutils.get_portgroup_by_name(self.sc, network_name)
            nicspec = vim.vm.device.VirtualDeviceSpec()
            nicspec.operation = vim.vm.device.VirtualDeviceSpec.Operation.add
            nicspec.device = vim.vm.device.VirtualVmxnet3()
            nicspec.device.wakeOnLanEnabled = True
            nicspec.device.deviceInfo = vim.Description()
            nicspec.device.macAddress = mac_address
            nicspec.device.key = -47
            nicspec.device.addressType = "manual"

            dvs_port_connection = vim.dvs.PortConnection()
            dvs_port_connection.portgroupKey = network_ref.key
            dvs_port_connection.switchUuid = network_ref.config.distributedVirtualSwitch.uuid

            nicspec.device.backing = vim.vm.device.VirtualEthernetCard.DistributedVirtualPortBackingInfo()
            nicspec.device.backing.port = dvs_port_connection

            connectable_spec = vim.vm.device.VirtualDevice.ConnectInfo()
            connectable_spec.startConnected = True
            connectable_spec.allowGuestControl = True
            connectable_spec.connected = True
            nicspec.device.connectable = connectable_spec
            nics_info.append(nicspec)

            option = vim.option.OptionValue()
            option.key = mac_address
            option.value = vmi_obj.uuid
            extra_cfg.append(option)

        # Set VM configuration (CPU MEM)
        vmconf = vim.vm.ConfigSpec(deviceChange=nics_info,
                                   extraConfig=extra_cfg)
        cloneSpec = vim.vm.CloneSpec(powerOn=True, template=False,
                                     location=relocateSpec,
                                     customization=None, config=vmconf)
        folder = vmutils.get_folder_by_name(self.sc, proj_name)
        # Clone and launch vm
        self.logger.log('Launching VM : ' + instance_name)
        TASK = template_vm.CloneVM_Task(name=instance_name, folder=folder, spec=cloneSpec)
        vmutils.wait_for_tasks(self.sc, [TASK])
        vmware_vm = vmutils.get_vm_by_name(self.sc, instance_name)
        if not vmware_vm:
            return

        self._reconfig_vm_vnc(vmware_vm)
        self._config_nfv_vm_metadata(vmware_vm, si)

        # create vnc VM object and link to SI
        self.link_si_to_vm(si, st, instance_index, vmware_vm.config.instanceUuid)
        return vmware_vm.config.instanceUuid

    def _config_nfv_vm_metadata(self, vm, si):
        instance_type = vim.option.OptionValue()
        instance_type.key = "instance_type"
        instance_type.value = "nfv"

        nfv_type = vim.option.OptionValue()
        nfv_type.key = "nfv_type"
        nfv_type.value = si.params.get("nfv_type",None)

        old_extra = vm.config.extraConfig
        old_extra.append(instance_type)
        old_extra.append(nfv_type)

        reconfig_spec = vim.vm.ConfigSpec(extraConfig=old_extra)

        task = vm.ReconfigVM_Task(spec=reconfig_spec)
        vmutils.wait_for_tasks(self.sc, [task])

    def _reconfig_vm_vnc(self, vm):
        vnc_enabled = vim.option.OptionValue()
        vnc_enabled.key = "RemoteDisplay.vnc.enabled"
        vnc_enabled.value = "TRUE"



        vnc_port = vim.option.OptionValue()
        vnc_port.key = "RemoteDisplay.vnc.port"
        vnc_port.value = self._get_vnc_port(vm.summary.runtime.host.name)


        vnc_key_map = vim.option.OptionValue()
        vnc_key_map.key = "RemoteDisplay.vnc.keyMap"
        vnc_key_map.value = "en-us"

        old_extra = vm.config.extraConfig
        old_extra.append(vnc_enabled)
        old_extra.append(vnc_port)
        old_extra.append(vnc_key_map)

        reconfig_spec = vim.vm.ConfigSpec(extraConfig=old_extra)

        task = vm.ReconfigVM_Task(spec=reconfig_spec)
        vmutils.wait_for_tasks(self.sc, [task])
        return


    @synchronized("get_vnc_port")
    def _get_vnc_port(self, host):
        #Maybe we can config the port range in
        #a config file not coded here.
        #And here may cause a bug:for flaxscape and svc monitor
        #create vm at the same time ,there is not a method
        #to syncronize the get_vnc_port,that may cause get the
        #same vnc port.
        ports = vmutils.get_allocated_port(self.sc, host)
        min_port = 5900
        max_port = 6080

        for p in range(min_port, max_port):
            if p not in ports:
                return p

    @check_connect
    def delete_unused_vn(self, vnid):
        net_obj = VirtualNetworkSM.get(vnid)
        network_name = net_obj.display_name or net_obj.name
        net = vmutils.get_portgroup_by_name(self.sc, network_name)
        if len(net.vm)==0:
            TASK=net.Destroy_Task()
            vmutils.wait_for_tasks(self.sc, [TASK])

    @check_connect
    def create_service(self, st, si):
        if not self.validate_network_config(st, si):
            return
        vm_list = [None] * si.max_instances
        vm_id_list = list(si.virtual_machines)
        for vm_id in vm_id_list:
            vm = VirtualMachineSM.get(vm_id)
            if not vm:
                continue
            if (vm.index + 1) > si.max_instances:
                self.delete_service(vm)
                continue
            vm_list[vm.index] = vm

        # create and launch vm
        si.state = 'launching'
        instances = []
        for index in range(0, si.max_instances):
            if vm_list[index]:
                vm_uuid = vm_list[index].uuid
            else:
                vm_uuid = self._create_service_vm(index, si, st)
                if not vm_uuid:
                    self.logger.error("virtual machine create failed "+
                        "for service instance %s"%si.uuid)
                    continue

            instances.append({'uuid': vm_uuid})

        # update static routes
        self.update_static_routes(si)

        # uve trace
        si.state = 'active'
        self.logger.uve_svc_instance(":".join(si.fq_name), status='CREATE',
                                     vms=instances, st_name=st.name)

        self.create_vip(si)
        if instances:
            self.update_si_prop(si)

    @check_connect
    def check_service(self, si):
        vm_id_list = list(si.virtual_machines)
        for vm_id in vm_id_list:
            vm = vmutils.get_vm_by_uuid(self.sc, vm_id)

            if vm and vm.configStatus == 'red':
                try:
                    self._destory_vm(vm)
                except Exception:
                    pass

        return True

    @check_connect
    def delete_service(self, vm):
        # instance ip delete
        vmi_list = []
        for vmi_id in vm.virtual_machine_interfaces:
            vmi_list.append(vmi_id)
        self.cleanup_svc_vm_ports(vmi_list)

        vm_deleted = False

        exsi_vm = vmutils.get_vm_by_uuid(self.sc, vm.uuid)
        if not exsi_vm:
            vm_deleted = True
            exsi_vm = None

        if exsi_vm:
            try:
                self._destory_vm(exsi_vm)
                vm_deleted = True
            except Exception as e:
                self.logger.error("%s nova delete failed with error %s" %
                                  (vm.uuid, str(e)))
        if vm_deleted:
            try:
                self._vnc_lib.virtual_machine_delete(id=vm.uuid)
            except NoIdError:
                pass
            except RefsExistError:
                self.logger.error("%s vm delete RefsExist" % (vm.uuid))

    @check_connect
    def create_service_vn(self, vn_name, vn_subnet, vn_subnet6,
                          proj_fq_name, user_visible=None):
        dvs = vmutils.get_dvswitch_by_name(self.sc, self._args.vcenter_dvswitch)
        dc = vmutils.get_datacenter_by_name(self.sc, self._args.vcenter_datacenter)
        description = {"project": self._vnc_lib.fq_name_to_id('project', proj_fq_name)}
        configSpec = vim.dvs.DistributedVirtualPortgroup.ConfigSpec(name=vn_name, type="earlyBinding", numPorts=8,\
                                                                    description=json.dumps(description))
        pvlanId = self._get_pvlan_id()

        pvlan = vim.dvs.VmwareDistributedVirtualSwitch.PvlanSpec(pvlanId=pvlanId)
        portSetting = vim.dvs.VmwareDistributedVirtualSwitch.VmwarePortConfigPolicy(vlan=pvlan)

        configSpec.defaultPortConfig = portSetting
        TASK = dvs.CreateDVPortgroup_Task(spec=configSpec)
        vmutils.wait_for_tasks(self.sc, [TASK])

        if vn_subnet:
            net = netaddr.IPNetwork(vn_subnet)
            ip = str(net.ip)
            netmask = str(net.netmask)
            gateway=str(netaddr.IPAddress(net.last-1))
            net = vmutils.get_portgroup_by_name(self.sc, vn_name)
            ipPoolManager = self.sc.RetrieveContent().ipPoolManager
            ipv4Config = vim.vApp.IpPool.IpPoolConfigInfo(subnetAddress=ip, netmask=netmask,
                                                          gateway=gateway)
            networkAssociation = vim.vApp.IpPool.Association(network=net)

            ipPool = vim.vApp.IpPool(name="ip-pool-for-" + vn_name, ipv4Config=ipv4Config,
                                     networkAssociation=[networkAssociation])
            ipPoolManager.CreateIpPool(dc=dc, pool=ipPool)

        gevent.sleep(2)
        vn_fq_name = proj_fq_name + [vn_name]
        vn_uuid = self._vnc_lib.fq_name_to_id('virtual-network', vn_fq_name)
        VirtualNetworkSM.locate(vn_uuid)

        return vn_uuid

    def get_svc_vn_info(self,itf_type, si):
        service_vn_name, service_vn_subnet, service_vn_subnet6 = \
            super(VmwareVirtualMachineManager, self).get_svc_vn_info(itf_type, si)
        proj_uuid = self._vnc_lib.fq_name_to_id('project', si.fq_name[:-1])
        service_vn_name = service_vn_name + "-" + proj_uuid
        return service_vn_name, service_vn_subnet, service_vn_subnet6

    def _destory_vm(self,vm):
        if format(vm.runtime.powerState) == "poweredOn":
            TASK = vm.PowerOffVM_Task()
            vmutils.wait_for_tasks(self.sc, [TASK])

        TASK = vm.Destroy_Task()
        vmutils.wait_for_tasks(self.sc, [TASK])

    def _get_pvlan_id(self):
        dvs = vmutils.get_dvswitch_by_name(self.sc, self._args.vcenter_dvswitch)
        if dvs:
            for pvlan in dvs.config.pvlanConfig:
                if pvlan.pvlanType == "isolated":
                    return pvlan.secondaryVlanId
        return None


