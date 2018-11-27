from pyVmomi import vim
from pyVmomi import vmodl

def _get_obj(content, vimtype, name):
    """
    Get the vsphere object associated with a given text name
    if the name is None, this method would return the first obj.
    """
    obj = None
    container = content.viewManager.CreateContainerView(content.rootFolder, vimtype, True)
    for c in container.view:
        if name:
            if c.name == name:
                obj = c
                break
        else:
            obj = c
            break
    return obj

def _get_all_objs(content, vimtype):
    """
    Get all the vsphere objects associated with a given type
    """
    obj = {}
    container = content.viewManager.CreateContainerView(content.rootFolder, vimtype, True)
    for c in container.view:
        obj.update({c: c.name})
    return obj


def login_in_guest(username, password):
    return vim.vm.guest.NamePasswordAuthentication(username=username,password=password)

def start_process(si, vm, auth, program_path, args=None, env=None, cwd=None):
    cmdspec = vim.vm.guest.ProcessManager.ProgramSpec(arguments=args, programPath=program_path, envVariables=env, workingDirectory=cwd)
    cmdpid = si.content.guestOperationsManager.processManager.StartProgramInGuest(vm=vm, auth=auth, spec=cmdspec)
    return cmdpid

def get_cluster_by_name(si, name):
    """
    Find a cluster by it's name and return it
    """
    return _get_obj(si.RetrieveContent(), [vim.ClusterComputeResource], name)

def get_dvswitch_by_name(si, name):
    """
    Find a dv switch by it's name and return it
    """
    return _get_obj(si.RetrieveContent(), [vim.DistributedVirtualSwitch], name)

def get_folder_by_name(si, name):
    """
    Find a dv folder by it's name and return it
    """
    return _get_obj(si.RetrieveContent(), [vim.Folder], name)

def get_vm_by_name(si, name):
    """
    Find a virtual machine by it's name and return it
    """
    return _get_obj(si.RetrieveContent(), [vim.VirtualMachine], name)

def get_vm_by_uuid(si, uuid):
    """
    Find a virtual machine by it's uuid and return it
    """
    obj = None
    content = si.RetrieveContent()
    container = content.viewManager.CreateContainerView(content.rootFolder, [vim.VirtualMachine], True)
    for c in container.view:
        if (c.config and c.config.instanceUuid == uuid):
            obj = c
            break
    return obj

def get_host_by_name(si, name):
    """
    Find a host by it's name and return it
    """
    return _get_obj(si.RetrieveContent(), [vim.HostSystem], name)

def get_resource_pool(si, name):
    """
    Find a resource pool by it's name and return it
    """
    return _get_obj(si.RetrieveContent(), [vim.ResourcePool], name)

def get_portgroup_by_name(si, name):
    """
    Find a port group by it's name and return it
    """
    return _get_obj(si.RetrieveContent(), [vim.dvs.DistributedVirtualPortgroup], name)

def get_datacenter_by_name(si, name):
    """
    Find a datacenter by it's name and return it
    """
    return _get_obj(si.RetrieveContent(), [vim.Datacenter], name)

def get_resource_pools(si):
    """
    Returns all resource pools
    """
    return _get_all_objs(si.RetrieveContent(), [vim.ResourcePool])

def get_datastores(si):
    """
    Returns all datastores
    """
    return _get_all_objs(si.RetrieveContent(), [vim.Datastore])

def get_hosts(si):
    """
    Returns all hosts
    """
    return _get_all_objs(si.RetrieveContent(), [vim.HostSystem])

def get_datacenters(si):
    """
    Returns all datacenters
    """
    return _get_all_objs(si.RetrieveContent(), [vim.Datacenter])

def get_registered_vms(si):
    """
    Returns all vms
    """
    return _get_all_objs(si.RetrieveContent(), [vim.VirtualMachine])


def get_allocated_port(si, host):
    """
    Return a host vnc port
    :param si:
    :param host:
    :return:
    """
    ports = []
    host = _get_obj(si.RetrieveContent(), [vim.HostSystem], host)
    for v in host.vm:
        extra_config_list = v.config.extraConfig
        for e in extra_config_list:
            if e.key == "RemoteDisplay.vnc.port":
                ports.append(int(e.value))
                break
    return ports


def wait_for_tasks(service_instance, tasks):
    """Given the service instance si and tasks, it returns after all the
   tasks are complete
   """
    property_collector = service_instance.content.propertyCollector
    task_list = [str(task) for task in tasks]
    # Create filter
    obj_specs = [vmodl.query.PropertyCollector.ObjectSpec(obj=task)
                 for task in tasks]
    property_spec = vmodl.query.PropertyCollector.PropertySpec(type=vim.Task,
                                                               pathSet=[],
                                                               all=True)
    filter_spec = vmodl.query.PropertyCollector.FilterSpec()
    filter_spec.objectSet = obj_specs
    filter_spec.propSet = [property_spec]
    pcfilter = property_collector.CreateFilter(filter_spec, True)
    try:
        version, state = None, None
        # Loop looking for updates till the state moves to a completed state.
        while len(task_list):
            update = property_collector.WaitForUpdates(version)
            for filter_set in update.filterSet:
                for obj_set in filter_set.objectSet:
                    task = obj_set.obj
                    for change in obj_set.changeSet:
                        if change.name == 'info':
                            state = change.val.state
                        elif change.name == 'info.state':
                            state = change.val
                        else:
                            continue

                        if not str(task) in task_list:
                            continue

                        if state == vim.TaskInfo.State.success:
                            # Remove task from taskList
                            task_list.remove(str(task))
                        elif state == vim.TaskInfo.State.error:
                            raise task.info.error
            # Move to next version
            version = update.version
    finally:
        if pcfilter:
            pcfilter.Destroy()

