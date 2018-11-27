import svc_monitor.services.loadbalancer.drivers.abstract_driver as abstract_driver

class FlexLbDriver(abstract_driver.ContrailLoadBalancerAbstractDriver):
    """Abstract lbaas driver that expose ~same API as lbaas plugin.

    The configuration elements (Vip,Member,etc) are the dicts that
    are returned to the tenant.
    Get operations are not part of the API - it will be handled
    by the lbaas plugin.
    """
    def __init__(self, name, manager, api, db, args=None):
        self._name = name
        self._api = api
        self._svc_manager = manager
        self._lb_template = None
        self.db = db

    def create_vip(self, vip):
        """A real driver would invoke a call to his backend
        and set the Vip status to ACTIVE/ERROR according
        to the backend call result
        self.plugin.update_status(Vip, vip["id"], constants.ACTIVE)
        """
        pass

    def update_vip(self, old_vip, vip):
        """Driver may call the code below in order to update the status.
        self.plugin.update_status(Vip, id, constants.ACTIVE)
        """
        pass

    def delete_vip(self, vip):
        """A real driver would invoke a call to his backend
        and try to delete the Vip.
        if the deletion was successfull, delete the record from the database.
        if the deletion has failed, set the Vip status to ERROR.
        """
        pass

    def create_pool(self, pool):
        """Driver may call the code below in order to update the status.
        self.plugin.update_status(Pool, pool["id"],
                                  constants.ACTIVE)
        """
        pass

    def update_pool(self, old_pool, pool):
        """Driver may call the code below in order to update the status.
        self.plugin.update_status(Pool,
                                  pool["id"], constants.ACTIVE)
        """
        pass

    def delete_pool(self, pool):
        """Driver can call the code below in order to delete the pool.
        self.plugin._delete_db_pool(pool["id"])
        or set the status to ERROR if deletion failed
        """
        pass

    def stats(self, pool_id):
        pass

    def create_member(self, member):
        """Driver may call the code below in order to update the status.
        self.plugin.update_status(Member, member["id"],
                                   constants.ACTIVE)
        """
        pass

    def update_member(self, old_member, member):
        """Driver may call the code below in order to update the status.
        self.plugin.update_status(Member,
                                  member["id"], constants.ACTIVE)
        """
        pass

    def delete_member(self, member):
        pass

    def update_health_monitor(self,
                              old_health_monitor,
                              health_monitor,
                              pool_id):
        pass

    def create_pool_health_monitor(self,
                                   health_monitor,
                                   pool_id):
        """Driver may call the code below in order to update the status.
        self.plugin.update_pool_health_monitor(
                                               health_monitor["id"],
                                               pool_id,
                                               constants.ACTIVE)
        """
        pass

    def delete_pool_health_monitor(self, health_monitor, pool_id):
        pass

    def create_health_monitor(self,
                              health_monitor,
                              pool_id):
        pass
    # end  create_health_monitor

    def delete_health_monitor(self, health_monitor, pool_id):
        pass
    # end  delete_health_monitor

    def set_config_v1(self, pool_id):
        pass
    # end set_config_v1

    def set_config_v2(self, lb_id):
        pass
    # end set_config_v2

    def create_loadbalancer(self, loadbalancer):
        pass
    # end create_loadbalancer

    def update_loadbalancer(self, old_loadbalancer, loadbalancer):
        pass
    # end update_loadbalancer

    def delete_loadbalancer(self, loadbalancer):
        pass
    # end delete_loadbalancer

    def create_listener(self, listener):
        pass
    # end create_listener

    def update_listener(self, old_listener, listener):
        pass
    # end update_listener

    def delete_listener(self, listener):
        pass
    # end delete_listener