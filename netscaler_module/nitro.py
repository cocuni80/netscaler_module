import urllib3

from nssrc.com.citrix.netscaler.nitro.exception.nitro_exception import nitro_exception
from nssrc.com.citrix.netscaler.nitro.service.nitro_service import nitro_service
from nssrc.com.citrix.netscaler.nitro.resource.config.lb.lbvserver import lbvserver
from nssrc.com.citrix.netscaler.nitro.resource.config.lb.lbvserver_binding import lbvserver_binding
from nssrc.com.citrix.netscaler.nitro.resource.config.ns.nspartition import nspartition
from nssrc.com.citrix.netscaler.nitro.resource.config.ns.nspartition_binding import nspartition_binding
from nssrc.com.citrix.netscaler.nitro.resource.stat.ha.hanode_stats import hanode_stats

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def filter_json(source, fields):
    """
    Function that can filter a Dict
    """
    return list(
        map(
            lambda x: dict(
                filter(
                    lambda y: y[0] in fields,
                    x.items()
                )
            ),
            source
        )
    )


class NitroClass(object):
    """
    Core Nitro class
    """

    def __init__(self, **kwargs):
        """
        Initialise a NitroClass
        """
        self._ip = kwargs.get('ip', None)
        self._username = kwargs.get('username', None)
        self._password = kwargs.get('password', None)
        self._session = None
        self._timeout = 900
        self._conexion = 'HTTPS'
        self._partition = 'default'
        self._partitions = ['default']
        self._state = None

    def login(self):
        """
        Login function to manage session with NetScaler
        """
        try:
            self._session = nitro_service(self._ip,self._conexion)
            self._session.set_credential(self._username,self._password)
            self._session.timeout = self._timeout
            self._session.certvalidation = False
            self._session.skipinvalidarg = True
            self._session.idempotent = True
            self._session.login()
            print('[DEBUG]: Logged into NS: {}'.format(self._ip))
            return True
        except nitro_exception as  e:
            print("[ERROR]: Netscaler Login, ErrorCode=" + str(e.errorcode) + ", Message=" + e.message)
            return False
        except Exception as e:
            print("[ERROR]: Netscaler Login, " + str(e.args))
            return False
    
    def logout(self):
        """
        Logout function to quit from NetScaler
        """
        if not self._session:
            return False
        self._session.logout()
        print('[DEBUG]: Logout from NS: {}'.format(self._ip))
        return True        
    
    def switch(self, partition_name):
        """
        Function that conmutes through partition in Netscaler
        """
        if not self._session:
            print('[ERROR]: Please log into NS')
            return False
        try:
            if not partition_name == 'default':
                resource = nspartition
                resource.partitionname = partition_name
                nspartition.Switch(self._session, resource)
                self._partition = partition_name
                print('[LOG]: NS: {}, Switching to partition: {}'.format(self._ip, partition_name))
            return True
        except nitro_exception as e :
            print("[ERROR]: Switch Partition, ErrorCode=" + str(e.errorcode) + ", Message=" + e.message)
            return False
        except Exception as e :  
            print("[ERROR]: Switch Partition, " + str(e.args))
            return False

    def get_lbservers(self):
        """
        Function to get LB information from current partition
        """
        if not self._session:
            print('[ERROR]: Please log into NS')
            return False
        try:
            output = list()
            ns_lbvservers = lbvserver.get(self._session)
            for ns_lbvserver in ns_lbvservers:
                temp = {
                    'ns_ip': str(self._ip),
                    'partition': str(self._partition),
                    'vs_name': str(ns_lbvserver.name),
                    'vs_ip': str(ns_lbvserver.ipv46),
                    'vs_port': str(ns_lbvserver.port),
                    'vs_health': str(ns_lbvserver.health),
                    'vs_lbmethod': str(ns_lbvserver.lbmethod),
                    'vs_persistencetype': str(ns_lbvserver.persistencetype),
                    'vs_servicetype': str(ns_lbvserver.servicetype),
                    'vs_netprofile': str(ns_lbvserver.netprofile),
                    'vs_rhistate': str(ns_lbvserver.rhistate),
                    'vs_mode': str(ns_lbvserver.m),
                }
                output.append(temp)
            return output
        except nitro_exception as e:
            print("[ERROR]: Get LB vservers, ErrorCode=" + str(e.errorcode) + ", Message=" + e.message)
            return []
        except Exception as e:
            print("[ERROR]: Get LB vservers, " + str(e.args))
            return []
    
    def get_lbvserver_binding(self, lbvserver_name):
        """
        Function to get vServers Service and Servicegroup members 
        information from a LBvServer
        """
        if not self._session:
            print('[ERROR]: Please log into NS')
            return False
        try:
            output = dict()
            objects = lbvserver_binding.get(self._session, lbvserver_name)
            if '_lbvserver_servicegroupmember_binding' in objects.__dict__:
                fields = ['servicegroupname', 'vserverid', 'ipv46', 'port', 'servicetype', 'curstate', 'weight']
                output['servicegroupmember_binding'] = filter_json(objects._lbvserver_servicegroupmember_binding, fields)
            elif '_lbvserver_service_binding' in objects.__dict__:
                fields = ['servicename', 'vserverid', 'ipv46', 'port', 'servicetype', 'curstate', 'weight']
                output['service_binding'] = filter_json(objects._lbvserver_service_binding, fields)
            else:
                return None
            return output
        except nitro_exception as e:
            print("[ERROR]: Get Vservers Bindings, ErrorCode=" + str(e.errorcode) + ", Message=" + e.message)
            return None
        except Exception as e:
            print("[ERROR]: Get Vservers Bindings, " + str(e.args))
            return None

    def get_lbvservers_binding(self):
        """
        Function to get vServers Service and Servicegroup members 
        information from a Partition
        """
        if not self._session:
            print('[ERROR]: Please log into NS')
            return False
        print('[LOG]: NS: {}, Getting LB Vserver Bindings from : {}'.format(self._ip, self._partition))
        output = list()
        ns_lbservers = self.get_lbservers()
        for ns_lbserver in ns_lbservers:
            print('[LOG]: NS: {}, Reading LB vServer: {}'.format(self._ip, ns_lbserver['vs_name']))
            ns_vservers = self.get_lbvserver_binding(ns_lbserver['vs_name'])
            if ns_vservers:
                if 'servicegroupmember_binding' in ns_vservers:
                    for ns_vserver in ns_vservers['servicegroupmember_binding']:
                        try:
                            temp = dict(ns_lbserver)
                            temp.update(ns_vserver)
                            output.append(temp)
                        except Exception as e:
                            print("[ERROR]: " + str(e.args))
                elif 'service_binding' in ns_vservers:
                    for ns_vserver in ns_vservers['service_binding']:
                        try:
                            temp = dict(ns_lbserver)
                            temp.update(ns_vserver)
                            output.append(temp)
                        except Exception as e:
                            print("[ERROR]: " + str(e.args))
        return output

    def get_lbvservers_binding_partitions(self):
        """
        Function to get vServers Service and Servicegroup members 
        information from Netscaler
        """
        output = list()
        for ns_partition in self.partitions:
            if self.switch(ns_partition):
                output.extend(self.get_lbvservers_binding())
        return output
    
    def get_backup(self):
        return True

    @property
    def master(self):
        """
        Check if NS is master
        """
        if not self._session:
            print('[ERROR]: Please log into NS')
            return False
        try:
            ha = hanode_stats.get(self._session)
            self._state = ha[0]._hacurmasterstate
            if self._state == 'Primary':
                return True
            else:
                return False
        except nitro_exception as  e:
            print("[ERROR]: HA Status, ErrorCode=" + str(e.errorcode) + ", Message=" + e.message)
            return False
        except Exception as e:
            print("[ERROR]: HA Status, " + str(e.args))
            return False

    @property
    def ip(self):
        """
        Return actual IP from Netscaler
        Return:: Bolean
        """
        return self._ip
    
    @property
    def state(self):
        """
        Return actual state from Netscaler
        Return:: Primary or Secondary
        """
        return self._state

    @property
    def partitions(self):
        """
        Return a List with all the partitiion in Netscaler
        """
        if self._session:
            ns_partitions = nspartition.get(self._session)
            if ns_partitions:
                for ns_partition in ns_partitions:                
                    self._partitions.append(ns_partition.partitionname)
            return self._partitions
        else:
            print('[ERROR]: Please log into NS')
            return None