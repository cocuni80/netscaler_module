import urllib3
import json
from datetime import datetime

from paramiko import Transport, SFTPClient
from pathlib import Path
from nssrc.com.citrix.netscaler.nitro.exception.nitro_exception import nitro_exception
from nssrc.com.citrix.netscaler.nitro.service.nitro_service import nitro_service
from nssrc.com.citrix.netscaler.nitro.resource.config.lb.lbvserver import lbvserver
from nssrc.com.citrix.netscaler.nitro.resource.config.lb.lbvserver_binding import lbvserver_binding
from nssrc.com.citrix.netscaler.nitro.resource.config.ns.nspartition import nspartition
from nssrc.com.citrix.netscaler.nitro.resource.config.ns.nspartition_binding import nspartition_binding
from nssrc.com.citrix.netscaler.nitro.resource.config.system.systembackup import systembackup
from nssrc.com.citrix.netscaler.nitro.resource.stat.ha.hanode_stats import hanode_stats

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def sftp_get(ip, user, pwd, local_file, remote_file, port=22):
    try:
        t = Transport(ip, port)
        t.connect(username=user, password=pwd)
        sftp = SFTPClient.from_transport(t)
        sftp.get(remote_file, local_file)
        t.close()

    except Exception as e:
        print(e)

def save_file(source, file='none'):
    """
    A custom function that can save the value to a JSON file
    """
    try:
        with open(file, 'w') as data:
            json.dump(source, data)
        print("Class saved at {}".format(file))
    except Exception as e:
        print("[ERROR]: Unable to save {}, ".format(file) + str(e.args))
        return False

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
    
    
class NitroError(Exception):
    """
        NitroError class manage the exceptions for Nitro class
    """
    def __init__(self, *args, **kwargs):
        self._username = kwargs.get('username', None)
        self._ip = kwargs.get('ip', None)
        self._hostname = kwargs.get('hostname', None)
        self._partition = kwargs.get('partition', None)        
        self._backup_folder = kwargs.get('backup_folder', None)
        self._backup_name = kwargs.get('backup_name', None)
        self._backup_level = kwargs.get('backup_level', None)
        self._title = kwargs.get('title', None)
        self._message = kwargs.get('message', None)

    def __str__(self):
        """
        Str for NitroError class
        """
        output = '[Error] - '
        if self._title:
            output += '{}, '.format(self._title)
        if self._ip:
            output += 'ip: {}, '.format(self._ip)
        if self._hostname:
            output += 'Hostmame: {}, '.format(self._hostname)
        if self._username:
            output += 'Username: {}, '.format(self._username)
        if self._partition:
            output += 'Partition: {}, '.format(self._partition)        
        if self._backup_folder:
            output += 'Backup Folder: {}, '.format(self._backup_folder)
        if self._backup_name:
            output += 'Backup Name: {}, '.format(self._backup_name)
        if self._backup_level:
            output += 'Backup Level: {}, '.format(self._backup_level)
        if self._message:
            output += 'Message: {}'.format(self._message)
        return output


class NitroDebug(object):
    """
        NitroDebug class manage the debugs for Nitro class
    """
    def __init__(self, *args, **kwargs):
        self._username = kwargs.get('username', None)
        self._ip = kwargs.get('ip', None)
        self._hostname = kwargs.get('hostname', None)
        self._partition = kwargs.get('partition', None)        
        self._backup_folder = kwargs.get('backup_folder', None)
        self._backup_name = kwargs.get('backup_name', None)
        self._backup_level = kwargs.get('backup_level', None)
        self._title = kwargs.get('title', None)
        self._message = kwargs.get('message', None)

    def __str__(self):
        """
        Str for NitroDebug class
        """
        output = '[Debug] - '
        if self._title:
            output += '{}, '.format(self._title)
        if self._ip:
            output += 'ip: {}, '.format(self._ip)
        if self._hostname:
            output += 'Hostmame: {}, '.format(self._hostname)
        if self._username:
            output += 'Username: {}, '.format(self._username)
        if self._partition:
            output += 'Partition: {}, '.format(self._partition)        
        if self._backup_folder:
            output += 'Backup Folder: {}, '.format(self._backup_folder)
        if self._backup_name:
            output += 'Backup Name: {}, '.format(self._backup_name)
        if self._backup_level:
            output += 'Backup Level: {}, '.format(self._backup_level)
        if self._message:
            output += 'Message: {}'.format(self._message)
        return output


class NitroClass(object):
    """
    Core Nitro class
    """

    def __init__(self, **kwargs):
        """
        Initialise a NitroClass
        """
        self._ip = kwargs.get('ip', None)
        self._hostname = kwargs.get('hostname', self._ip)
        self._username = kwargs.get('username', None)
        self._password = kwargs.get('password', None)
        self._session = None
        self._timeout = kwargs.get('timeout', 900)
        self._conexion = kwargs.get('conexion', 'HTTPS')
        self._partition = 'default'
        self._partitions = ['default']
        self._state = None
        self._backup_name = kwargs.get('backup_name', None)
        self._backup_folder = kwargs.get('backup_folder', 'backups')
        self._backup_level = kwargs.get('backup_level', 'basic')
        self._root = str((Path().absolute()))
        #self._root = str((Path(__file__).parent.absolute() / "..").resolve())        

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
            print(NitroDebug(title='Logged to Netscaler', 
                             ip=self._ip, hostname=self._hostname, username=self._username))
            return True
        except nitro_exception as e:
            self._session = None
            print(NitroError(title='Unable login', ip=self._ip, hostname=self._hostname, message=e.message))
            return False
        except Exception as e:
            self._session = None
            print(NitroError(title='Unable login', ip=self._ip, hostname=self._hostname, message=e))
            return False
    
    @property
    def exist_session(self):
        if self._session:
            return True
        else:
            print(NitroError(title='No logged into Netscaler', 
                             ip=self._ip, hostname=self._hostname, username=self._username))
            return False
    
    def logout(self):
        """
        Logout function to quit from NetScaler
        """
        if not self.exist_session:
            return False
        try:
            self._session.logout()
            self._session = None
            print(NitroDebug(title='Logout Done', ip=self._ip))
            return True
        except nitro_exception as e:
            print(NitroError(title='Unable logout', ip=self._ip, hostname=self._hostname, message=e.message))
            return False
        except Exception as e:
            print(NitroError(title='Unable logout', ip=self._ip, hostname=self._hostname, message=e))
            return False
    
    def switch(self, partition_name):
        """
        Function that conmutes through partition in Netscaler
        """
        if not self.exist_session:
            return False
        try:
            if not partition_name == 'default':
                resource = nspartition
                resource.partitionname = partition_name
                nspartition.Switch(self._session, resource)
                self._partition = partition_name
                print(NitroDebug(title='Switch partition done', 
                                 ip=self._ip, hostname=self._hostname, partition=self._partition))
            return True
        except nitro_exception as e:
            print(NitroError(title='Unable to switch partition', 
                             ip=self._ip, hostname=self._hostname, partition=self._partition, message=e.message))
            return False
        except Exception as e:
            print(NitroError(title='Unable to switch partition', 
                             ip=self._ip, hostname=self._hostname, partition=self._partition, message=e))
            return False

    def get_lbservers(self):
        """
        Function to get LB information from current partition
        """
        if not self.exist_session:
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
            print(NitroError(title='Unable to get LB vservers', 
                             ip=self._ip, hostname=self._hostname, partition=self._partition, message=e.message))
            return []
        except Exception as e:
            print(NitroError(title='Unable to get LB vservers', 
                             ip=self._ip, hostname=self._hostname, partition=self._partition, message=e))
            return []
    
    def get_lbvserver_binding(self, lbvserver_name):
        """
        Function to get vServers Service and Servicegroup members 
        information from a LBvServer
        """
        if not self.exist_session:
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
            print(NitroError(title='Unable to get vservers bindings', 
                             ip=self._ip, hostname=self._hostname, partition=self._partition, message=e.message))
            return []
        except Exception as e:
            print(NitroError(title='Unable to get vservers bindings', 
                             ip=self._ip, hostname=self._hostname, partition=self._partition, message=e))
            return []

    def get_lbvservers_binding(self):
        """
        Function to get vServers Service and Servicegroup members 
        information from a Partition
        """
        if not self.exist_session:
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
                            #print("[ERROR]: " + str(e.args))
                            print(NitroError(title='Unable to append service group', 
                             ip=self._ip, hostname=self._hostname, partition=self._partition, message=e))
                elif 'service_binding' in ns_vservers:
                    for ns_vserver in ns_vservers['service_binding']:
                        try:
                            temp = dict(ns_lbserver)
                            temp.update(ns_vserver)
                            output.append(temp)
                        except Exception as e:
                            #print("[ERROR]: " + str(e.args))
                            print(NitroError(title='Unable to append service', 
                             ip=self._ip, hostname=self._hostname, partition=self._partition, message=e))
        return output

    def get_lbvservers_binding_partitions(self):
        """
        Function to get vServers Service and Servicegroup members 
        information from Netscaler
        """
        if not self.exist_session:
            return False
        output = list()
        for ns_partition in self.partitions:
            if self.switch(ns_partition):
                output.extend(self.get_lbvservers_binding())
        return output
    
    def create_backup(self, **kwargs):
        """
        Function to create a backup on Netscaler.
        - Input:
            * backup_name: Remote backup name | default: <self._backup_name>
            * backup_level: Backup level, basic or full | default: <basic>
        - Output: 
            * Boolean
        """
        if not self.exist_session:
            return False
        try:            
            if not self._backup_name:
                self._backup_name = kwargs.get('backup_name', self._hostname + datetime.now().strftime("_%m.%d.%Y-%H.%M%p"))
            self._backup_level = kwargs.get('backup_level', self._backup_level)            
            resource = systembackup()
            resource.filename = self._backup_name
            resource.level = self._backup_level
            systembackup.create(self._session, resource)
            print('[LOG]: NS: {}, Backup {} created'.format(self._ip, self._backup_name))
            return True
        except nitro_exception as e:
            print(NitroError(title='Unable to create backup', 
                             ip=self._ip, hostname=self._hostname, backup_name=self._backup_name, message=e.message))
            return False
        except Exception as e:
            print(NitroError(title='Unable to create backup', 
                             ip=self._ip, hostname=self._hostname, backup_name=self._backup_name, message=e))
            return False
    
    def query_backup(self, **kwargs):
        """
        Function to query a backup from Netscaler.
        - Input:
            * backup_name: Remote backup name | default: <self._backup_name>
        - Output:
            * ResourceClass or False
        """
        if not self.exist_session:
            return False
        try:
            backup_name = "filename:{}.tgz".format(kwargs.get('backup_name', self._backup_name))
            resource = systembackup.get_filtered(self._session, filter_=backup_name)
            #print(resource[0].__dict__)
            print('[LOG]: NS: {}, Backup {} queried'.format(self._ip, resource[0].filename))
            print(json.dumps(resource[0].__dict__, indent=3))
            return resource
        except nitro_exception as e:
            print(NitroError(title='Unable to query backup', 
                             ip=self._ip, hostname=self._hostname, backup_name=backup_name, message=e.message))
            return False
        except Exception as e:
            print(NitroError(title='Unable to query backup', 
                             ip=self._ip, hostname=self._hostname, backup_name=backup_name, message=e))
            return False
        
    def query_all_backups(self):
        """
        Function to query a backup from Netscaler.
        - Input:
            * None
        - Output:
            * ResourceClass List or False
        """
        if not self.exist_session:
            return False
        try:
            resources = systembackup.get(self._session)
            for resource in resources:
                print('[LOG]: NS: {}, Backup {} queried'.format(self._ip, resource.filename))
            return resources
        except nitro_exception as e:
            print(NitroError(title='Unable to query all backups', 
                             ip=self._ip, hostname=self._hostname, message=e.message))
            return False
        except Exception as e:
            print(NitroError(title='Unable to query all backups', 
                             ip=self._ip, hostname=self._hostname, message=e))
            return False
    
    def download_backup(self, **kwargs):
        """
        Function to download a backup from Netscaler.
        - Input:
            * backup_name: Local backup name | default: <self._backup_name>
            * backup_folder: Local folder Name | default: <self._backup_folder>
        - Output: 
            * ResourceClass or False
        """
        if not self.exist_session:
            return False
        try:
            local_name = kwargs.get('backup_name', self._backup_name)
            folder_path = Path(self._root, kwargs.get('backup_folder', self._backup_folder))
            if not folder_path.is_dir():
                try: 
                    folder_path.mkdir(parents=True, exist_ok=True)
                    print('[LOG]: Created folder {}'.format(folder_path))
                except Exception as e:
                    print("[ERROR]: Unable to create folder {}, ".format(folder_path) + str(e.args))
            
            local_file = Path(folder_path, local_name + '.tgz')
            print('[LOG]: NS: {}, Downloading backup {}'.format(self._ip, local_file))
            #remote_file = r'/var/ns_sys_backup/{}.tgz'.format(name)
            remote_file = '{}.tgz'.format(self._backup_name)           
            
            t = Transport(self.ip, 22)
            t.connect(username=self.username, password=self.password)
            sftp = SFTPClient.from_transport(t)
            sftp.chdir('/var/ns_sys_backup')
            sftp.get(remote_file, local_file)
            t.close()
            return True
        except nitro_exception as e:
            print(NitroError(title='Unable to download backup', 
                             ip=self._ip, hostname=self._hostname, backup_name=local_name, message=e.message))
            return False
        except Exception as e:
            print(NitroError(title='Unable to download backup', 
                             ip=self._ip, hostname=self._hostname, backup_name=local_name, message=e))
            return False
    
    def delete_backup(self, **kwargs):
        """
        Function to delete a backup from Netscaler.
        - Input:
            * backup_name: Remote backup name | default: <self._backup_name>
        - Output: 
            * Boolean
        """
        if not self.exist_session:
            return False
        try:            
            remote_name = "filename:{}.tgz".format(kwargs.get('backup_name', self._backup_name))
            resource = systembackup.get_filtered(self._session, filter_=remote_name)            
            if resource:
                print('[LOG]: NS: {}, Backup {} deleted'.format(self._ip, self._backup_name))          
                systembackup.delete(self._session, resource)
                return True
            else:
                return False
        except nitro_exception as e:
            print(NitroError(title='Unable to delete backup', 
                             ip=self._ip, hostname=self._hostname, backup_name=remote_name, message=e.message))
            return False
        except Exception as e:
            print(NitroError(title='Unable to delete backup', 
                             ip=self._ip, hostname=self._hostname, backup_name=remote_name, message=e))
            return False
    
    def delete_all_backups(self):
        """
        Function to delete all backups from Netscaler.
        - Input:
            * None
        - Output: 
            * Boolean
        """
        if not self.exist_session:
            return False
        try:
            resources = systembackup.get(self._session)
            if resources:
                for resource in resources:
                    print('[LOG]: NS: {}, Backup {} deleted'.format(self._ip, resource.filename))          
                systembackup.delete(self._session, resources)
                return True
            else:
                return False
        except nitro_exception as e:
            print(NitroError(title='Unable to delete all backups', 
                             ip=self._ip, hostname=self._hostname, message=e.message))
            return False
        except Exception as e:
            print(NitroError(title='Unable to delete all backups', 
                             ip=self._ip, hostname=self._hostname, message=e))
            return False

    @property
    def master(self):
        """
        Check if NS is master
        """
        if not self.exist_session:
            return False
        try:
            ha = hanode_stats.get(self._session)
            self._state = ha[0]._hacurmasterstate
            if self._state == 'Primary':
                return True
            else:
                return False
        except nitro_exception as e:
            print(NitroError(title='Unable to get NS status', 
                             ip=self._ip, hostname=self._hostname, message=e.message))
            return False
        except Exception as e:
            print(NitroError(title='Unable to get NS status', 
                             ip=self._ip, hostname=self._hostname, message=e))
            return False
    
    @property
    def hostname(self):
        """
        Return actual hostname
        Return:: Str
        """
        return self._hostname

    @hostname.setter
    def hostname(self, value):
        """
        Set actual hostname
        Return:: Str
        """
        self._hostname = value

    @property
    def ip(self):
        """
        Return actual IP from Netscaler
        Return:: Bolean
        """
        return self._ip
    
    @ip.setter
    def ip(self, value):
        """
        Set actual IP
        Return:: Bolean
        """
        self._ip = value
        
    @property
    def conexion(self):
        """
        Return actual conexion to Netscaler
        Return:: Bolean
        """
        return self._conexion
    
    @conexion.setter
    def conexion(self, value):
        """
        Set actual conexion
        Return:: Bolean
        """
        self._conexion = value
    
    @property
    def username(self):
        """
        Return actual username
        Return:: Str
        """
        return self._username

    @username.setter
    def username(self, value):
        """
        Set actual username
        Return:: Str
        """
        self._username = value
        
    @property
    def password(self):
        """
        Return actual Password
        Return:: Str
        """
        return self._password

    @password.setter
    def password(self, value):
        """
        Set actual Password
        Return:: Str
        """
        self._password = value
    
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
        if not self.exist_session:
            return False
        try:
            ns_partitions = nspartition.get(self._session)
            if ns_partitions:
                for ns_partition in ns_partitions:                
                    self._partitions.append(ns_partition.partitionname)
            return self._partitions
        except nitro_exception as e:
            print(NitroError(title='Unable to get partitions', 
                             ip=self._ip, hostname=self._hostname, message=e.message))
            return False
        except Exception as e:
            print(NitroError(title='Unable to get partitions', 
                             ip=self._ip, hostname=self._hostname, message=e))
            return False
        