from netscaler_module import NitroClass
from time import sleep

def get_ns_vservers(**kwargs):
    global DATABASE
    ns = NitroClass(**kwargs)
    ns.login()
    if ns.master:
        data = ns.get_lbvservers_binding_partitions()
        DATABASE.extend(data)        
    else:
        print('NS: {}, is not master'.format(ns.ip))
    ns.logout()
    return None

def get_ns_backup(**kwargs):
    ns = NitroClass(**kwargs)
    ns.login()
    ns.create_backup()
    ns.download_backup()
    if ns.master:
       ns.delete_backup()
    else:
        print('NS: {}, is not master'.format(ns.ip))
        ns.delete_all_backups()
    ns.logout()
    return None

DATABASE = list()

if __name__ == '__main__':
    ns_pool = {
        'ns1': '192.168.2.100',
        'ns2': '192.168.2.101',
    }
    password = {
        'username': 'nsroot',
        'password': 'nsroot',
        'conexion': 'HTTP'
    }
    backup = {
        'backup_folder': 'repo',
        'backup_level': 'full',
    }
    for hostname, ip in ns_pool.items():
        ns_properties = {'hostname': hostname, 'ip': ip} | password | backup
        get_ns_backup(**ns_properties)        
    
    print(DATABASE)