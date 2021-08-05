from netscaler_module import NitroClass

def get_ns(**kwargs):
    global DATABASE
    ns = NitroClass(**kwargs)
    ns._conexion = 'HTTP'
    ns.login()
    if ns.master:
        data = ns.get_lbvservers_binding_partitions()
        DATABASE.extend(data)        
    else:
        print('NS: {}, is not master'.format(ns.ip))
    ns.logout()
    return None

DATABASE = list()

if __name__ == '__main__':
    ns_pool = [
        '192.168.2.100',
        '192.168.2.101',
    ]
    password = {
        'username': 'nsroot',
        'password': 'nsroot'
    }
    for ns_ip in ns_pool:
        temp = {'ip': ns_ip} | password
        get_ns(**temp)
    
    print(DATABASE)