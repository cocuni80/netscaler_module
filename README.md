# Netscaler Module
Netscaler module for python 3.x

## Requirements
Python 3+

## Installation
```shell
$ pip install netscaler_module
```

## Quickstart
Import the `netscaler_module` library to use the functions
```python
from netscaler_module import NitroClass

....
```
Create a `DATABASE` variable and append the dicts response from nitro class.
Below an example.
```python

DATABASE = list()

if __name__ == '__main__':
    global DATABASE
    
    ns_pool = [
        {            
            'ip': '192.168.2.100',
            'hostname': 'ns1',
            'backup_name': 'ns1',
        },
        {            
            'ip': '192.168.2.101',
            'hostname': 'ns2',
            'backup_name': 'ns2',
        }
    ]
    password = {
        'username': 'nsroot',
        'password': 'XXXXXXX'
    }
    backup = {        
        'backup_folder': 'repo',
        'backup_level': 'full',
    }

    for ns_item in ns_pool:        
        kwargs = ns_item | password | backup
        ns = NitroClass(**kwargs)
        ns.login()

        if ns.master:
            data = ns.get_lbvservers_binding_partitions()
            DATABASE.extend(data)
        
        ns.create_backup()
        ns.download_backup()
        ns.delete_backup()
        ns.logout()
        
    print(DATABASE)
```