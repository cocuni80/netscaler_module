# Netscaler Module
Simple parallel processing interface for python

## Requirements
Python 3+

## Installation
```shell
$ pip install netscaler_module
```

## Quickstart
Use the `threaded` decorator to turn a method into a threaded method.
```python
from netscaler_module import nitro

....
```

Both the `threaded` decorator and `run_threaded` method will return an instance of
`ResultThread`. This allow you to optionally wait for the function to finish executing 
and get the return value. To get the return value, use `.await_output()`
```python

def get_ns(**kwargs):
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

DATABASE = list()

if __name__ == '__main__':
    ns_pool = [
        '192.168.1.1',
        '192.168.1.2',
    ]
    password = {
        'username': 'nsroot',
        'password': 'XXXXXXX'
    }
    for ns_ip in ns_pool:
        temp = {'ip': ns_ip} | password
        get_ns(**temp)
    
    print(DATABASE)
```