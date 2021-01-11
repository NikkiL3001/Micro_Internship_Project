import os.path
import json

database_fname = 'DNS_file.txt'
if os.path.isfile(database_fname):
    with open(database_fname, 'r') as file:
        dns_database = json.load(file)
else:
    with open(database_fname, 'x') as file:
        pass
    dns_database={}

with open(database_fname, 'w') as file:  
    file.write(json.dumps(dns_database))
    