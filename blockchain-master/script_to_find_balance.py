import requests
import json
from collections import deque

url = "https://blockchain.info/balance?active="

priv_pub_stack = deque()
public_keys = []
results_json = dict()

with open("key_database.txt","r") as f:
    for line in f:
        #print(line)
        values = line.strip().split(" ")
        priv_pub_stack.append(tuple(values[1:3]))
        public_keys.append(values[2])

step = 100
for i in range(0,3000,step):
    appendix = "|".join(public_keys[i:i+step])
    r = requests.get(url+appendix)
    
    #print(r.status_code)
    #print(r.json())

    for key in r.json().keys():
        if r.json().get(key).get('n_tx') > 0:
            print(key)
    results_json.update(r.json())


with open("results.json", "w") as outfile:
     json.dump(results_json,outfile)




