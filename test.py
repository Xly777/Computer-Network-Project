import json
import time

import requests
import http.server

#Breakpoint Transmission
url='http://127.0.0.1:8080/client1/a.txt'

data={}
headers={"Authorization": "Basic Y2xpZW50MToxMjM=",
         "Range": "0-1,1-2,2-3"}
r=requests.get(url=url, data=data, headers=headers)
print(r.content.decode())

# headers={"Authorization": "Basic Y2xpZW50MToxMjM="}
# r=requests.get(url='http://127.0.0.1:8080/a.txt', headers=headers)
# print(r.content.decode())