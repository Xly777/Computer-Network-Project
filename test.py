import json
import time

import requests
import http.server

headers={"Authorization": "Basic Y2xpZW50MToxMjM="}
r=requests.get(url='http://127.0.0.1:8080/client1/a.txt?chunked=1', headers=headers)
print(r)