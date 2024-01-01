import json
import time

import requests
import http.server

files = {"firstFile": open('C:\\Users\\a\'gou\\Desktop\\test.html', "rb")}


data={}
headers={"Authorization": "Basic Y2xpZW50MToxMjM="}
r=requests.post(url='http://127.0.0.1:8080/upload?path=client1/',data=data,headers=headers, files=files)
print(r)
# r=requests.post(url='http://127.0.0.1:8080/upload?path=client2/',data=data,headers=headers, files=files)
# print(r)