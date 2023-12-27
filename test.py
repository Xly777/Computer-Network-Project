import json
import time

import requests
import http.server

#%% raw
#3.1
files = {"firstFile": open('./data/a.txt', "rb")}
# files = {"firstFile": open('./data/CS305.ipynb', "rb")}



data={}
headers={"Authorization": "Basic Y2xpZW50MToxMjM="}
r=requests.post(url='http://127.0.0.1:8080/upload?path=client1/',data=data,headers=headers, files=files)
print(r)
# r=requests.post(url='http://127.0.0.1:8080/upload?path=client2/',data=data,headers=headers, files=files)
# print(r)