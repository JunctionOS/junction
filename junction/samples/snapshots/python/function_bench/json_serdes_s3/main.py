import json
from time import time
from minio import Minio
import urllib3

http = urllib3.PoolManager()
data_path = '/tmp/'

def function_handler(request_json):
    json_file = request_json['json_file']

    addr = request_json['minio_addr']
    path = f"{data_path}/{json_file}"
    
    minio = Minio(addr,
                  http_client = http, # for some reason this makes urllib use ipv4 instead of unix sockets
                  access_key='minioadmin',
                  secret_key='minioadmin',
                  secure=False)

    start = time()
    
    minio.fget_object('bucket', json_file, path)
    
    data = open(path).read()
    json_data = json.loads(data)
    str_json = json.dumps(json_data, indent=4)
    
    latency = time() - start
    
    return {"serialization_latency": latency}

