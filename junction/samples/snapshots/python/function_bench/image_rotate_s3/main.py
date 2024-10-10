import json
from time import time
from minio import Minio
import urllib3

from PIL import Image, ImageOps

http = urllib3.PoolManager()
data_path = '/tmp/'

def function_handler(request_json):
    image = request_json['image']
    addr = request_json['minio_addr']
    path = f"{data_path}/{image}"

    minio = Minio(addr,
                  http_client = http, # for some reason this makes urllib use ipv4 instead of unix sockets
                  access_key='minioadmin',
                  secret_key='minioadmin',
                  secure=False)

    start = time()
    
    minio.fget_object('bucket', image, path)

    image = Image.open(path)
    img = image.transpose(Image.ROTATE_90)
        
    latency = time() - start
    
    return {"serialization_latency": latency}

