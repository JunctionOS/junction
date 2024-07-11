import json
from time import time


def function_handler(request_json):
    json_path = request_json['json_path']

    with open(json_path, 'rb') as file:
        data = file.read() 

    start = time()
    json_data = json.loads(data)
    str_json = json.dumps(json_data, indent=4)
    latency = time() - start

    return {"serialization_latency": latency}