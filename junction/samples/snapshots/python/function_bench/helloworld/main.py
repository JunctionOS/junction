from time import time

def function_handler(request_json):
    start = time()
    msg = request_json['message']
    latency = time() - start
    
    return f"latency: {latency}, message: {msg}"
