import math
from time import time

def float_operation(N):
    start = time()
    for i in range(0, N):
        sin_i = math.sin(i)
        cos_i = math.cos(i)
        sqrt_i = math.sqrt(i)
    latency = time() - start
    return latency

def function_handler(request_json):
    N = request_json['N']
    latency = float_operation(N)
    return "latency : " + str(latency)